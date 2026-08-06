using System;
using System.Collections.Generic;
using System.Text;

namespace KsDumperClient.DotNet
{
    /// <summary>
    /// IL instruction disassembler. Decodes method bodies per ECMA-335 III.
    /// </summary>
    public class ILDisassembler
    {
        private readonly MetadataTableParser metadata;
        private readonly byte[] peBytes;
        private readonly int peOffset;
        private readonly bool is64;

        public ILDisassembler(MetadataTableParser metadata, byte[] peBytes)
        {
            this.metadata = metadata;
            this.peBytes = peBytes;
            this.peOffset = BitConverter.ToInt32(peBytes, 60);
            ushort machine = BitConverter.ToUInt16(peBytes, peOffset + 4);
            is64 = (machine == 0x8664 || machine == 0xAA64);
        }

        /// <summary>
        /// Disassemble a method by its index (0-based) in the MethodDef table.
        /// </summary>
        public string DisassembleMethod(int methodIndex)
        {
            if (metadata?.MethodDefs == null || methodIndex < 0 || methodIndex >= metadata.MethodDefs.Length)
                return "// Method not found";

            var method = metadata.MethodDefs[methodIndex];
            if (method.Rva == 0)
                return "// No RVA (abstract/extern/pinvoke)";

            // Convert RVA to file offset
            int methodOffset = CliHeader.RvaToFileOffset(peBytes, peOffset, method.Rva, is64);
            if (methodOffset < 0 || methodOffset + 4 > peBytes.Length)
                return "// Invalid RVA";

            // Parse method header
            int codeOffset;
            int codeSize;
            int maxStack;
            uint localVarToken;
            bool isFat;

            byte headerByte = peBytes[methodOffset];

            if ((headerByte & 0x03) == 0x02) // Tiny header
            {
                codeSize = headerByte >> 2;
                codeOffset = methodOffset + 1;
                maxStack = 8;
                localVarToken = 0;
                isFat = false;
            }
            else if ((headerByte & 0x03) == 0x03) // Fat header
            {
                ushort fatFlags = BitConverter.ToUInt16(peBytes, methodOffset);
                int headerSize = (fatFlags >> 12) * 4; // in bytes
                maxStack = BitConverter.ToUInt16(peBytes, methodOffset + 2);
                codeSize = BitConverter.ToInt32(peBytes, methodOffset + 4);
                localVarToken = BitConverter.ToUInt32(peBytes, methodOffset + 8);
                codeOffset = methodOffset + headerSize;
                isFat = true;
            }
            else
            {
                return "// Unknown method header format";
            }

            if (codeOffset + codeSize > peBytes.Length)
                codeSize = peBytes.Length - codeOffset;

            var sb = new StringBuilder();

            // Method info header
            string methodName = metadata.ReadString(method.NameIndex);
            sb.AppendLine($"// Method: {methodName}");
            sb.AppendLine($"// RVA: 0x{method.Rva:X8}  Token: 0x06{(methodIndex + 1):X6}");
            sb.AppendLine($"// Code Size: {codeSize}  MaxStack: {maxStack}  Format: {(isFat ? "Fat" : "Tiny")}");

            if (localVarToken != 0)
                sb.AppendLine($"// LocalVarSig Token: 0x{localVarToken:X8}");

            sb.AppendLine();

            // Disassemble IL instructions
            int pos = codeOffset;
            int endPos = codeOffset + codeSize;
            var labelOffsets = new HashSet<int>();

            // First pass: collect branch targets for label generation
            int tempPos = codeOffset;
            while (tempPos < endPos)
            {
                int instrStart = tempPos;
                byte opByte = peBytes[tempPos++];
                int opCode = opByte;

                if (opByte == 0xFE && tempPos < endPos)
                {
                    opCode = 0xFE00 | peBytes[tempPos++];
                }

                var info = GetOpcodeInfo(opCode);
                int operandSize = GetOperandSize(info.OperandType);

                if (info.OperandType == OperandType.InlineBrTarget || info.OperandType == OperandType.ShortInlineBrTarget)
                {
                    int branchTarget;
                    if (info.OperandType == OperandType.InlineBrTarget && tempPos + 4 <= endPos)
                    {
                        int offset = BitConverter.ToInt32(peBytes, tempPos);
                        branchTarget = (tempPos + 4 - codeOffset) + offset;
                    }
                    else if (info.OperandType == OperandType.ShortInlineBrTarget && tempPos + 1 <= endPos)
                    {
                        sbyte offset = (sbyte)peBytes[tempPos];
                        branchTarget = (tempPos + 1 - codeOffset) + offset;
                    }
                    else
                    {
                        branchTarget = -1;
                    }

                    if (branchTarget >= 0)
                        labelOffsets.Add(branchTarget);
                }

                if (info.OperandType == OperandType.InlineSwitch && tempPos + 4 <= endPos)
                {
                    int numCases = BitConverter.ToInt32(peBytes, tempPos);
                    int switchBase = tempPos + 4 + numCases * 4 - codeOffset;
                    for (int i = 0; i < numCases && tempPos + 4 + (i + 1) * 4 <= endPos; i++)
                    {
                        int offset = BitConverter.ToInt32(peBytes, tempPos + 4 + i * 4);
                        labelOffsets.Add(switchBase + offset);
                    }
                    operandSize = 4 + numCases * 4;
                }

                tempPos += operandSize;
            }

            // Second pass: emit disassembly
            pos = codeOffset;
            while (pos < endPos)
            {
                int instrOffset = pos - codeOffset;

                // Emit label if this offset is a branch target
                if (labelOffsets.Contains(instrOffset))
                    sb.AppendLine($"  IL_{instrOffset:X4}:");

                sb.Append($"  IL_{instrOffset:X4}: ");

                byte opByte2 = peBytes[pos++];
                int opCode2 = opByte2;

                if (opByte2 == 0xFE && pos < endPos)
                {
                    opCode2 = 0xFE00 | peBytes[pos++];
                }

                var info2 = GetOpcodeInfo(opCode2);
                sb.Append(info2.Name.PadRight(12));

                switch (info2.OperandType)
                {
                    case OperandType.InlineNone:
                        break;

                    case OperandType.ShortInlineI:
                        if (pos < endPos)
                            sb.Append(peBytes[pos].ToString());
                        pos += 1;
                        break;

                    case OperandType.InlineI:
                        if (pos + 4 <= endPos)
                            sb.Append(BitConverter.ToInt32(peBytes, pos).ToString());
                        pos += 4;
                        break;

                    case OperandType.InlineI8:
                        if (pos + 8 <= endPos)
                            sb.Append(BitConverter.ToInt64(peBytes, pos).ToString());
                        pos += 8;
                        break;

                    case OperandType.ShortInlineR:
                        if (pos + 4 <= endPos)
                            sb.Append(BitConverter.ToSingle(peBytes, pos).ToString("F4"));
                        pos += 4;
                        break;

                    case OperandType.InlineR:
                        if (pos + 8 <= endPos)
                            sb.Append(BitConverter.ToDouble(peBytes, pos).ToString("F6"));
                        pos += 8;
                        break;

                    case OperandType.ShortInlineVar:
                        if (pos < endPos)
                            sb.Append(peBytes[pos].ToString());
                        pos += 1;
                        break;

                    case OperandType.InlineVar:
                        if (pos + 2 <= endPos)
                            sb.Append(BitConverter.ToUInt16(peBytes, pos).ToString());
                        pos += 2;
                        break;

                    case OperandType.ShortInlineBrTarget:
                        if (pos < endPos)
                        {
                            sbyte offset = (sbyte)peBytes[pos];
                            int target = (pos + 1 - codeOffset) + offset;
                            sb.Append($"IL_{target:X4}");
                        }
                        pos += 1;
                        break;

                    case OperandType.InlineBrTarget:
                        if (pos + 4 <= endPos)
                        {
                            int offset = BitConverter.ToInt32(peBytes, pos);
                            int target = (pos + 4 - codeOffset) + offset;
                            sb.Append($"IL_{target:X4}");
                        }
                        pos += 4;
                        break;

                    case OperandType.InlineString:
                        if (pos + 4 <= endPos)
                        {
                            uint strToken = BitConverter.ToUInt32(peBytes, pos);
                            int strIndex = (int)(strToken & 0x00FFFFFF);
                            string str = metadata.ReadUserString((uint)strIndex);
                            sb.Append($"\"{EscapeString(str)}\"");
                        }
                        pos += 4;
                        break;

                    case OperandType.InlineType:
                    case OperandType.InlineField:
                    case OperandType.InlineMethod:
                    case OperandType.InlineTok:
                        if (pos + 4 <= endPos)
                        {
                            uint token = BitConverter.ToUInt32(peBytes, pos);
                            sb.Append(ResolveToken(token));
                        }
                        pos += 4;
                        break;

                    case OperandType.InlineSig:
                        if (pos + 4 <= endPos)
                            sb.Append($"0x{BitConverter.ToUInt32(peBytes, pos):X8}");
                        pos += 4;
                        break;

                    case OperandType.InlineSwitch:
                        if (pos + 4 <= endPos)
                        {
                            int numCases = BitConverter.ToInt32(peBytes, pos);
                            int switchBase2 = (pos + 4 + numCases * 4) - codeOffset;
                            sb.Append($"({numCases} cases) ");
                            for (int i = 0; i < numCases && pos + 4 + (i + 1) * 4 <= endPos; i++)
                            {
                                int offset = BitConverter.ToInt32(peBytes, pos + 4 + i * 4);
                                int target = switchBase2 + offset;
                                if (i > 0) sb.Append(", ");
                                sb.Append($"IL_{target:X4}");
                            }
                        }
                        pos += 4;
                        if (pos + 4 <= endPos)
                        {
                            int nc = BitConverter.ToInt32(peBytes, pos - 4);
                            pos += nc * 4;
                        }
                        break;

                    default:
                        sb.Append("/* unknown operand */");
                        break;
                }

                sb.AppendLine();
            }

            return sb.ToString();
        }

        /// <summary>
        /// Resolve a metadata token to a human-readable name.
        /// </summary>
        public string ResolveToken(uint token)
        {
            if (token == 0) return "/* null */";

            uint tableId = (token >> 24) & 0xFF;
            int rowIndex = (int)(token & 0x00FFFFFF);

            switch (tableId)
            {
                case 0x01: // TypeRef
                    return $"[TypeRef:0x{token:X8}]";

                case 0x02: // TypeDef
                    if (metadata?.TypeDefs != null && rowIndex >= 1 && rowIndex <= metadata.TypeDefs.Length)
                    {
                        var td = metadata.TypeDefs[rowIndex - 1];
                        string ns = metadata.ReadString(td.NamespaceIndex);
                        string name = metadata.ReadString(td.NameIndex);
                        return string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
                    }
                    return $"[TypeDef:0x{token:X8}]";

                case 0x04: // Field
                    if (metadata?.Fields != null && rowIndex >= 1 && rowIndex <= metadata.Fields.Length)
                    {
                        var fd = metadata.Fields[rowIndex - 1];
                        return metadata.ReadString(fd.NameIndex);
                    }
                    return $"[Field:0x{token:X8}]";

                case 0x06: // MethodDef
                    if (metadata?.MethodDefs != null && rowIndex >= 1 && rowIndex <= metadata.MethodDefs.Length)
                    {
                        var md = metadata.MethodDefs[rowIndex - 1];
                        return metadata.ReadString(md.NameIndex) + "()";
                    }
                    return $"[Method:0x{token:X8}]";

                case 0x0A: // MemberRef
                    if (metadata?.MemberRefs != null && rowIndex >= 1 && rowIndex <= metadata.MemberRefs.Length)
                    {
                        var mr = metadata.MemberRefs[rowIndex - 1];
                        string parent = metadata.ResolveMemberRefParent(mr.Class);
                        string name = metadata.ReadString(mr.NameIndex);
                        return $"{parent}::{name}";
                    }
                    return $"[MemberRef:0x{token:X8}]";

                case 0x11: // StandAloneSig
                    return $"[StandAloneSig:0x{token:X8}]";

                case 0x1B: // TypeSpec
                    return $"[TypeSpec:0x{token:X8}]";

                case 0x2B: // MethodSpec
                    return $"[MethodSpec:0x{token:X8}]";

                case 0x70: // String (user string)
                    {
                        int idx = (int)(token & 0x00FFFFFF);
                        string str = metadata?.ReadUserString((uint)idx) ?? "";
                        return $"\"{EscapeString(str)}\"";
                    }

                default:
                    return $"[0x{token:X8}]";
            }
        }

        private string EscapeString(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
        }

        // ---- Opcode table ----

        public enum OperandType
        {
            InlineNone, ShortInlineI, InlineI, InlineI8,
            ShortInlineR, InlineR,
            ShortInlineVar, InlineVar,
            ShortInlineBrTarget, InlineBrTarget,
            InlineString, InlineType, InlineField, InlineMethod, InlineTok,
            InlineSig, InlineSwitch
        }

        public struct OpcodeInfo
        {
            public string Name;
            public OperandType OperandType;
            public OpcodeInfo(string name, OperandType type) { Name = name; OperandType = type; }
        }

        private static readonly Dictionary<int, OpcodeInfo> Opcodes = BuildOpcodeTable();

        private static Dictionary<int, OpcodeInfo> BuildOpcodeTable()
        {
            var t = new Dictionary<int, OpcodeInfo>();

            // 1-byte opcodes
            t[0x00] = new OpcodeInfo("nop", OperandType.InlineNone);
            t[0x01] = new OpcodeInfo("break", OperandType.InlineNone);
            t[0x02] = new OpcodeInfo("ldarg.0", OperandType.InlineNone);
            t[0x03] = new OpcodeInfo("ldarg.1", OperandType.InlineNone);
            t[0x04] = new OpcodeInfo("ldarg.2", OperandType.InlineNone);
            t[0x05] = new OpcodeInfo("ldarg.3", OperandType.InlineNone);
            t[0x06] = new OpcodeInfo("ldloc.0", OperandType.InlineNone);
            t[0x07] = new OpcodeInfo("ldloc.1", OperandType.InlineNone);
            t[0x08] = new OpcodeInfo("ldloc.2", OperandType.InlineNone);
            t[0x09] = new OpcodeInfo("ldloc.3", OperandType.InlineNone);
            t[0x0A] = new OpcodeInfo("stloc.0", OperandType.InlineNone);
            t[0x0B] = new OpcodeInfo("stloc.1", OperandType.InlineNone);
            t[0x0C] = new OpcodeInfo("stloc.2", OperandType.InlineNone);
            t[0x0D] = new OpcodeInfo("stloc.3", OperandType.InlineNone);
            t[0x0E] = new OpcodeInfo("ldarg.s", OperandType.ShortInlineVar);
            t[0x0F] = new OpcodeInfo("ldarga.s", OperandType.ShortInlineVar);
            t[0x10] = new OpcodeInfo("starg.s", OperandType.ShortInlineVar);
            t[0x11] = new OpcodeInfo("ldloc.s", OperandType.ShortInlineVar);
            t[0x12] = new OpcodeInfo("ldloca.s", OperandType.ShortInlineVar);
            t[0x13] = new OpcodeInfo("stloc.s", OperandType.ShortInlineVar);
            t[0x14] = new OpcodeInfo("ldnull", OperandType.InlineNone);
            t[0x15] = new OpcodeInfo("ldc.i4.m1", OperandType.InlineNone);
            t[0x16] = new OpcodeInfo("ldc.i4.0", OperandType.InlineNone);
            t[0x17] = new OpcodeInfo("ldc.i4.1", OperandType.InlineNone);
            t[0x18] = new OpcodeInfo("ldc.i4.2", OperandType.InlineNone);
            t[0x19] = new OpcodeInfo("ldc.i4.3", OperandType.InlineNone);
            t[0x1A] = new OpcodeInfo("ldc.i4.4", OperandType.InlineNone);
            t[0x1B] = new OpcodeInfo("ldc.i4.5", OperandType.InlineNone);
            t[0x1C] = new OpcodeInfo("ldc.i4.6", OperandType.InlineNone);
            t[0x1D] = new OpcodeInfo("ldc.i4.7", OperandType.InlineNone);
            t[0x1E] = new OpcodeInfo("ldc.i4.8", OperandType.InlineNone);
            t[0x1F] = new OpcodeInfo("ldc.i4.s", OperandType.ShortInlineI);
            t[0x20] = new OpcodeInfo("ldc.i4", OperandType.InlineI);
            t[0x21] = new OpcodeInfo("ldc.i8", OperandType.InlineI8);
            t[0x22] = new OpcodeInfo("ldc.r4", OperandType.ShortInlineR);
            t[0x23] = new OpcodeInfo("ldc.r8", OperandType.InlineR);
            t[0x25] = new OpcodeInfo("dup", OperandType.InlineNone);
            t[0x26] = new OpcodeInfo("pop", OperandType.InlineNone);
            t[0x27] = new OpcodeInfo("jmp", OperandType.InlineMethod);
            t[0x28] = new OpcodeInfo("call", OperandType.InlineMethod);
            t[0x29] = new OpcodeInfo("calli", OperandType.InlineSig);
            t[0x2A] = new OpcodeInfo("ret", OperandType.InlineNone);
            t[0x2B] = new OpcodeInfo("br.s", OperandType.ShortInlineBrTarget);
            t[0x2C] = new OpcodeInfo("brfalse.s", OperandType.ShortInlineBrTarget);
            t[0x2D] = new OpcodeInfo("brtrue.s", OperandType.ShortInlineBrTarget);
            t[0x2E] = new OpcodeInfo("beq.s", OperandType.ShortInlineBrTarget);
            t[0x2F] = new OpcodeInfo("bge.s", OperandType.ShortInlineBrTarget);
            t[0x30] = new OpcodeInfo("bgt.s", OperandType.ShortInlineBrTarget);
            t[0x31] = new OpcodeInfo("ble.s", OperandType.ShortInlineBrTarget);
            t[0x32] = new OpcodeInfo("blt.s", OperandType.ShortInlineBrTarget);
            t[0x33] = new OpcodeInfo("bne.un.s", OperandType.ShortInlineBrTarget);
            t[0x34] = new OpcodeInfo("bge.un.s", OperandType.ShortInlineBrTarget);
            t[0x35] = new OpcodeInfo("bgt.un.s", OperandType.ShortInlineBrTarget);
            t[0x36] = new OpcodeInfo("ble.un.s", OperandType.ShortInlineBrTarget);
            t[0x37] = new OpcodeInfo("blt.un.s", OperandType.ShortInlineBrTarget);
            t[0x38] = new OpcodeInfo("br", OperandType.InlineBrTarget);
            t[0x39] = new OpcodeInfo("brfalse", OperandType.InlineBrTarget);
            t[0x3A] = new OpcodeInfo("brtrue", OperandType.InlineBrTarget);
            t[0x3B] = new OpcodeInfo("beq", OperandType.InlineBrTarget);
            t[0x3C] = new OpcodeInfo("bge", OperandType.InlineBrTarget);
            t[0x3D] = new OpcodeInfo("bgt", OperandType.InlineBrTarget);
            t[0x3E] = new OpcodeInfo("ble", OperandType.InlineBrTarget);
            t[0x3F] = new OpcodeInfo("blt", OperandType.InlineBrTarget);
            t[0x40] = new OpcodeInfo("bne.un", OperandType.InlineBrTarget);
            t[0x41] = new OpcodeInfo("bge.un", OperandType.InlineBrTarget);
            t[0x42] = new OpcodeInfo("bgt.un", OperandType.InlineBrTarget);
            t[0x43] = new OpcodeInfo("ble.un", OperandType.InlineBrTarget);
            t[0x44] = new OpcodeInfo("blt.un", OperandType.InlineBrTarget);
            t[0x45] = new OpcodeInfo("switch", OperandType.InlineSwitch);
            t[0x46] = new OpcodeInfo("ldind.i1", OperandType.InlineNone);
            t[0x47] = new OpcodeInfo("ldind.u1", OperandType.InlineNone);
            t[0x48] = new OpcodeInfo("ldind.i2", OperandType.InlineNone);
            t[0x49] = new OpcodeInfo("ldind.u2", OperandType.InlineNone);
            t[0x4A] = new OpcodeInfo("ldind.i4", OperandType.InlineNone);
            t[0x4B] = new OpcodeInfo("ldind.u4", OperandType.InlineNone);
            t[0x4C] = new OpcodeInfo("ldind.i8", OperandType.InlineNone);
            t[0x4D] = new OpcodeInfo("ldind.i", OperandType.InlineNone);
            t[0x4E] = new OpcodeInfo("ldind.r4", OperandType.InlineNone);
            t[0x4F] = new OpcodeInfo("ldind.r8", OperandType.InlineNone);
            t[0x50] = new OpcodeInfo("ldind.ref", OperandType.InlineNone);
            t[0x51] = new OpcodeInfo("stind.ref", OperandType.InlineNone);
            t[0x52] = new OpcodeInfo("stind.i1", OperandType.InlineNone);
            t[0x53] = new OpcodeInfo("stind.i2", OperandType.InlineNone);
            t[0x54] = new OpcodeInfo("stind.i4", OperandType.InlineNone);
            t[0x55] = new OpcodeInfo("stind.i8", OperandType.InlineNone);
            t[0x56] = new OpcodeInfo("stind.r4", OperandType.InlineNone);
            t[0x57] = new OpcodeInfo("stind.r8", OperandType.InlineNone);
            t[0x58] = new OpcodeInfo("add", OperandType.InlineNone);
            t[0x59] = new OpcodeInfo("sub", OperandType.InlineNone);
            t[0x5A] = new OpcodeInfo("mul", OperandType.InlineNone);
            t[0x5B] = new OpcodeInfo("div", OperandType.InlineNone);
            t[0x5C] = new OpcodeInfo("div.un", OperandType.InlineNone);
            t[0x5D] = new OpcodeInfo("rem", OperandType.InlineNone);
            t[0x5E] = new OpcodeInfo("rem.un", OperandType.InlineNone);
            t[0x5F] = new OpcodeInfo("and", OperandType.InlineNone);
            t[0x60] = new OpcodeInfo("or", OperandType.InlineNone);
            t[0x61] = new OpcodeInfo("xor", OperandType.InlineNone);
            t[0x62] = new OpcodeInfo("shl", OperandType.InlineNone);
            t[0x63] = new OpcodeInfo("shr", OperandType.InlineNone);
            t[0x64] = new OpcodeInfo("shr.un", OperandType.InlineNone);
            t[0x65] = new OpcodeInfo("neg", OperandType.InlineNone);
            t[0x66] = new OpcodeInfo("not", OperandType.InlineNone);
            t[0x67] = new OpcodeInfo("conv.i1", OperandType.InlineNone);
            t[0x68] = new OpcodeInfo("conv.i2", OperandType.InlineNone);
            t[0x69] = new OpcodeInfo("conv.i4", OperandType.InlineNone);
            t[0x6A] = new OpcodeInfo("conv.i8", OperandType.InlineNone);
            t[0x6B] = new OpcodeInfo("conv.r4", OperandType.InlineNone);
            t[0x6C] = new OpcodeInfo("conv.r8", OperandType.InlineNone);
            t[0x6D] = new OpcodeInfo("conv.u4", OperandType.InlineNone);
            t[0x6E] = new OpcodeInfo("conv.u8", OperandType.InlineNone);
            t[0x6F] = new OpcodeInfo("callvirt", OperandType.InlineMethod);
            t[0x70] = new OpcodeInfo("cpobj", OperandType.InlineType);
            t[0x71] = new OpcodeInfo("ldobj", OperandType.InlineType);
            t[0x72] = new OpcodeInfo("ldstr", OperandType.InlineString);
            t[0x73] = new OpcodeInfo("newobj", OperandType.InlineMethod);
            t[0x74] = new OpcodeInfo("castclass", OperandType.InlineType);
            t[0x75] = new OpcodeInfo("isinst", OperandType.InlineType);
            t[0x76] = new OpcodeInfo("conv.r.un", OperandType.InlineNone);
            t[0x79] = new OpcodeInfo("unbox", OperandType.InlineType);
            t[0x7A] = new OpcodeInfo("throw", OperandType.InlineNone);
            t[0x7B] = new OpcodeInfo("ldfld", OperandType.InlineField);
            t[0x7C] = new OpcodeInfo("ldflda", OperandType.InlineField);
            t[0x7D] = new OpcodeInfo("stfld", OperandType.InlineField);
            t[0x7E] = new OpcodeInfo("ldsfld", OperandType.InlineField);
            t[0x7F] = new OpcodeInfo("ldsflda", OperandType.InlineField);
            t[0x80] = new OpcodeInfo("stsfld", OperandType.InlineField);
            t[0x81] = new OpcodeInfo("stobj", OperandType.InlineType);
            t[0x8C] = new OpcodeInfo("box", OperandType.InlineType);
            t[0x8D] = new OpcodeInfo("newarr", OperandType.InlineType);
            t[0x8E] = new OpcodeInfo("ldlen", OperandType.InlineNone);
            t[0x8F] = new OpcodeInfo("ldelema", OperandType.InlineType);
            t[0x98] = new OpcodeInfo("stelem.i", OperandType.InlineNone);
            t[0x99] = new OpcodeInfo("stelem.i1", OperandType.InlineNone);
            t[0x9A] = new OpcodeInfo("stelem.i2", OperandType.InlineNone);
            t[0x9B] = new OpcodeInfo("stelem.i4", OperandType.InlineNone);
            t[0x9C] = new OpcodeInfo("stelem.i8", OperandType.InlineNone);
            t[0x9D] = new OpcodeInfo("stelem.r4", OperandType.InlineNone);
            t[0x9E] = new OpcodeInfo("stelem.r8", OperandType.InlineNone);
            t[0x9F] = new OpcodeInfo("stelem.ref", OperandType.InlineNone);
            t[0xA2] = new OpcodeInfo("stelem", OperandType.InlineType);
            t[0xA5] = new OpcodeInfo("unbox.any", OperandType.InlineType);
            t[0xD0] = new OpcodeInfo("ldtoken", OperandType.InlineTok);
            t[0xD1] = new OpcodeInfo("conv.u2", OperandType.InlineNone);
            t[0xD2] = new OpcodeInfo("conv.u1", OperandType.InlineNone);
            t[0xD3] = new OpcodeInfo("conv.i", OperandType.InlineNone);
            t[0xD6] = new OpcodeInfo("add.ovf", OperandType.InlineNone);
            t[0xD7] = new OpcodeInfo("add.ovf.un", OperandType.InlineNone);
            t[0xD8] = new OpcodeInfo("mul.ovf", OperandType.InlineNone);
            t[0xD9] = new OpcodeInfo("mul.ovf.un", OperandType.InlineNone);
            t[0xDA] = new OpcodeInfo("sub.ovf", OperandType.InlineNone);
            t[0xDB] = new OpcodeInfo("sub.ovf.un", OperandType.InlineNone);
            t[0xDC] = new OpcodeInfo("endfinally", OperandType.InlineNone);
            t[0xDD] = new OpcodeInfo("leave", OperandType.InlineBrTarget);
            t[0xDE] = new OpcodeInfo("leave.s", OperandType.ShortInlineBrTarget);
            t[0xDF] = new OpcodeInfo("stind.i", OperandType.InlineNone);
            t[0xE0] = new OpcodeInfo("conv.u", OperandType.InlineNone);

            // 2-byte opcodes (0xFE prefix)
            t[0xFE00] = new OpcodeInfo("arglist", OperandType.InlineNone);
            t[0xFE01] = new OpcodeInfo("ceq", OperandType.InlineNone);
            t[0xFE02] = new OpcodeInfo("cgt", OperandType.InlineNone);
            t[0xFE03] = new OpcodeInfo("cgt.un", OperandType.InlineNone);
            t[0xFE04] = new OpcodeInfo("clt", OperandType.InlineNone);
            t[0xFE05] = new OpcodeInfo("clt.un", OperandType.InlineNone);
            t[0xFE06] = new OpcodeInfo("ldftn", OperandType.InlineMethod);
            t[0xFE09] = new OpcodeInfo("ldarg", OperandType.InlineVar);
            t[0xFE0A] = new OpcodeInfo("ldarga", OperandType.InlineVar);
            t[0xFE0B] = new OpcodeInfo("starg", OperandType.InlineVar);
            t[0xFE0C] = new OpcodeInfo("ldloc", OperandType.InlineVar);
            t[0xFE0D] = new OpcodeInfo("ldloca", OperandType.InlineVar);
            t[0xFE0E] = new OpcodeInfo("stloc", OperandType.InlineVar);
            t[0xFE12] = new OpcodeInfo("readonly.", OperandType.InlineNone);
            t[0xFE15] = new OpcodeInfo("initobj", OperandType.InlineType);
            t[0xFE16] = new OpcodeInfo("constrained.", OperandType.InlineType);
            t[0xFE19] = new OpcodeInfo("rethrow", OperandType.InlineNone);
            t[0xFE1C] = new OpcodeInfo("sizeof", OperandType.InlineType);

            return t;
        }

        private OpcodeInfo GetOpcodeInfo(int opCode)
        {
            if (Opcodes.TryGetValue(opCode, out var info))
                return info;
            return new OpcodeInfo($"/* unknown 0x{opCode:X} */", OperandType.InlineNone);
        }

        private int GetOperandSize(OperandType type)
        {
            switch (type)
            {
                case OperandType.InlineNone: return 0;
                case OperandType.ShortInlineI: return 1;
                case OperandType.ShortInlineVar: return 1;
                case OperandType.ShortInlineBrTarget: return 1;
                case OperandType.InlineI: return 4;
                case OperandType.InlineVar: return 2;
                case OperandType.InlineI8: return 8;
                case OperandType.ShortInlineR: return 4;
                case OperandType.InlineR: return 8;
                case OperandType.InlineBrTarget: return 4;
                case OperandType.InlineString: return 4;
                case OperandType.InlineType: return 4;
                case OperandType.InlineField: return 4;
                case OperandType.InlineMethod: return 4;
                case OperandType.InlineTok: return 4;
                case OperandType.InlineSig: return 4;
                default: return 0;
            }
        }
    }
}
