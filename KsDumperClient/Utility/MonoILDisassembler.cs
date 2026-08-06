using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class MonoILDisassembler
    {
        public class ILInstruction
        {
            public int Offset;
            public string Mnemonic;
            public string Operand;
        }

        public class MethodBody
        {
            public uint RVA;
            public int MaxStack;
            public int CodeSize;
            public int LocalVarCount;
            public bool InitLocals;
            public List<ILInstruction> Instructions = new List<ILInstruction>();
        }

        private static readonly Dictionary<byte, (string name, int operandSize)> OneByteOpcodes = new Dictionary<byte, (string, int)>
        {
            { 0x00, ("nop", 0) }, { 0x01, ("break", 0) },
            { 0x02, ("ldarg.0", 0) }, { 0x03, ("ldarg.1", 0) }, { 0x04, ("ldarg.2", 0) }, { 0x05, ("ldarg.3", 0) },
            { 0x06, ("ldloc.0", 0) }, { 0x07, ("ldloc.1", 0) }, { 0x08, ("ldloc.2", 0) }, { 0x09, ("ldloc.3", 0) },
            { 0x0A, ("stloc.0", 0) }, { 0x0B, ("stloc.1", 0) }, { 0x0C, ("stloc.2", 0) }, { 0x0D, ("stloc.3", 0) },
            { 0x0E, ("ldarg.s", 1) }, { 0x0F, ("ldarga.s", 1) }, { 0x10, ("starg.s", 1) },
            { 0x11, ("ldloc.s", 1) }, { 0x12, ("ldloca.s", 1) }, { 0x13, ("stloc.s", 1) },
            { 0x14, ("ldnull", 0) },
            { 0x15, ("ldc.i4.m1", 0) }, { 0x16, ("ldc.i4.0", 0) }, { 0x17, ("ldc.i4.1", 0) },
            { 0x18, ("ldc.i4.2", 0) }, { 0x19, ("ldc.i4.3", 0) }, { 0x1A, ("ldc.i4.4", 0) },
            { 0x1B, ("ldc.i4.5", 0) }, { 0x1C, ("ldc.i4.6", 0) }, { 0x1D, ("ldc.i4.7", 0) },
            { 0x1E, ("ldc.i4.8", 0) },
            { 0x1F, ("ldc.i4.s", 1) }, { 0x20, ("ldc.i4", 4) },
            { 0x21, ("ldc.i8", 8) }, { 0x22, ("ldc.r4", 4) }, { 0x23, ("ldc.r8", 8) },
            { 0x25, ("dup", 0) }, { 0x26, ("pop", 0) },
            { 0x27, ("jmp", 4) }, { 0x28, ("call", 4) }, { 0x29, ("calli", 4) },
            { 0x2A, ("ret", 0) },
            { 0x2B, ("br.s", 1) }, { 0x2C, ("brfalse.s", 1) }, { 0x2D, ("brtrue.s", 1) },
            { 0x2E, ("beq.s", 1) }, { 0x2F, ("bge.s", 1) }, { 0x30, ("bgt.s", 1) },
            { 0x31, ("ble.s", 1) }, { 0x32, ("blt.s", 1) }, { 0x33, ("bne.un.s", 1) },
            { 0x34, ("bge.un.s", 1) }, { 0x35, ("bgt.un.s", 1) }, { 0x36, ("ble.un.s", 1) },
            { 0x37, ("blt.un.s", 1) },
            { 0x38, ("br", 4) }, { 0x39, ("brfalse", 4) }, { 0x3A, ("brtrue", 4) },
            { 0x3B, ("beq", 4) }, { 0x3C, ("bge", 4) }, { 0x3D, ("bgt", 4) },
            { 0x3E, ("ble", 4) }, { 0x3F, ("blt", 4) }, { 0x40, ("bne.un", 4) },
            { 0x41, ("bge.un", 4) }, { 0x42, ("bgt.un", 4) }, { 0x43, ("ble.un", 4) },
            { 0x44, ("blt.un", 4) },
            { 0x45, ("switch", -1) },
            { 0x46, ("ldind.i1", 0) }, { 0x47, ("ldind.u1", 0) }, { 0x48, ("ldind.i2", 0) },
            { 0x49, ("ldind.u2", 0) }, { 0x4A, ("ldind.i4", 0) }, { 0x4B, ("ldind.u4", 0) },
            { 0x4C, ("ldind.i8", 0) }, { 0x4D, ("ldind.i", 0) }, { 0x4E, ("ldind.r4", 0) },
            { 0x4F, ("ldind.r8", 0) }, { 0x50, ("ldind.ref", 0) },
            { 0x51, ("stind.ref", 0) }, { 0x52, ("stind.i1", 0) }, { 0x53, ("stind.i2", 0) },
            { 0x54, ("stind.i4", 0) }, { 0x55, ("stind.i8", 0) }, { 0x56, ("stind.r4", 0) },
            { 0x57, ("stind.r8", 0) },
            { 0x58, ("add", 0) }, { 0x59, ("sub", 0) }, { 0x5A, ("mul", 0) },
            { 0x5B, ("div", 0) }, { 0x5C, ("div.un", 0) }, { 0x5D, ("rem", 0) },
            { 0x5E, ("rem.un", 0) }, { 0x5F, ("and", 0) }, { 0x60, ("or", 0) },
            { 0x61, ("xor", 0) }, { 0x62, ("shl", 0) }, { 0x63, ("shr", 0) },
            { 0x64, ("shr.un", 0) }, { 0x65, ("neg", 0) }, { 0x66, ("not", 0) },
            { 0x67, ("conv.i1", 0) }, { 0x68, ("conv.i2", 0) }, { 0x69, ("conv.i4", 0) },
            { 0x6A, ("conv.i8", 0) }, { 0x6B, ("conv.r4", 0) }, { 0x6C, ("conv.r8", 0) },
            { 0x6D, ("conv.u4", 0) }, { 0x6E, ("conv.u8", 0) },
            { 0x6F, ("callvirt", 4) },
            { 0x70, ("cpobj", 4) }, { 0x71, ("ldobj", 4) }, { 0x72, ("ldstr", 4) },
            { 0x73, ("newobj", 4) }, { 0x74, ("castclass", 4) }, { 0x75, ("isinst", 4) },
            { 0x76, ("conv.r.un", 0) },
            { 0x79, ("unbox", 4) }, { 0x7A, ("throw", 0) },
            { 0x7B, ("ldfld", 4) }, { 0x7C, ("ldflda", 4) }, { 0x7D, ("stfld", 4) },
            { 0x7E, ("ldsfld", 4) }, { 0x7F, ("ldsflda", 4) }, { 0x80, ("stsfld", 4) },
            { 0x81, ("stobj", 4) },
            { 0x82, ("conv.ovf.i1.un", 0) }, { 0x83, ("conv.ovf.i2.un", 0) },
            { 0x84, ("conv.ovf.i4.un", 0) }, { 0x85, ("conv.ovf.i8.un", 0) },
            { 0x86, ("conv.ovf.u1.un", 0) }, { 0x87, ("conv.ovf.u2.un", 0) },
            { 0x88, ("conv.ovf.u4.un", 0) }, { 0x89, ("conv.ovf.u8.un", 0) },
            { 0x8A, ("conv.ovf.i.un", 0) }, { 0x8B, ("conv.ovf.u.un", 0) },
            { 0x8C, ("box", 4) }, { 0x8D, ("newarr", 4) }, { 0x8E, ("ldlen", 0) },
            { 0x8F, ("ldelema", 4) },
            { 0x90, ("ldelem.i1", 0) }, { 0x91, ("ldelem.u1", 0) }, { 0x92, ("ldelem.i2", 0) },
            { 0x93, ("ldelem.u2", 0) }, { 0x94, ("ldelem.i4", 0) }, { 0x95, ("ldelem.u4", 0) },
            { 0x96, ("ldelem.i8", 0) }, { 0x97, ("ldelem.i", 0) }, { 0x98, ("ldelem.r4", 0) },
            { 0x99, ("ldelem.r8", 0) }, { 0x9A, ("ldelem.ref", 0) },
            { 0x9B, ("stelem.i", 0) }, { 0x9C, ("stelem.i1", 0) }, { 0x9D, ("stelem.i2", 0) },
            { 0x9E, ("stelem.i4", 0) }, { 0x9F, ("stelem.i8", 0) }, { 0xA0, ("stelem.r4", 0) },
            { 0xA1, ("stelem.r8", 0) }, { 0xA2, ("stelem.ref", 0) },
            { 0xA3, ("ldelem", 4) }, { 0xA4, ("stelem", 4) }, { 0xA5, ("unbox.any", 4) },
            { 0xB3, ("conv.ovf.i1", 0) }, { 0xB4, ("conv.ovf.u1", 0) },
            { 0xB5, ("conv.ovf.i2", 0) }, { 0xB6, ("conv.ovf.u2", 0) },
            { 0xB7, ("conv.ovf.i4", 0) }, { 0xB8, ("conv.ovf.u4", 0) },
            { 0xB9, ("conv.ovf.i8", 0) }, { 0xBA, ("conv.ovf.u8", 0) },
            { 0xC2, ("refanyval", 4) }, { 0xC3, ("ckfinite", 0) },
            { 0xC6, ("mkrefany", 4) },
            { 0xD0, ("ldtoken", 4) }, { 0xD1, ("conv.u2", 0) }, { 0xD2, ("conv.u1", 0) },
            { 0xD3, ("conv.i", 0) }, { 0xD4, ("conv.ovf.i", 0) }, { 0xD5, ("conv.ovf.u", 0) },
            { 0xD6, ("add.ovf", 0) }, { 0xD7, ("add.ovf.un", 0) },
            { 0xD8, ("mul.ovf", 0) }, { 0xD9, ("mul.ovf.un", 0) },
            { 0xDA, ("sub.ovf", 0) }, { 0xDB, ("sub.ovf.un", 0) },
            { 0xDC, ("endfinally", 0) },
            { 0xDD, ("leave", 4) }, { 0xDE, ("leave.s", 1) },
            { 0xDF, ("stind.i", 0) }, { 0xE0, ("conv.u", 0) },
        };

        private static readonly Dictionary<byte, (string name, int operandSize)> TwoByteOpcodes = new Dictionary<byte, (string, int)>
        {
            { 0x00, ("arglist", 0) }, { 0x01, ("ceq", 0) }, { 0x02, ("cgt", 0) },
            { 0x03, ("cgt.un", 0) }, { 0x04, ("clt", 0) }, { 0x05, ("clt.un", 0) },
            { 0x06, ("ldftn", 4) }, { 0x07, ("ldvirtftn", 4) },
            { 0x09, ("ldarg", 2) }, { 0x0A, ("ldarga", 2) }, { 0x0B, ("starg", 2) },
            { 0x0C, ("ldloc", 2) }, { 0x0D, ("ldloca", 2) }, { 0x0E, ("stloc", 2) },
            { 0x0F, ("localloc", 0) }, { 0x11, ("endfilter", 0) },
            { 0x12, ("unaligned.", 1) }, { 0x13, ("volatile.", 0) },
            { 0x14, ("tail.", 0) }, { 0x15, ("initobj", 4) },
            { 0x16, ("constrained.", 4) }, { 0x17, ("cpblk", 0) },
            { 0x18, ("initblk", 0) }, { 0x1A, ("rethrow", 0) },
            { 0x1C, ("sizeof", 4) }, { 0x1D, ("refanytype", 0) },
            { 0x1E, ("readonly.", 0) },
        };

        public static MethodBody DisassembleMethod(byte[] peData, uint rva)
        {
            if (peData == null || rva == 0) return null;

            int fileOffset = RvaToFileOffset(peData, rva);
            if (fileOffset < 0 || fileOffset >= peData.Length) return null;

            var body = new MethodBody { RVA = rva };

            byte headerByte = peData[fileOffset];

            if ((headerByte & 0x03) == 0x02) // Tiny header
            {
                body.CodeSize = headerByte >> 2;
                body.MaxStack = 8;
                body.LocalVarCount = 0;
                body.InitLocals = false;

                int codeStart = fileOffset + 1;
                if (codeStart + body.CodeSize > peData.Length) return null;

                DisassembleIL(peData, codeStart, body.CodeSize, body.Instructions);
            }
            else if ((headerByte & 0x03) == 0x03) // Fat header
            {
                if (fileOffset + 12 > peData.Length) return null;

                ushort flagsAndSize = BitConverter.ToUInt16(peData, fileOffset);
                body.MaxStack = BitConverter.ToUInt16(peData, fileOffset + 2);
                body.CodeSize = BitConverter.ToInt32(peData, fileOffset + 4);
                uint localVarSigTok = BitConverter.ToUInt32(peData, fileOffset + 8);

                body.InitLocals = (flagsAndSize & 0x0010) != 0;
                int headerSize = (flagsAndSize >> 12) * 4;

                int codeStart = fileOffset + headerSize;
                if (codeStart + body.CodeSize > peData.Length) return null;

                DisassembleIL(peData, codeStart, body.CodeSize, body.Instructions);
            }

            return body;
        }

        private static void DisassembleIL(byte[] data, int start, int length, List<ILInstruction> instructions)
        {
            int end = start + length;
            int p = start;

            while (p < end)
            {
                var instr = new ILInstruction { Offset = p - start };
                byte op = data[p++];

                if (op == 0xFE) // Two-byte opcode prefix
                {
                    if (p >= end) break;
                    byte op2 = data[p++];
                    if (TwoByteOpcodes.TryGetValue(op2, out var info2))
                    {
                        instr.Mnemonic = info2.name;
                        instr.Operand = ReadOperand(data, ref p, end, info2.operandSize, instr.Offset);
                    }
                    else
                    {
                        instr.Mnemonic = $"<unknown FE.{op2:X2}>";
                    }
                }
                else if (OneByteOpcodes.TryGetValue(op, out var info))
                {
                    instr.Mnemonic = info.name;
                    if (info.operandSize == -1 && op == 0x45) // switch
                    {
                        if (p + 4 > end) break;
                        int count = BitConverter.ToInt32(data, p); p += 4;
                        var targets = new List<string>();
                        for (int i = 0; i < count && p + 4 <= end; i++)
                        {
                            int target = BitConverter.ToInt32(data, p); p += 4;
                            targets.Add($"IL_{(p - start + target):X4}");
                        }
                        instr.Operand = $"({string.Join(", ", targets)})";
                    }
                    else
                    {
                        instr.Operand = ReadOperand(data, ref p, end, info.operandSize, instr.Offset);
                    }
                }
                else
                {
                    instr.Mnemonic = $"<unknown {op:X2}>";
                }

                instructions.Add(instr);
            }
        }

        private static string ReadOperand(byte[] data, ref int p, int end, int size, int instrOffset)
        {
            if (size <= 0) return null;

            switch (size)
            {
                case 1:
                    if (p >= end) return null;
                    byte b = data[p++];
                    return $"0x{b:X2}";
                case 2:
                    if (p + 2 > end) return null;
                    short s = BitConverter.ToInt16(data, p); p += 2;
                    return $"0x{s:X4}";
                case 4:
                    if (p + 4 > end) return null;
                    int i = BitConverter.ToInt32(data, p); p += 4;
                    return $"0x{(uint)i:X8}";
                case 8:
                    if (p + 8 > end) return null;
                    long l = BitConverter.ToInt64(data, p); p += 8;
                    return $"0x{(ulong)l:X16}";
                default:
                    return null;
            }
        }

        public static string FormatMethodBody(MethodBody body, string methodName = null)
        {
            if (body == null) return "// Method body not found";

            var sb = new StringBuilder();
            if (methodName != null)
                sb.AppendLine($"// {methodName}");
            sb.AppendLine($"// RVA: 0x{body.RVA:X8}, MaxStack: {body.MaxStack}, CodeSize: {body.CodeSize}");
            if (body.InitLocals)
                sb.AppendLine("// .locals init");
            sb.AppendLine();

            foreach (var instr in body.Instructions)
            {
                string operand = instr.Operand != null ? " " + instr.Operand : "";
                sb.AppendLine($"IL_{instr.Offset:X4}: {instr.Mnemonic}{operand}");
            }

            return sb.ToString();
        }

        public static string DisassembleAllMethods(byte[] peData, MonoSdkGenerator.MonoSdkInfo sdkInfo, int maxMethods = 500)
        {
            if (peData == null || sdkInfo == null) return "// No data";

            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Mono IL Disassembly");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            int count = 0;
            foreach (var cls in sdkInfo.Classes)
            {
                bool headerWritten = false;
                foreach (var method in cls.Methods)
                {
                    if (method.RVA == 0 || count >= maxMethods) continue;

                    var body = DisassembleMethod(peData, method.RVA);
                    if (body == null || body.Instructions.Count == 0) continue;

                    if (!headerWritten)
                    {
                        string fullName = string.IsNullOrEmpty(cls.Namespace) ? cls.Name : $"{cls.Namespace}.{cls.Name}";
                        sb.AppendLine($"// ====== {fullName} ======");
                        headerWritten = true;
                    }

                    sb.AppendLine(FormatMethodBody(body, method.Name));
                    sb.AppendLine();
                    count++;
                }
            }

            sb.AppendLine($"// Disassembled {count} method bodies");
            return sb.ToString();
        }

        private static int RvaToFileOffset(byte[] peData, uint rva)
        {
            if (peData == null || peData.Length < 0x40) return -1;

            int peOffset = BitConverter.ToInt32(peData, 0x3C);
            if (peOffset < 0 || peOffset + 24 > peData.Length) return -1;

            ushort sectionCount = BitConverter.ToUInt16(peData, peOffset + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peData, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + optHeaderSize;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOffset + s * 40;
                if (off + 40 > peData.Length) break;

                uint virtualSize = BitConverter.ToUInt32(peData, off + 8);
                uint virtualAddr = BitConverter.ToUInt32(peData, off + 12);
                uint rawSize = BitConverter.ToUInt32(peData, off + 16);
                uint rawAddr = BitConverter.ToUInt32(peData, off + 20);

                if (rva >= virtualAddr && rva < virtualAddr + Math.Max(virtualSize, rawSize))
                    return (int)(rawAddr + (rva - virtualAddr));
            }

            return -1;
        }
    }
}
