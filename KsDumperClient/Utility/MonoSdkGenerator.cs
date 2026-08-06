using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class MonoSdkGenerator
    {
        public class MonoSdkInfo
        {
            public string AssemblyName;
            public List<MonoClassInfo> Classes = new List<MonoClassInfo>();
        }

        public class MonoClassInfo
        {
            public string Namespace;
            public string Name;
            public uint Flags;
            public List<MonoMethodInfo> Methods = new List<MonoMethodInfo>();
            public List<MonoFieldInfo> Fields = new List<MonoFieldInfo>();
        }

        public class MonoMethodInfo
        {
            public string Name;
            public ushort Flags;
            public ushort ImplFlags;
            public int ParameterCount;
            public uint RVA;
            public string ReturnType;
            public string[] ParameterTypes;
            public string[] ParameterNames;
        }

        public class MonoFieldInfo
        {
            public string Name;
            public ushort Flags;
            public string TypeName;
        }

        public static MonoSdkInfo ParseFromPE(byte[] peBytes)
        {
            if (peBytes == null || peBytes.Length < 64) return null;

            // Parse DOS header
            if (BitConverter.ToUInt16(peBytes, 0) != 0x5A4D) return null;
            int peOffset = BitConverter.ToInt32(peBytes, 60);
            if (peOffset + 24 > peBytes.Length) return null;

            // PE signature
            if (BitConverter.ToUInt32(peBytes, peOffset) != 0x00004550) return null;

            ushort magic = BitConverter.ToUInt16(peBytes, peOffset + 24);
            bool is64 = magic == 0x20b;

            // CLI descriptor is DataDirectory[14]
            int dataDirOffset = is64 ? peOffset + 24 + 112 : peOffset + 24 + 96;
            int cliDirIndex = dataDirOffset + 14 * 8; // 14th entry, each is 8 bytes
            if (cliDirIndex + 8 > peBytes.Length) return null;

            uint cliRVA = BitConverter.ToUInt32(peBytes, cliDirIndex);
            uint cliSize = BitConverter.ToUInt32(peBytes, cliDirIndex + 4);
            if (cliRVA == 0 || cliSize == 0) return null;

            // Find section containing CLI RVA
            int cliFileOff = RvaToFileOffset(peBytes, peOffset, cliRVA);
            if (cliFileOff <= 0 || cliFileOff + 72 > peBytes.Length) return null;

            // CLI header: Cb(4), MajorRuntime(2), MinorRuntime(2), MetadataRVA(4), MetadataSize(4), ...
            uint metadataRVA = BitConverter.ToUInt32(peBytes, cliFileOff + 8);
            uint metadataSize = BitConverter.ToUInt32(peBytes, cliFileOff + 12);
            if (metadataRVA == 0 || metadataSize == 0) return null;

            int metaOff = RvaToFileOffset(peBytes, peOffset, metadataRVA);
            if (metaOff <= 0 || metaOff + 20 > peBytes.Length) return null;

            // Metadata root signature: 0x424A5342 ("BSJB")
            uint signature = BitConverter.ToUInt32(peBytes, metaOff);
            if (signature != 0x424A5342) return null;

            // Parse metadata root header
            int p = metaOff + 12; // skip signature(4) + major(2) + minor(2) + reserved(4)
            if (p + 4 > peBytes.Length) return null;

            int versionLength = BitConverter.ToInt32(peBytes, p);
            p += 4 + versionLength; // skip version string
            if (p + 4 > peBytes.Length) return null;

            p += 2; // flags
            ushort streamCount = BitConverter.ToUInt16(peBytes, p);
            p += 2;

            // Parse stream headers
            byte[] tildeStream = null;
            byte[] stringsHeap = null;
            byte[] blobHeap = null;

            for (int s = 0; s < streamCount && p + 8 <= peBytes.Length; s++)
            {
                uint streamOffset = BitConverter.ToUInt32(peBytes, p);
                uint streamSize = BitConverter.ToUInt32(peBytes, p + 4);
                p += 8;

                // Read stream name (null-terminated, padded to 4 bytes)
                int nameStart = p;
                while (p < peBytes.Length && peBytes[p] != 0) p++;
                string streamName = Encoding.ASCII.GetString(peBytes, nameStart, p - nameStart);
                p++; // skip null
                while (p % 4 != 0) p++; // align to 4

                int absOffset = metaOff + (int)streamOffset;
                if (absOffset >= 0 && absOffset + streamSize <= peBytes.Length)
                {
                    byte[] streamData = new byte[streamSize];
                    Array.Copy(peBytes, absOffset, streamData, 0, (int)streamSize);

                    if (streamName == "#~" || streamName == "#-")
                        tildeStream = streamData;
                    else if (streamName == "#Strings")
                        stringsHeap = streamData;
                    else if (streamName == "#Blob")
                        blobHeap = streamData;
                }
            }

            if (tildeStream == null || stringsHeap == null) return null;

            return ParseTildeStream(tildeStream, stringsHeap, blobHeap);
        }

        private static MonoSdkInfo ParseTildeStream(byte[] tilde, byte[] strings, byte[] blob)
        {
            var info = new MonoSdkInfo { AssemblyName = "Unknown" };

            if (tilde.Length < 24) return info;

            int p = 4;
            byte heapSizes = tilde[6];

            bool wideStrings = (heapSizes & 0x01) != 0;
            bool wideGuids = (heapSizes & 0x02) != 0;
            bool wideBlobs = (heapSizes & 0x04) != 0;

            long validTables = BitConverter.ToInt64(tilde, 8);
            p = 24;

            int[] rowCounts = new int[64];
            for (int t = 0; t < 64; t++)
            {
                if ((validTables & (1L << t)) != 0)
                {
                    if (p + 4 > tilde.Length) return info;
                    rowCounts[t] = BitConverter.ToInt32(tilde, p);
                    p += 4;
                }
            }

            int stringIdxSize = wideStrings ? 4 : 2;
            int blobIdxSize = wideBlobs ? 4 : 2;

            int typeDefTable = 0x02;
            int methodDefTable = 0x06;
            int fieldTable = 0x04;
            int paramTable = 0x08;

            if ((validTables & (1L << typeDefTable)) == 0) return info;

            int typeDefRowSize = CalculateTypeDefRowSize(rowCounts, stringIdxSize, validTables);
            int methodDefRowSize = CalculateMethodDefRowSize(rowCounts, stringIdxSize, validTables);
            int fieldRowSize = CalculateFieldRowSize(rowCounts, stringIdxSize, validTables);
            int paramRowSize = 2 + 2 + stringIdxSize; // Flags(2) + Sequence(2) + Name
            int methodIdxSize = rowCounts[methodDefTable] > 0xFFFF ? 4 : 2;
            int fieldIdxSize = rowCounts[fieldTable] > 0xFFFF ? 4 : 2;
            int paramIdxSize = rowCounts[paramTable] > 0xFFFF ? 4 : 2;
            int typeDefOrRefSize = CalculateCodedIndexSize(rowCounts, validTables, TypeDefOrRefTables);

            // Skip tables before TypeDef
            for (int t = 0; t < typeDefTable; t++)
            {
                if ((validTables & (1L << t)) != 0)
                {
                    int skipSize = GetTableRowSize(t, rowCounts, stringIdxSize, wideBlobs, wideGuids, validTables);
                    p += skipSize * rowCounts[t];
                }
            }

            // --- Pass 1: read TypeDef rows, collect indices ---
            int typeDefStart = p;
            var typeDefRows = new List<(uint flags, int nameIdx, int nsIdx, int extendsIdx, int fieldList, int methodList)>();

            for (int i = 0; i < rowCounts[typeDefTable] && p + typeDefRowSize <= tilde.Length; i++)
            {
                uint flags = BitConverter.ToUInt32(tilde, p); p += 4;
                int nameIdx = ReadIndex(tilde, ref p, stringIdxSize);
                int nsIdx = ReadIndex(tilde, ref p, stringIdxSize);
                int extendsIdx = ReadCodedIndex(tilde, ref p, typeDefOrRefSize);
                int fieldList = ReadIndex(tilde, ref p, fieldIdxSize);
                int methodList = ReadIndex(tilde, ref p, methodIdxSize);
                typeDefRows.Add((flags, nameIdx, nsIdx, extendsIdx, fieldList, methodList));
            }

            // --- Skip to Field table (skip table 0x03 InterfaceImpl if present) ---
            int fieldTableStart = p;
            for (int t = typeDefTable + 1; t < fieldTable; t++)
            {
                if ((validTables & (1L << t)) != 0)
                {
                    int skipSize = GetTableRowSize(t, rowCounts, stringIdxSize, wideBlobs, wideGuids, validTables);
                    fieldTableStart += skipSize * rowCounts[t];
                }
            }

            // --- Pass 2: read Field rows ---
            var fieldRows = new List<(ushort flags, int nameIdx, int sigIdx)>();
            int fp = fieldTableStart;
            for (int i = 0; i < rowCounts[fieldTable] && fp + fieldRowSize <= tilde.Length; i++)
            {
                ushort fflags = BitConverter.ToUInt16(tilde, fp); fp += 2;
                int fnameIdx = ReadIndex(tilde, ref fp, stringIdxSize);
                int fsigIdx = ReadIndex(tilde, ref fp, blobIdxSize);
                fieldRows.Add((fflags, fnameIdx, fsigIdx));
            }

            // --- Skip to MethodDef table ---
            int methodTableStart = fp;
            for (int t = fieldTable + 1; t < methodDefTable; t++)
            {
                if ((validTables & (1L << t)) != 0)
                {
                    int skipSize = GetTableRowSize(t, rowCounts, stringIdxSize, wideBlobs, wideGuids, validTables);
                    methodTableStart += skipSize * rowCounts[t];
                }
            }

            // --- Pass 3: read MethodDef rows ---
            var methodRows = new List<(uint rva, ushort implFlags, ushort flags, int nameIdx, int sigIdx, int paramList)>();
            int mp = methodTableStart;
            for (int i = 0; i < rowCounts[methodDefTable] && mp + methodDefRowSize <= tilde.Length; i++)
            {
                uint rva = BitConverter.ToUInt32(tilde, mp); mp += 4;
                ushort implFlags = BitConverter.ToUInt16(tilde, mp); mp += 2;
                ushort mflags = BitConverter.ToUInt16(tilde, mp); mp += 2;
                int mnameIdx = ReadIndex(tilde, ref mp, stringIdxSize);
                int msigIdx = ReadIndex(tilde, ref mp, blobIdxSize);
                int mparamList = ReadIndex(tilde, ref mp, paramIdxSize);
                methodRows.Add((rva, implFlags, mflags, mnameIdx, msigIdx, mparamList));
            }

            // --- Skip to Param table ---
            int paramTableStart = mp;
            for (int t = methodDefTable + 1; t < paramTable; t++)
            {
                if ((validTables & (1L << t)) != 0)
                {
                    int skipSize = GetTableRowSize(t, rowCounts, stringIdxSize, wideBlobs, wideGuids, validTables);
                    paramTableStart += skipSize * rowCounts[t];
                }
            }

            // --- Pass 4: read Param rows ---
            var paramRows = new List<(ushort flags, ushort sequence, int nameIdx)>();
            int pp = paramTableStart;
            for (int i = 0; i < rowCounts[paramTable] && pp + paramRowSize <= tilde.Length; i++)
            {
                ushort pflags = BitConverter.ToUInt16(tilde, pp); pp += 2;
                ushort psequence = BitConverter.ToUInt16(tilde, pp); pp += 2;
                int pnameIdx = ReadIndex(tilde, ref pp, stringIdxSize);
                paramRows.Add((pflags, psequence, pnameIdx));
            }

            // --- Build class info with resolved types ---
            for (int i = 0; i < typeDefRows.Count; i++)
            {
                var td = typeDefRows[i];
                string className = ReadString(strings, td.nameIdx);
                string namespaceName = ReadString(strings, td.nsIdx);

                if (string.IsNullOrEmpty(className) || className == "<Module>")
                    continue;

                var cls = new MonoClassInfo
                {
                    Name = className,
                    Namespace = namespaceName ?? "",
                    Flags = td.flags
                };

                // Resolve fields
                int fieldStart = td.fieldList - 1; // 1-based
                int fieldEnd = (i + 1 < typeDefRows.Count) ? typeDefRows[i + 1].fieldList - 1 : fieldRows.Count;
                for (int fi = fieldStart; fi < fieldEnd && fi < fieldRows.Count; fi++)
                {
                    var fr = fieldRows[fi];
                    string fieldType = (blob != null) ? DecodeFieldSig(blob, fr.sigIdx) : "object";
                    cls.Fields.Add(new MonoFieldInfo
                    {
                        Name = ReadString(strings, fr.nameIdx),
                        Flags = fr.flags,
                        TypeName = fieldType
                    });
                }

                // Resolve methods
                int methodStart = td.methodList - 1;
                int methodEnd = (i + 1 < typeDefRows.Count) ? typeDefRows[i + 1].methodList - 1 : methodRows.Count;
                for (int mi = methodStart; mi < methodEnd && mi < methodRows.Count; mi++)
                {
                    var mr = methodRows[mi];
                    string retType = "void";
                    string[] paramTypes = null;

                    if (blob != null)
                        (retType, paramTypes) = DecodeMethodSig(blob, mr.sigIdx);

                    int paramStart = mr.paramList - 1;
                    int paramEnd = (mi + 1 < methodRows.Count) ? methodRows[mi + 1].paramList - 1 : paramRows.Count;
                    int paramCount = 0;
                    var paramNames = new List<string>();
                    for (int pi = paramStart; pi < paramEnd && pi < paramRows.Count; pi++)
                    {
                        if (paramRows[pi].sequence > 0) // sequence 0 = return value
                        {
                            paramNames.Add(ReadString(strings, paramRows[pi].nameIdx));
                            paramCount++;
                        }
                    }

                    cls.Methods.Add(new MonoMethodInfo
                    {
                        Name = ReadString(strings, mr.nameIdx),
                        Flags = mr.flags,
                        ImplFlags = mr.implFlags,
                        ParameterCount = paramCount > 0 ? paramCount : (paramTypes != null ? paramTypes.Length : 0),
                        RVA = mr.rva,
                        ReturnType = retType,
                        ParameterTypes = paramTypes,
                        ParameterNames = paramNames.Count > 0 ? paramNames.ToArray() : null
                    });
                }

                info.Classes.Add(cls);
            }

            return info;
        }

        private static string DecodeFieldSig(byte[] blob, int index)
        {
            if (blob == null || index <= 0 || index >= blob.Length) return "object";
            int p = index;
            int len = ReadCompressedUint(blob, ref p);
            if (len <= 0 || p >= blob.Length) return "object";
            byte callingConv = blob[p++]; // should be 0x06 for FIELD
            if (callingConv != 0x06) return "object";
            return DecodeType(blob, ref p);
        }

        private static (string retType, string[] paramTypes) DecodeMethodSig(byte[] blob, int index)
        {
            if (blob == null || index <= 0 || index >= blob.Length) return ("void", null);
            int p = index;
            int len = ReadCompressedUint(blob, ref p);
            if (len <= 0 || p >= blob.Length) return ("void", null);

            byte callingConv = blob[p++];
            if ((callingConv & 0x10) != 0) // GENERIC
                ReadCompressedUint(blob, ref p); // generic param count

            int paramCount = ReadCompressedUint(blob, ref p);
            string retType = DecodeType(blob, ref p);

            var paramTypes = new string[paramCount];
            for (int i = 0; i < paramCount && p < blob.Length; i++)
                paramTypes[i] = DecodeType(blob, ref p);

            return (retType, paramTypes);
        }

        private static string DecodeType(byte[] blob, ref int p)
        {
            if (p >= blob.Length) return "object";
            byte type = blob[p++];
            switch (type)
            {
                case 0x01: return "void";
                case 0x02: return "bool";
                case 0x03: return "char";
                case 0x04: return "sbyte";
                case 0x05: return "byte";
                case 0x06: return "short";
                case 0x07: return "ushort";
                case 0x08: return "int";
                case 0x09: return "uint";
                case 0x0A: return "long";
                case 0x0B: return "ulong";
                case 0x0C: return "float";
                case 0x0D: return "double";
                case 0x0E: return "string";
                case 0x0F: // PTR
                    return DecodeType(blob, ref p) + "*";
                case 0x10: // BYREF
                    return "ref " + DecodeType(blob, ref p);
                case 0x11: // VALUETYPE
                case 0x12: // CLASS
                    ReadCompressedUint(blob, ref p); // TypeDefOrRef coded index
                    return type == 0x11 ? "/* valuetype */" : "/* class */";
                case 0x13: // VAR (generic type param)
                    int num = ReadCompressedUint(blob, ref p);
                    return $"T{num}";
                case 0x14: // ARRAY
                    return DecodeType(blob, ref p) + "[]";
                case 0x15: // GENERICINST
                    byte gtype = blob[p++]; // CLASS or VALUETYPE
                    ReadCompressedUint(blob, ref p); // TypeDefOrRef
                    int argCount = ReadCompressedUint(blob, ref p);
                    var args = new string[argCount];
                    for (int i = 0; i < argCount && p < blob.Length; i++)
                        args[i] = DecodeType(blob, ref p);
                    return "/* generic<" + string.Join(",", args) + "> */";
                case 0x16: return "TypedReference";
                case 0x18: return "IntPtr";
                case 0x19: return "UIntPtr";
                case 0x1C: return "object";
                case 0x1D: // SZARRAY
                    return DecodeType(blob, ref p) + "[]";
                case 0x1E: // MVAR (generic method param)
                    int mnum = ReadCompressedUint(blob, ref p);
                    return $"M{mnum}";
                case 0x45: // PINNED
                    return DecodeType(blob, ref p);
                default:
                    return "object";
            }
        }

        private static int ReadCompressedUint(byte[] data, ref int p)
        {
            if (p >= data.Length) return 0;
            byte b0 = data[p++];
            if ((b0 & 0x80) == 0) return b0;
            if ((b0 & 0xC0) == 0x80)
            {
                if (p >= data.Length) return 0;
                return ((b0 & 0x3F) << 8) | data[p++];
            }
            if (p + 2 >= data.Length) return 0;
            return ((b0 & 0x1F) << 24) | (data[p++] << 16) | (data[p++] << 8) | data[p++];
        }

        private static readonly int[] TypeDefOrRefTables = { 0x02, 0x01, 0x1B }; // TypeDef, TypeRef, TypeSpec

        private static int CalculateCodedIndexSize(int[] rowCounts, long validTables, int[] possibleTables)
        {
            int maxRows = 0;
            foreach (int t in possibleTables)
            {
                if (t < rowCounts.Length && rowCounts[t] > maxRows)
                    maxRows = rowCounts[t];
            }
            int tagBits = (int)Math.Ceiling(Math.Log(possibleTables.Length, 2));
            return maxRows < (1 << (16 - tagBits)) ? 2 : 4;
        }

        private static int CalculateTypeDefRowSize(int[] rowCounts, int stringIdxSize, long validTables)
        {
            int methodIdxSize = rowCounts[0x06] > 0xFFFF ? 4 : 2;
            int fieldIdxSize = rowCounts[0x04] > 0xFFFF ? 4 : 2;
            int typeDefOrRefSize = CalculateCodedIndexSize(rowCounts, validTables, TypeDefOrRefTables);
            return 4 + stringIdxSize + stringIdxSize + typeDefOrRefSize + fieldIdxSize + methodIdxSize;
        }

        private static int CalculateMethodDefRowSize(int[] rowCounts, int stringIdxSize, long validTables)
        {
            int paramIdxSize = rowCounts[0x08] > 0xFFFF ? 4 : 2;
            return 4 + 2 + 2 + stringIdxSize + 4 + paramIdxSize; // RVA(4) + ImplFlags(2) + Flags(2) + Name + Signature(4) + ParamList
        }

        private static int CalculateFieldRowSize(int[] rowCounts, int stringIdxSize, long validTables)
        {
            return 2 + stringIdxSize + 4; // Flags(2) + Name + Signature(blob index, using 4 as max)
        }

        private static int GetTableRowSize(int tableId, int[] rowCounts, int stringIdxSize, bool wideBlobs, bool wideGuids, long validTables)
        {
            // Simplified: return estimated row size for common tables
            // This is a rough approximation for skipping tables
            int blobIdxSize = wideBlobs ? 4 : 2;
            int guidIdxSize = wideGuids ? 4 : 2;

            switch (tableId)
            {
                case 0x00: return 2 + guidIdxSize; // Module
                case 0x01: return 4 + stringIdxSize + stringIdxSize + guidIdxSize + blobIdxSize; // TypeRef
                default: return 16; // Conservative default
            }
        }

        private static int ReadIndex(byte[] data, ref int p, int size)
        {
            if (size == 4)
            {
                int val = BitConverter.ToInt32(data, p);
                p += 4;
                return val;
            }
            else
            {
                int val = BitConverter.ToUInt16(data, p);
                p += 2;
                return val;
            }
        }

        private static int ReadCodedIndex(byte[] data, ref int p, int size)
        {
            return ReadIndex(data, ref p, size);
        }

        private static string ReadString(byte[] heap, int index)
        {
            if (index < 0 || index >= heap.Length) return "";
            int end = index;
            while (end < heap.Length && heap[end] != 0) end++;
            return Encoding.UTF8.GetString(heap, index, end - index);
        }

        private static int RvaToFileOffset(byte[] pe, int peOffset, uint rva)
        {
            ushort numSections = BitConverter.ToUInt16(pe, peOffset + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(pe, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + sizeOfOptHdr;

            for (int i = 0; i < numSections; i++)
            {
                int off = sectionTableOffset + i * 40;
                if (off + 40 > pe.Length) break;

                uint secVA = BitConverter.ToUInt32(pe, off + 12);
                uint secRawSize = BitConverter.ToUInt32(pe, off + 16);
                uint secRawOff = BitConverter.ToUInt32(pe, off + 20);
                uint secVSize = BitConverter.ToUInt32(pe, off + 8);

                if (rva >= secVA && rva < secVA + Math.Max(secRawSize, secVSize))
                {
                    return (int)(secRawOff + (rva - secVA));
                }
            }
            return -1;
        }

        public static string GenerateSdk(MonoSdkInfo info)
        {
            var sb = new StringBuilder();

            sb.AppendLine("// KsDumper - Mono SDK (from .NET metadata)");
            sb.AppendLine($"// Assembly: {info.AssemblyName}");
            sb.AppendLine($"// Classes: {info.Classes.Count}");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            // Group by namespace
            var grouped = new Dictionary<string, List<MonoClassInfo>>();
            foreach (var cls in info.Classes)
            {
                string ns = string.IsNullOrEmpty(cls.Namespace) ? "<global>" : cls.Namespace;
                if (!grouped.ContainsKey(ns))
                    grouped[ns] = new List<MonoClassInfo>();
                grouped[ns].Add(cls);
            }

            foreach (var kvp in grouped)
            {
                sb.AppendLine($"namespace {EscapeName(kvp.Key)}");
                sb.AppendLine("{");

                foreach (var cls in kvp.Value)
                {
                    string access = GetTypeAccess(cls.Flags);
                    string typeKind = (cls.Flags & 0x20) != 0 ? "interface" : "class";

                    sb.AppendLine($"    // Flags: 0x{cls.Flags:X8}");
                    sb.AppendLine($"    {access} {typeKind} {EscapeName(cls.Name)}");
                    sb.AppendLine("    {");

                    foreach (var field in cls.Fields)
                    {
                        string fAccess = GetFieldAccess(field.Flags);
                        bool isStatic = (field.Flags & 0x10) != 0;
                        string staticStr = isStatic ? "static " : "";
                        string fieldType = field.TypeName ?? "object";
                        sb.AppendLine($"        {fAccess} {staticStr}{fieldType} {EscapeName(field.Name)}; // 0x{field.Flags:X4}");
                    }

                    foreach (var method in cls.Methods)
                    {
                        string mAccess = GetMethodAccess(method.Flags);
                        bool isStatic = (method.Flags & 0x10) != 0;
                        bool isVirtual = (method.Flags & 0x40) != 0;
                        string modifiers = "";
                        if (isStatic) modifiers += "static ";
                        if (isVirtual) modifiers += "virtual ";
                        string retType = method.ReturnType ?? "void";
                        string paramSig = BuildParamSignature(method);
                        sb.AppendLine($"        {mAccess} {modifiers}{retType} {EscapeName(method.Name)}({paramSig}); // RVA: 0x{method.RVA:X8}");
                    }

                    sb.AppendLine("    }");
                    sb.AppendLine();
                }

                sb.AppendLine("}");
                sb.AppendLine();
            }

            return sb.ToString();
        }

        public static void Save(string path, string sdkText, MonoSdkInfo info)
        {
            File.WriteAllText(path, sdkText, Encoding.UTF8);
        }

        private static string GetTypeAccess(uint flags)
        {
            uint visibility = flags & 0x07;
            switch (visibility)
            {
                case 0x01: return "public";
                case 0x02: return "internal";
                case 0x03: return "internal"; // nested public
                default: return "internal";
            }
        }

        private static string GetFieldAccess(ushort flags)
        {
            uint access = (uint)(flags & 0x07);
            switch (access)
            {
                case 0x01: return "private";
                case 0x02: return "private"; // famandassem
                case 0x03: return "protected";
                case 0x04: return "internal";
                case 0x05: return "protected internal";
                case 0x06: return "public";
                default: return "private";
            }
        }

        private static string GetMethodAccess(ushort flags)
        {
            return GetFieldAccess(flags);
        }

        private static readonly HashSet<string> CSharpKeywords = new HashSet<string>
        {
            "abstract", "as", "base", "bool", "break", "byte", "case", "catch",
            "char", "checked", "class", "const", "continue", "decimal", "default",
            "delegate", "do", "double", "else", "enum", "event", "explicit",
            "extern", "false", "finally", "fixed", "float", "for", "foreach",
            "goto", "if", "implicit", "in", "int", "interface", "internal",
            "is", "lock", "long", "namespace", "new", "null", "object",
            "operator", "out", "override", "params", "private", "protected",
            "public", "readonly", "ref", "return", "sbyte", "sealed", "short",
            "sizeof", "stackalloc", "static", "string", "struct", "switch",
            "this", "throw", "true", "try", "typeof", "uint", "ulong",
            "unchecked", "unsafe", "ushort", "using", "virtual", "void", "while"
        };

        private static string BuildParamSignature(MonoMethodInfo method)
        {
            if (method.ParameterCount == 0 && (method.ParameterTypes == null || method.ParameterTypes.Length == 0))
                return "";

            var parts = new List<string>();
            int count = method.ParameterTypes != null ? method.ParameterTypes.Length : method.ParameterCount;
            for (int i = 0; i < count; i++)
            {
                string type = (method.ParameterTypes != null && i < method.ParameterTypes.Length) ? method.ParameterTypes[i] : "object";
                string name = (method.ParameterNames != null && i < method.ParameterNames.Length && !string.IsNullOrEmpty(method.ParameterNames[i]))
                    ? method.ParameterNames[i] : $"arg{i}";
                parts.Add($"{type} {name}");
            }
            return string.Join(", ", parts);
        }

        private static string EscapeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_empty";
            if (CSharpKeywords.Contains(name)) return "@" + name;
            // Sanitize invalid chars
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                if (char.IsLetterOrDigit(c) || c == '_')
                    sb.Append(c);
                else
                    sb.Append('_');
            }
            string result = sb.ToString();
            if (result.Length > 0 && char.IsDigit(result[0]))
                result = "_" + result;
            return result;
        }
    }
}
