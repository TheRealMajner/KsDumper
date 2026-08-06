using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppMetadataUsageParser
    {
        public enum UsageType : int
        {
            TypeInfo = 1,
            Il2CppType = 2,
            MethodDef = 3,
            FieldInfo = 4,
            StringLiteral = 5,
            MethodRef = 6,
        }

        public class MetadataUsageEntry
        {
            public int UsageIndex;
            public UsageType Type;
            public int SourceIndex;
            public ulong RuntimeAddress;
            public string ResolvedName;
        }

        public class MetadataUsageList
        {
            public int Start;
            public int Count;
        }

        public class UsageParseResult
        {
            public List<MetadataUsageEntry> Entries = new List<MetadataUsageEntry>();
            public Dictionary<UsageType, int> CountByType = new Dictionary<UsageType, int>();
            public int TotalPairs;
            public int TotalLists;
            public int Resolved;
        }

        public static UsageParseResult ParseFromMetadata(
            Il2CppMetadataSnapshot snapshot,
            IMemoryReader driver = null, int pid = 0,
            ulong gaBase = 0, uint gaSize = 0)
        {
            var result = new UsageParseResult();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            // MetadataUsageLists: array of { int start; int count; }
            int usageListOffset = header.MetadataUsageListsOffset;
            int usageListSize = header.MetadataUsageListsSize;
            // MetadataUsagePairs: array of { uint32 destinationIndex; uint32 encodedSourceIndex; }
            int usagePairOffset = header.MetadataUsagePairsOffset;
            int usagePairSize = header.MetadataUsagePairsSize;

            if (usageListOffset <= 0 || usageListSize <= 0) return result;
            if (usagePairOffset <= 0 || usagePairSize <= 0) return result;
            if (usageListOffset + usageListSize > metadata.Length) return result;
            if (usagePairOffset + usagePairSize > metadata.Length) return result;

            // Build type name lookup
            string[] typeNames = BuildTypeNames(snapshot);
            string[] methodNames = BuildMethodNames(snapshot, typeNames);

            // Parse usage lists (8 bytes each: int start, int count)
            int listCount = usageListSize / 8;
            result.TotalLists = listCount;

            var usageLists = new List<MetadataUsageList>();
            for (int i = 0; i < listCount; i++)
            {
                int off = usageListOffset + i * 8;
                if (off + 8 > metadata.Length) break;
                int start = BitConverter.ToInt32(metadata, off);
                int count = BitConverter.ToInt32(metadata, off + 4);
                usageLists.Add(new MetadataUsageList { Start = start, Count = count });
            }

            // Parse usage pairs (8 bytes each: uint32 destinationIndex, uint32 encodedSourceIndex)
            int pairCount = usagePairSize / 8;
            result.TotalPairs = pairCount;

            for (int i = 0; i < pairCount; i++)
            {
                int off = usagePairOffset + i * 8;
                if (off + 8 > metadata.Length) break;

                uint destIndex = BitConverter.ToUInt32(metadata, off);
                uint encodedSource = BitConverter.ToUInt32(metadata, off + 4);

                // Decode the encoded source index
                // Upper 3 bits = usage type, lower 29 bits = source index
                int usageType = (int)(encodedSource >> 29);
                int sourceIndex = (int)(encodedSource & 0x1FFFFFFF);

                if (usageType < 1 || usageType > 6) continue;

                var entry = new MetadataUsageEntry
                {
                    UsageIndex = (int)destIndex,
                    Type = (UsageType)usageType,
                    SourceIndex = sourceIndex
                };

                // Resolve name based on type
                switch (entry.Type)
                {
                    case UsageType.TypeInfo:
                    case UsageType.Il2CppType:
                        if (sourceIndex >= 0 && sourceIndex < typeNames.Length)
                            entry.ResolvedName = typeNames[sourceIndex];
                        else
                            entry.ResolvedName = $"type_{sourceIndex}";
                        break;

                    case UsageType.MethodDef:
                    case UsageType.MethodRef:
                        if (sourceIndex >= 0 && sourceIndex < methodNames.Length)
                            entry.ResolvedName = methodNames[sourceIndex];
                        else
                            entry.ResolvedName = $"method_{sourceIndex}";
                        break;

                    case UsageType.FieldInfo:
                        if (sourceIndex >= 0 && sourceIndex < snapshot.Fields.Length)
                        {
                            var fd = snapshot.Fields[sourceIndex];
                            string fName = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)fd.NameIndex);
                            entry.ResolvedName = fName;
                        }
                        else
                        {
                            entry.ResolvedName = $"field_{sourceIndex}";
                        }
                        break;

                    case UsageType.StringLiteral:
                        entry.ResolvedName = ReadStringLiteral(metadata, header, sourceIndex);
                        break;
                }

                result.Entries.Add(entry);

                if (!result.CountByType.ContainsKey(entry.Type))
                    result.CountByType[entry.Type] = 0;
                result.CountByType[entry.Type]++;
            }

            // If driver available, try to resolve runtime addresses
            if (driver != null && gaBase != 0)
            {
                ResolveRuntimeAddresses(driver, pid, gaBase, gaSize, snapshot, result);
            }

            return result;
        }

        private static void ResolveRuntimeAddresses(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot,
            UsageParseResult result)
        {
            // Il2CppMetadataRegistration contains s_Il2CppMetadataUsages pointer array
            // Each entry in the runtime array corresponds to a usage destination index
            // Find the array by scanning for a pointer to a large array in .data
            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            ulong gaEnd = gaBase + gaSize;
            int maxDest = result.Entries.Count > 0 ? result.Entries.Max(e => e.UsageIndex) + 1 : 0;
            if (maxDest <= 0) return;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                if (sName != ".data" && sName != ".rdata") continue;

                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                ulong secStart = gaBase + vAddr;
                int readSize = (int)Math.Min(vSize, 0x2000000);

                byte[] data = ReadMemory(driver, pid, secStart, readSize);
                if (data == null) continue;

                // Scan for pointer to array of pointers (metadata usage table)
                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    ulong arrayPtr = BitConverter.ToUInt64(data, i);
                    if (arrayPtr < gaBase || arrayPtr >= gaEnd) continue;

                    // Read first few entries to validate
                    int testCount = Math.Min(maxDest, 16);
                    byte[] testData = ReadMemory(driver, pid, arrayPtr, testCount * 8);
                    if (testData == null) continue;

                    int validPtrs = 0;
                    for (int t = 0; t < testCount; t++)
                    {
                        ulong ptr = BitConverter.ToUInt64(testData, t * 8);
                        if (ptr == 0 || (ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF))
                            validPtrs++;
                    }

                    if (validPtrs < testCount * 3 / 4) continue;

                    // This looks like the usage table — read all entries
                    byte[] fullTable = ReadMemory(driver, pid, arrayPtr, maxDest * 8);
                    if (fullTable == null) continue;

                    foreach (var entry in result.Entries)
                    {
                        if (entry.UsageIndex * 8 + 8 > fullTable.Length) continue;
                        ulong addr = BitConverter.ToUInt64(fullTable, entry.UsageIndex * 8);
                        if (addr != 0)
                        {
                            entry.RuntimeAddress = addr;
                            result.Resolved++;
                        }
                    }

                    return; // Found and resolved
                }
            }
        }

        public static string GenerateReport(UsageParseResult result, UsageType? filterType = null, string search = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Metadata Usage Table");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Total usage pairs: {result.TotalPairs}");
            sb.AppendLine($"// Total usage lists: {result.TotalLists}");
            sb.AppendLine($"// Runtime resolved: {result.Resolved}");
            sb.AppendLine();

            sb.AppendLine("// Usage type breakdown:");
            foreach (var kvp in result.CountByType.OrderBy(k => (int)k.Key))
                sb.AppendLine($"//   {kvp.Key}: {kvp.Value}");
            sb.AppendLine();

            var entries = result.Entries.AsEnumerable();
            if (filterType.HasValue)
                entries = entries.Where(e => e.Type == filterType.Value);
            if (!string.IsNullOrEmpty(search))
                entries = entries.Where(e =>
                    e.ResolvedName != null && e.ResolvedName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0);

            int shown = 0;
            foreach (var entry in entries.OrderBy(e => e.Type).ThenBy(e => e.UsageIndex))
            {
                if (shown >= 2000) break;

                string addr = entry.RuntimeAddress != 0 ? $" -> 0x{entry.RuntimeAddress:X}" : "";
                string display = entry.ResolvedName ?? "";
                if (display.Length > 150)
                    display = display.Substring(0, 150) + "...";

                sb.AppendLine($"  [{entry.UsageIndex,6}] {entry.Type,-14} src:{entry.SourceIndex,6} {display}{addr}");
                shown++;
            }

            return sb.ToString();
        }

        private static string[] BuildTypeNames(Il2CppMetadataSnapshot snapshot)
        {
            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;
            string[] names = new string[snapshot.TypeDefinitions.Length];
            for (int i = 0; i < snapshot.TypeDefinitions.Length; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                string name = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);
                string ns = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);
                names[i] = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
            }
            return names;
        }

        private static string[] BuildMethodNames(Il2CppMetadataSnapshot snapshot, string[] typeNames)
        {
            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;
            string[] names = new string[snapshot.Methods.Length];
            for (int i = 0; i < snapshot.Methods.Length; i++)
            {
                var md = snapshot.Methods[i];
                string mName = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)md.NameIndex);

                // Find declaring type
                string typeName = "";
                for (int t = 0; t < snapshot.TypeDefinitions.Length; t++)
                {
                    var td = snapshot.TypeDefinitions[t];
                    if (i >= td.MethodStart && i < td.MethodStart + td.MethodCount)
                    {
                        typeName = typeNames[t];
                        break;
                    }
                }

                names[i] = string.IsNullOrEmpty(typeName) ? mName : $"{typeName}.{mName}";
            }
            return names;
        }

        private static string ReadStringLiteral(byte[] metadata, Il2CppMetadataHeader header, int index)
        {
            int litOffset = header.StringLiteralOffset;
            int litDataOffset = header.StringLiteralDataOffset;

            int entryOff = litOffset + index * 8;
            if (entryOff + 8 > metadata.Length) return $"string_{index}";

            int len = BitConverter.ToInt32(metadata, entryOff);
            int dataIdx = BitConverter.ToInt32(metadata, entryOff + 4);

            if (len <= 0 || len > 0x10000 || litDataOffset + dataIdx + len > metadata.Length)
                return $"string_{index}";

            try
            {
                string val = Encoding.UTF8.GetString(metadata, litDataOffset + dataIdx, Math.Min(len, 200));
                return val;
            }
            catch
            {
                return $"<binary:{len}bytes>";
            }
        }

        private static byte[] ReadMemory(IMemoryReader driver, int pid, ulong address, int size)
        {
            byte[] buf = new byte[size];
            GCHandle handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                if (!driver.CopyVirtualMemory(pid, (IntPtr)(long)address, handle.AddrOfPinnedObject(), size))
                    return null;
                return buf;
            }
            finally { handle.Free(); }
        }
    }
}
