using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

using static KsDumperClient.PE.NativePEStructs;

namespace KsDumperClient.PE
{
    /// <summary>
    /// Comprehensive IAT/Import table rebuilder. Handles:
    /// - Import-by-name and import-by-ordinal
    /// - OriginalFirstThunk (INT) validation against FirstThunk (IAT)
    /// - Delay-load imports (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
    /// - Bound import recovery
    /// - Forwarded import detection
    /// - API Set schema resolution (api-ms-win-core-* -> real DLL)
    /// - Cross-section import descriptors
    /// - Duplicate deduplication and DLL name normalization
    /// </summary>
    public class ImportRebuilder
    {
        private const int IMPORT_DESCRIPTOR_SIZE = 20;
        private const int DELAY_IMPORT_DESCRIPTOR_SIZE = 32;

        public struct RebuildReport
        {
            public int TotalImports;
            public int ResolvedByName;
            public int ResolvedByOrdinal;
            public int ResolvedFromINT;
            public int ResolvedFromDelayLoad;
            public int Unresolved;
            public int DllsReferenced;
            public int Forwarders;
            public int ApiSetsResolved;
            public List<string> Warnings;

            public string Summary()
            {
                var sb = new StringBuilder();
                sb.AppendLine($"Import Rebuild Report:");
                sb.AppendLine($"  Total imports: {TotalImports}");
                sb.AppendLine($"  Resolved by name: {ResolvedByName}");
                sb.AppendLine($"  Resolved by ordinal: {ResolvedByOrdinal}");
                sb.AppendLine($"  Resolved from INT: {ResolvedFromINT}");
                sb.AppendLine($"  Resolved from delay-load: {ResolvedFromDelayLoad}");
                sb.AppendLine($"  Unresolved: {Unresolved}");
                sb.AppendLine($"  DLLs referenced: {DllsReferenced}");
                sb.AppendLine($"  Forwarders: {Forwarders}");
                sb.AppendLine($"  API Sets resolved: {ApiSetsResolved}");
                if (Warnings.Count > 0)
                {
                    sb.AppendLine($"  Warnings ({Warnings.Count}):");
                    foreach (var w in Warnings)
                        sb.AppendLine($"    - {w}");
                }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Rebuild the import table of a dumped PE file using a resolved export map.
        /// </summary>
        public bool RebuildImports(PEFile peFile, Dictionary<ulong, (string dllName, string funcName)> exportMap, ulong moduleBaseAddress)
        {
            var report = DoRebuild(peFile, exportMap, moduleBaseAddress);
            return report.TotalImports > 0 && report.Unresolved < report.TotalImports;
        }

        /// <summary>
        /// Rebuild imports and return a detailed report of what was resolved.
        /// </summary>
        public RebuildReport DoRebuild(PEFile peFile, Dictionary<ulong, (string dllName, string funcName)> exportMap, ulong moduleBaseAddress)
        {
            var report = new RebuildReport { Warnings = new List<string>() };
            bool is64 = peFile.Type == PEFile.PEType.PE64;
            int thunkSize = is64 ? 8 : 4;

            // Phase 1: Collect all imports from all sources
            var allImports = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            var ordinalImports = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);

            // 1a: Standard imports from IMAGE_DIRECTORY_ENTRY_IMPORT
            CollectStandardImports(peFile, exportMap, is64, thunkSize, allImports, ordinalImports, report);

            // 1b: Delay-load imports from IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT
            CollectDelayLoadImports(peFile, exportMap, is64, thunkSize, allImports, report);

            // 1c: Bound imports from IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (recovery)
            CollectBoundImports(peFile, allImports, report);

            if (allImports.Count == 0 && ordinalImports.Count == 0)
            {
                report.Warnings.Add("No imports found from any source");
                return report;
            }

            // Phase 2: Normalize DLL names and resolve API sets
            var normalizedImports = NormalizeAndResolveApiSets(allImports, report);
            var normalizedOrdinals = NormalizeOrdinals(ordinalImports, report);

            // Phase 3: Build new import table
            uint importDirRVA = GetImportDirRVA(peFile);
            PESection importSection = importDirRVA != 0 ? FindSectionByRVA(peFile, importDirRVA) : null;

            // If no existing import section, use .rdata or first writable section
            if (importSection == null)
                importSection = FindBestSectionForImports(peFile);

            if (importSection == null)
            {
                report.Warnings.Add("No suitable section for import table");
                return report;
            }

            uint baseRVA = importSection.Header.VirtualAddress + (uint)(importSection.Content?.Length ?? 0);

            // Align base RVA to pointer alignment
            uint alignment = is64 ? 8u : 4u;
            baseRVA = ((baseRVA + alignment - 1) / alignment) * alignment;

            byte[] newImportData = BuildImportTable(normalizedImports, normalizedOrdinals, is64, baseRVA,
                out uint newImportDirRVA, out uint newIatRVA, out uint newIatSize, report);

            if (newImportData == null || newImportData.Length == 0)
            {
                report.Warnings.Add("Failed to build import table");
                return report;
            }

            AppendToSection(importSection, newImportData);

            // Ensure section has proper characteristics
            importSection.Header.Characteristics |= DataSectionFlags.MemoryRead | DataSectionFlags.MemoryWrite | DataSectionFlags.ContentInitializedData;

            // Update VirtualSize to cover new data
            uint newSectionEnd = importSection.Header.VirtualAddress + (uint)importSection.Content.Length;
            if (newSectionEnd > importSection.Header.VirtualAddress + importSection.Header.VirtualSize)
                importSection.Header.VirtualSize = (uint)importSection.Content.Length;

            int totalDescriptors = normalizedImports.Count + normalizedOrdinals.Count + 1; // +1 for null terminator
            SetImportDirRVA(peFile, newImportDirRVA, (uint)(totalDescriptors * IMPORT_DESCRIPTOR_SIZE));
            SetIatDirRVA(peFile, newIatRVA, newIatSize);

            // Clear bound import directory (invalid after rebuild)
            SetBoundImportDirRVA(peFile, 0, 0);

            report.TotalImports = normalizedImports.Values.Sum(v => v.Count) + normalizedOrdinals.Values.Sum(v => v.Count);
            report.DllsReferenced = normalizedImports.Count + normalizedOrdinals.Count;
            report.ResolvedByName = normalizedImports.Values.Sum(v => v.Count);
            report.ResolvedByOrdinal = normalizedOrdinals.Values.Sum(v => v.Count);

            return report;
        }

        // ---- Phase 1: Import Collection ----

        private void CollectStandardImports(PEFile peFile, Dictionary<ulong, (string dllName, string funcName)> exportMap,
            bool is64, int thunkSize, Dictionary<string, HashSet<string>> allImports,
            Dictionary<string, HashSet<int>> ordinalImports, RebuildReport report)
        {
            uint importDirRVA = GetImportDirRVA(peFile);
            uint importDirSize = GetImportDirSize(peFile);
            if (importDirRVA == 0 || importDirSize == 0) return;

            PESection importSection = FindSectionByRVA(peFile, importDirRVA);
            if (importSection == null || importSection.Content == null) return;

            uint sectionOffset = importDirRVA - importSection.Header.VirtualAddress;
            var descriptors = ParseImportDescriptors(importSection.Content, sectionOffset, importDirSize);

            foreach (var desc in descriptors)
            {
                // Read DLL name
                string dllName = ReadStringFromRVA(peFile, desc.NameRVA);
                if (string.IsNullOrEmpty(dllName)) continue;

                // Try OriginalFirstThunk (INT) first for import-by-name hints
                uint intRVA = desc.OriginalFirstThunkRVA;
                if (intRVA != 0)
                {
                    CollectFromThunkArray(peFile, intRVA, exportMap, dllName, allImports, ordinalImports, report, true);
                }

                // Always process FirstThunk (IAT) for resolved addresses
                if (desc.FirstThunkRVA != 0)
                {
                    CollectFromThunkArray(peFile, desc.FirstThunkRVA, exportMap, dllName, allImports, ordinalImports, report, false);
                }
            }
        }

        private void CollectFromThunkArray(PEFile peFile, uint thunkRVA,
            Dictionary<ulong, (string dllName, string funcName)> exportMap, string dllName,
            Dictionary<string, HashSet<string>> allImports, Dictionary<string, HashSet<int>> ordinalImports,
            RebuildReport report, bool isINT)
        {
            bool is64 = peFile.Type == PEFile.PEType.PE64;
            int thunkSize = is64 ? 8 : 4;

            PESection section = FindSectionByRVA(peFile, thunkRVA);
            if (section == null || section.Content == null) return;

            uint offset = thunkRVA - section.Header.VirtualAddress;

            for (int t = 0; ; t++)
            {
                int pos = (int)(offset + t * thunkSize);
                if (pos + thunkSize > section.Content.Length) break;

                ulong thunkValue = is64
                    ? BitConverter.ToUInt64(section.Content, pos)
                    : BitConverter.ToUInt32(section.Content, pos);

                if (thunkValue == 0) break;

                // Check for ordinal import
                bool isOrdinal = is64 ? (thunkValue & 0x8000000000000000) != 0 : (thunkValue & 0x80000000) != 0;

                if (isOrdinal)
                {
                    int ordinal = is64 ? (int)(thunkValue & 0xFFFF) : (int)(thunkValue & 0xFFFF);
                    if (!ordinalImports.ContainsKey(dllName))
                        ordinalImports[dllName] = new HashSet<int>();
                    ordinalImports[dllName].Add(ordinal);
                    report.ResolvedByOrdinal++;
                }
                else if (isINT)
                {
                    // INT contains import-by-name RVA - read the hint/name
                    string funcName = ReadHintNameFromRVA(peFile, (uint)thunkValue);
                    if (!string.IsNullOrEmpty(funcName))
                    {
                        if (!allImports.ContainsKey(dllName))
                            allImports[dllName] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        if (allImports[dllName].Add(funcName))
                            report.ResolvedFromINT++;
                    }
                }
                else
                {
                    // IAT contains resolved address - look up in export map
                    if (exportMap.TryGetValue(thunkValue, out var export))
                    {
                        string resolvedDll = !string.IsNullOrEmpty(export.dllName) ? export.dllName : dllName;

                        // Check for forwarded imports
                        if (!string.Equals(resolvedDll, dllName, StringComparison.OrdinalIgnoreCase))
                        {
                            report.Forwarders++;
                        }

                        if (!allImports.ContainsKey(resolvedDll))
                            allImports[resolvedDll] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        allImports[resolvedDll].Add(export.funcName);
                        report.ResolvedByName++;
                    }
                    else if (thunkValue != 0)
                    {
                        report.Unresolved++;
                    }
                }
            }
        }

        private void CollectDelayLoadImports(PEFile peFile, Dictionary<ulong, (string dllName, string funcName)> exportMap,
            bool is64, int thunkSize, Dictionary<string, HashSet<string>> allImports, RebuildReport report)
        {
            uint delayDirRVA = GetDelayImportDirRVA(peFile);
            uint delayDirSize = GetDelayImportDirSize(peFile);
            if (delayDirRVA == 0 || delayDirSize == 0) return;

            PESection section = FindSectionByRVA(peFile, delayDirRVA);
            if (section == null || section.Content == null) return;

            uint offset = delayDirRVA - section.Header.VirtualAddress;

            // Delay-load descriptor: 32 bytes (x64) or varies
            // Layout: Attributes(4), DllNameRVA(4/8), ModuleHandleRVA(4/8), IATRVA(4/8), INT_RVA(4/8), ...
            // Simplified: read DllNameRVA at offset 4, IAT at offset 12 (x86) or 20 (x64)

            while (offset + 32 <= section.Content.Length)
            {
                uint attributes = BitConverter.ToUInt32(section.Content, (int)offset);
                uint dllNameRVA = is64
                    ? (uint)BitConverter.ToInt64(section.Content, (int)offset + 8)
                    : BitConverter.ToUInt32(section.Content, (int)offset + 4);
                uint iatRVA = is64
                    ? (uint)BitConverter.ToInt64(section.Content, (int)offset + 24)
                    : BitConverter.ToUInt32(section.Content, (int)offset + 12);

                if (dllNameRVA == 0 && iatRVA == 0) break; // Null terminator

                string dllName = ReadStringFromRVA(peFile, dllNameRVA);
                if (!string.IsNullOrEmpty(dllName) && iatRVA != 0)
                {
                    // Read IAT entries for delay-loaded DLL
                    PESection iatSection = FindSectionByRVA(peFile, iatRVA);
                    if (iatSection != null && iatSection.Content != null)
                    {
                        uint iatOffset = iatRVA - iatSection.Header.VirtualAddress;
                        for (int t = 0; ; t++)
                        {
                            int pos = (int)(iatOffset + t * thunkSize);
                            if (pos + thunkSize > iatSection.Content.Length) break;

                            ulong thunkValue = is64
                                ? BitConverter.ToUInt64(iatSection.Content, pos)
                                : BitConverter.ToUInt32(iatSection.Content, pos);

                            if (thunkValue == 0) break;

                            if (exportMap.TryGetValue(thunkValue, out var export))
                            {
                                string resolvedDll = !string.IsNullOrEmpty(export.dllName) ? export.dllName : dllName;
                                if (!allImports.ContainsKey(resolvedDll))
                                    allImports[resolvedDll] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                                allImports[resolvedDll].Add(export.funcName);
                                report.ResolvedFromDelayLoad++;
                            }
                        }
                    }
                }

                offset += (uint)(is64 ? 32 : 20); // Advance to next descriptor
            }
        }

        private void CollectBoundImports(PEFile peFile, Dictionary<string, HashSet<string>> allImports, RebuildReport report)
        {
            uint boundDirRVA = GetBoundImportDirRVA(peFile);
            uint boundDirSize = GetBoundImportDirSize(peFile);
            if (boundDirRVA == 0 || boundDirSize == 0) return;

            PESection section = FindSectionByRVA(peFile, boundDirRVA);
            if (section == null || section.Content == null) return;

            uint offset = boundDirRVA - section.Header.VirtualAddress;

            // IMAGE_BOUND_IMPORT_DESCRIPTOR: TimeDateStamp(4), OffsetModuleName(2), NumberOfModuleForwarderRefs(2) = 8 bytes
            while (offset + 8 <= section.Content.Length)
            {
                uint timestamp = BitConverter.ToUInt32(section.Content, (int)offset);
                ushort nameOffset = BitConverter.ToUInt16(section.Content, (int)offset + 4);
                ushort forwarderCount = BitConverter.ToUInt16(section.Content, (int)offset + 6);

                if (timestamp == 0 && nameOffset == 0) break;

                // Read DLL name from bound import table
                int namePos = (int)(offset - (offset - sectionOffset(section, boundDirRVA)) + nameOffset);
                if (namePos >= 0 && namePos < section.Content.Length)
                {
                    string dllName = ReadAnsiString(section.Content, namePos);
                    if (!string.IsNullOrEmpty(dllName) && !allImports.ContainsKey(dllName))
                    {
                        allImports[dllName] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    }
                }

                offset += (uint)(8 + forwarderCount * 8); // Skip forwarder entries
            }
        }

        private uint sectionOffset(PESection section, uint rva)
        {
            return section.Header.VirtualAddress;
        }

        // ---- Phase 2: Normalization ----

        private static readonly Dictionary<string, string> ApiSetMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            { "api-ms-win-core-console-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-datetime-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-debug-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-errorhandling-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-file-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-file-l1-2-0", "kernel32.dll" },
            { "api-ms-win-core-file-l2-1-0", "kernel32.dll" },
            { "api-ms-win-core-handle-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-heap-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-interlocked-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-libraryloader-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-localization-l1-2-0", "kernel32.dll" },
            { "api-ms-win-core-memory-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-namedpipe-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-processenvironment-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-processthreads-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-processthreads-l1-1-1", "kernel32.dll" },
            { "api-ms-win-core-profile-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-rtlsupport-l1-1-0", "ntdll.dll" },
            { "api-ms-win-core-string-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-synch-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-synch-l1-2-0", "kernel32.dll" },
            { "api-ms-win-core-sysinfo-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-timezone-l1-1-0", "kernel32.dll" },
            { "api-ms-win-core-util-l1-1-0", "kernel32.dll" },
            { "api-ms-win-crt-runtime-l1-1-0", "ucrtbase.dll" },
            { "api-ms-win-crt-heap-l1-1-0", "ucrtbase.dll" },
            { "api-ms-win-crt-math-l1-1-0", "ucrtbase.dll" },
            { "api-ms-win-crt-stdio-l1-1-0", "ucrtbase.dll" },
            { "api-ms-win-crt-string-l1-1-0", "ucrtbase.dll" },
            { "api-ms-win-crt-convert-l1-1-0", "ucrtbase.dll" },
            { "api-ms-win-eventing-provider-l1-1-0", "advapi32.dll" },
            { "api-ms-win-security-base-l1-1-0", "kernel32.dll" },
        };

        private Dictionary<string, HashSet<string>> NormalizeAndResolveApiSets(
            Dictionary<string, HashSet<string>> imports, RebuildReport report)
        {
            var result = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

            foreach (var kvp in imports)
            {
                string dllName = NormalizeDllName(kvp.Key);

                // Check API Set schema
                string baseName = Path.GetFileNameWithoutExtension(dllName).ToLowerInvariant();
                if (baseName.StartsWith("api-ms-win-") && ApiSetMap.TryGetValue(baseName, out string realDll))
                {
                    dllName = realDll;
                    report.ApiSetsResolved++;
                }

                if (!result.ContainsKey(dllName))
                    result[dllName] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var func in kvp.Value)
                    result[dllName].Add(func);
            }

            return result;
        }

        private Dictionary<string, HashSet<int>> NormalizeOrdinals(
            Dictionary<string, HashSet<int>> ordinals, RebuildReport report)
        {
            var result = new Dictionary<string, HashSet<int>>(StringComparer.OrdinalIgnoreCase);
            foreach (var kvp in ordinals)
            {
                string dllName = NormalizeDllName(kvp.Key);
                if (!result.ContainsKey(dllName))
                    result[dllName] = new HashSet<int>();
                foreach (var ord in kvp.Value)
                    result[dllName].Add(ord);
            }
            return result;
        }

        private string NormalizeDllName(string name)
        {
            if (string.IsNullOrEmpty(name)) return name;
            // Ensure .dll extension
            if (!name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                name += ".dll";
            // Normalize case for system DLLs
            string lower = name.ToLowerInvariant();
            string[] systemDlls = { "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
                "shell32.dll", "ole32.dll", "oleaut32.dll", "gdi32.dll", "ws2_32.dll",
                "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll", "msvcp140.dll",
                "combase.dll", "rpcrt4.dll", "sechost.dll", "bcryptprimitives.dll" };
            foreach (var sys in systemDlls)
            {
                if (lower == sys) return sys;
            }
            return name;
        }

        // ---- Phase 3: Build Import Table ----

        private byte[] BuildImportTable(Dictionary<string, HashSet<string>> importsByDll,
            Dictionary<string, HashSet<int>> ordinalImports, bool is64, uint baseRVA,
            out uint importDirRVA, out uint iatRVA, out uint iatSize, RebuildReport report)
        {
            int thunkSize = is64 ? 8 : 4;
            int totalDlls = importsByDll.Count + ordinalImports.Count;
            if (totalDlls == 0) { importDirRVA = 0; iatRVA = 0; iatSize = 0; return null; }

            using (var ms = new MemoryStream())
            using (var writer = new BinaryWriter(ms))
            {
                // Calculate total thunks
                int totalNameThunks = importsByDll.Values.Sum(v => v.Count);
                int totalOrdinalThunks = ordinalImports.Values.Sum(v => v.Count);
                int totalThunks = totalNameThunks + totalOrdinalThunks + totalDlls; // +1 null per DLL

                int importDirSize = (totalDlls + 1) * IMPORT_DESCRIPTOR_SIZE; // +1 null descriptor
                int iltStart = importDirSize;
                int iatStart = iltStart + totalThunks * thunkSize;
                int hintNameStart = iatStart + totalThunks * thunkSize;

                // Pre-calculate offsets
                var funcOffsets = new Dictionary<string, Dictionary<string, int>>(StringComparer.OrdinalIgnoreCase);
                var ordinalOffsets = new Dictionary<string, Dictionary<int, int>>(StringComparer.OrdinalIgnoreCase);
                var dllNameOffsets = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                int cur = hintNameStart;

                foreach (var kvp in importsByDll)
                {
                    funcOffsets[kvp.Key] = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                    foreach (var func in kvp.Value)
                    {
                        funcOffsets[kvp.Key][func] = cur;
                        int entryLen = 2 + Encoding.ASCII.GetByteCount(func) + 1;
                        if (entryLen % 2 != 0) entryLen++;
                        cur += entryLen;
                    }
                }

                int dllNameStart = cur;
                foreach (var dll in importsByDll.Keys.Concat(ordinalImports.Keys))
                {
                    if (!dllNameOffsets.ContainsKey(dll))
                    {
                        dllNameOffsets[dll] = cur;
                        cur += Encoding.ASCII.GetByteCount(dll) + 1;
                    }
                }

                // Write import descriptors
                int thunkAccum = 0;
                foreach (var kvp in importsByDll)
                {
                    int count = kvp.Value.Count;
                    uint thisIltRVA = baseRVA + (uint)(iltStart + thunkAccum * thunkSize);
                    uint thisIatRVA = baseRVA + (uint)(iatStart + thunkAccum * thunkSize);
                    uint thisNameRVA = baseRVA + (uint)dllNameOffsets[kvp.Key];

                    writer.Write(thisIltRVA);  // OriginalFirstThunk
                    writer.Write((uint)0);      // TimeDateStamp
                    writer.Write((uint)0);      // ForwarderChain
                    writer.Write(thisNameRVA);  // Name
                    writer.Write(thisIatRVA);   // FirstThunk
                    thunkAccum += count + 1;
                }

                // Ordinal import descriptors
                foreach (var kvp in ordinalImports)
                {
                    int count = kvp.Value.Count;
                    uint thisIltRVA = baseRVA + (uint)(iltStart + thunkAccum * thunkSize);
                    uint thisIatRVA = baseRVA + (uint)(iatStart + thunkAccum * thunkSize);
                    uint thisNameRVA = baseRVA + (uint)dllNameOffsets[kvp.Key];

                    writer.Write(thisIltRVA);
                    writer.Write((uint)0);
                    writer.Write((uint)0);
                    writer.Write(thisNameRVA);
                    writer.Write(thisIatRVA);
                    thunkAccum += count + 1;
                }

                // Null terminator descriptor
                writer.Write(new byte[IMPORT_DESCRIPTOR_SIZE]);

                // Write ILT arrays (import-by-name RVAs for named imports)
                foreach (var kvp in importsByDll)
                {
                    foreach (var func in kvp.Value)
                    {
                        uint hintNameRVA = baseRVA + (uint)funcOffsets[kvp.Key][func];
                        if (is64) writer.Write((ulong)hintNameRVA); else writer.Write(hintNameRVA);
                    }
                    if (is64) writer.Write((ulong)0); else writer.Write((uint)0); // null terminator
                }

                // Write ILT arrays for ordinal imports
                foreach (var kvp in ordinalImports)
                {
                    ulong ordinalFlag = is64 ? 0x8000000000000000UL : 0x80000000UL;
                    foreach (var ord in kvp.Value)
                    {
                        ulong val = ordinalFlag | (uint)(ord & 0xFFFF);
                        if (is64) writer.Write(val); else writer.Write((uint)val);
                    }
                    if (is64) writer.Write((ulong)0); else writer.Write((uint)0);
                }

                // Write IAT arrays (zeroed - OS fills on load)
                for (int i = 0; i < totalThunks; i++)
                {
                    if (is64) writer.Write((ulong)0); else writer.Write((uint)0);
                }

                // Write Hint/Name entries
                foreach (var kvp in importsByDll)
                {
                    foreach (var func in kvp.Value)
                    {
                        writer.Write((ushort)0); // Hint
                        writer.Write(Encoding.ASCII.GetBytes(func));
                        writer.Write((byte)0);
                        int written = 2 + Encoding.ASCII.GetByteCount(func) + 1;
                        if (written % 2 != 0) writer.Write((byte)0);
                    }
                }

                // Write DLL name strings
                foreach (var dll in dllNameOffsets.Keys)
                {
                    writer.Write(Encoding.ASCII.GetBytes(dll));
                    writer.Write((byte)0);
                }

                importDirRVA = baseRVA;
                iatRVA = baseRVA + (uint)iatStart;
                iatSize = (uint)(totalThunks * thunkSize);

                return ms.ToArray();
            }
        }

        // ---- Helpers ----

        private void AppendToSection(PESection section, byte[] data)
        {
            int oldLen = section.Content?.Length ?? 0;
            byte[] newContent = new byte[oldLen + data.Length];
            if (oldLen > 0) Array.Copy(section.Content, newContent, oldLen);
            Array.Copy(data, 0, newContent, oldLen, data.Length);
            section.Content = newContent;
            section.DataSize = newContent.Length;
        }

        private string ReadStringFromRVA(PEFile peFile, uint rva)
        {
            if (rva == 0) return null;
            PESection section = FindSectionByRVA(peFile, rva);
            if (section?.Content == null) return null;
            int offset = (int)(rva - section.Header.VirtualAddress);
            if (offset < 0 || offset >= section.Content.Length) return null;
            return ReadAnsiString(section.Content, offset);
        }

        private string ReadHintNameFromRVA(PEFile peFile, uint rva)
        {
            if (rva == 0) return null;
            PESection section = FindSectionByRVA(peFile, rva);
            if (section?.Content == null) return null;
            int offset = (int)(rva - section.Header.VirtualAddress);
            if (offset + 2 >= section.Content.Length) return null;
            // Skip 2-byte hint
            return ReadAnsiString(section.Content, offset + 2);
        }

        private PESection FindSectionByRVA(PEFile peFile, uint rva)
        {
            foreach (var s in peFile.Sections)
            {
                uint maxEnd = s.Header.VirtualAddress + Math.Max(s.Header.VirtualSize, s.Header.SizeOfRawData);
                if (rva >= s.Header.VirtualAddress && rva < maxEnd)
                    return s;
            }
            return null;
        }

        private PESection FindBestSectionForImports(PEFile peFile)
        {
            // Prefer .rdata, then .data, then first writable section
            foreach (var name in new[] { ".rdata", ".data", "_rdata", "_data" })
            {
                foreach (var s in peFile.Sections)
                    if (s.Header.Name?.TrimEnd('\0') == name) return s;
            }
            // Fallback: first section with write permission
            foreach (var s in peFile.Sections)
                if ((s.Header.Characteristics & DataSectionFlags.MemoryWrite) != 0) return s;
            // Last resort: last section
            return peFile.Sections.Length > 0 ? peFile.Sections[peFile.Sections.Length - 1] : null;
        }

        private string ReadAnsiString(byte[] data, int offset)
        {
            if (offset < 0 || offset >= data.Length) return null;
            int end = offset;
            while (end < data.Length && data[end] != 0) end++;
            if (end == offset) return null;
            return Encoding.ASCII.GetString(data, offset, end - offset);
        }

        private List<ImportDescriptorParsed> ParseImportDescriptors(byte[] sectionData, uint offset, uint size)
        {
            var result = new List<ImportDescriptorParsed>();
            int pos = (int)offset;
            int maxDescriptors = (int)(size / IMPORT_DESCRIPTOR_SIZE);
            if (maxDescriptors <= 0) maxDescriptors = 1000;

            while (pos + IMPORT_DESCRIPTOR_SIZE <= sectionData.Length && result.Count < maxDescriptors)
            {
                uint origFirstThunk = BitConverter.ToUInt32(sectionData, pos);
                uint name = BitConverter.ToUInt32(sectionData, pos + 12);
                uint firstThunk = BitConverter.ToUInt32(sectionData, pos + 16);

                if (name == 0 && firstThunk == 0) break;

                result.Add(new ImportDescriptorParsed
                {
                    OriginalFirstThunkRVA = origFirstThunk,
                    NameRVA = name,
                    FirstThunkRVA = firstThunk
                });

                pos += IMPORT_DESCRIPTOR_SIZE;
            }
            return result;
        }

        // Data directory accessors
        private uint GetImportDirRVA(PEFile pe) => pe is PE64File pe64 ? pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress : pe is PE32File pe32 ? pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress : 0;
        private uint GetImportDirSize(PEFile pe) => pe is PE64File pe64 ? pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size : pe is PE32File pe32 ? pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size : 0;
        private uint GetDelayImportDirRVA(PEFile pe) => pe is PE64File pe64 ? pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress : pe is PE32File pe32 ? pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress : 0;
        private uint GetDelayImportDirSize(PEFile pe) => pe is PE64File pe64 ? pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size : pe is PE32File pe32 ? pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size : 0;
        private uint GetBoundImportDirRVA(PEFile pe) => pe is PE64File pe64 ? pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress : pe is PE32File pe32 ? pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress : 0;
        private uint GetBoundImportDirSize(PEFile pe) => pe is PE64File pe64 ? pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size : pe is PE32File pe32 ? pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size : 0;

        private void SetImportDirRVA(PEFile pe, uint rva, uint size)
        {
            if (pe is PE64File pe64) { pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = rva; pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = size; }
            else if (pe is PE32File pe32) { pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = rva; pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = size; }
        }

        private void SetIatDirRVA(PEFile pe, uint rva, uint size)
        {
            if (pe is PE64File pe64) { pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = rva; pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = size; }
            else if (pe is PE32File pe32) { pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = rva; pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = size; }
        }

        private void SetBoundImportDirRVA(PEFile pe, uint rva, uint size)
        {
            if (pe is PE64File pe64) { pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = rva; pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = size; }
            else if (pe is PE32File pe32) { pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = rva; pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = size; }
        }

        private class ImportDescriptorParsed
        {
            public uint OriginalFirstThunkRVA;
            public uint NameRVA;
            public uint FirstThunkRVA;
        }
    }
}
