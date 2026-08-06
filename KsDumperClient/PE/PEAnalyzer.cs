using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using KsDumperClient.Utility;

using static KsDumperClient.PE.NativePEStructs;

namespace KsDumperClient.PE
{
    public static class PEAnalyzer
    {
        private const int MIN_VTABLE_METHODS = 4;
        private const int MIN_ASCII_STRING_LENGTH = 6;
        private const int MIN_UNICODE_STRING_LENGTH = 4;

        public static List<string> ScanRTTI(PEFile pe)
        {
            var classes = new List<string>();
            bool is64 = pe.Type == PEFile.PEType.PE64;

            foreach (var section in pe.Sections)
            {
                if (section.Content == null || section.Content.Length == 0) continue;

                string name = section.Header.Name?.TrimEnd('\0') ?? "";
                if (name != ".rdata" && name != ".data" && name != "_rdata") continue;

                byte[] data = section.Content;
                uint sectionRVA = section.Header.VirtualAddress;

                for (int i = 0; i < data.Length - 6; i++)
                {
                    // Look for ".?AV" or ".?AU" (MSVC type descriptor prefix)
                    if (data[i] == (byte)'.' && data[i + 1] == (byte)'?' &&
                        (data[i + 2] == (byte)'A') &&
                        (data[i + 3] == (byte)'V' || data[i + 3] == (byte)'U'))
                    {
                        int end = i + 4;
                        while (end < data.Length && data[end] != 0) end++;

                        if (end > i + 4)
                        {
                            string raw = Encoding.ASCII.GetString(data, i, end - i);

                            // Strip "@@" suffix if present
                            if (raw.EndsWith("@@"))
                                raw = raw.Substring(0, raw.Length - 2);

                            // Demangle: ".?AVClassName" → "ClassName"
                            string className = raw.Substring(4);

                            // Demangle common MSVC decorations
                            className = DemangleClassName(className);

                            if (!string.IsNullOrEmpty(className) && !classes.Contains(className))
                                classes.Add(className);
                        }
                    }
                }
            }

            classes.Sort();
            return classes;
        }

        public static List<(uint rva, int methodCount)> FindVTables(PEFile pe, ulong imageBase)
        {
            var vtables = new List<(uint rva, int methodCount)>();
            bool is64 = pe.Type == PEFile.PEType.PE64;
            int ptrSize = is64 ? 8 : 4;

            // Find .text section VA range
            ulong textStart = 0, textEnd = 0;
            foreach (var s in pe.Sections)
            {
                string name = s.Header.Name?.TrimEnd('\0') ?? "";
                if (name == ".text" || name == "_text" || name == "CODE")
                {
                    textStart = imageBase + s.Header.VirtualAddress;
                    textEnd = textStart + Math.Max(s.Header.VirtualSize, s.Header.SizeOfRawData);
                    break;
                }
            }

            if (textStart == 0) return vtables;

            // Scan readable sections for vtable patterns
            foreach (var section in pe.Sections)
            {
                if (section.Content == null || section.Content.Length < ptrSize * MIN_VTABLE_METHODS) continue;

                string name = section.Header.Name?.TrimEnd('\0') ?? "";
                if (name == ".text" || name == "_text" || name == "CODE") continue;

                // Check if section is readable (has initialized data)
                if ((section.Header.Characteristics & DataSectionFlags.MemoryRead) == 0 &&
                    (section.Header.Characteristics & DataSectionFlags.ContentInitializedData) == 0)
                    continue;

                byte[] data = section.Content;
                uint sectionRVA = section.Header.VirtualAddress;
                int methods = 0;
                int startOffset = 0;

                for (int i = 0; i <= data.Length - ptrSize; i += ptrSize)
                {
                    ulong value = is64
                        ? (i + 8 <= data.Length ? BitConverter.ToUInt64(data, i) : 0)
                        : (i + 4 <= data.Length ? BitConverter.ToUInt32(data, i) : 0);

                    if (value >= textStart && value < textEnd)
                    {
                        if (methods == 0) startOffset = i;
                        methods++;
                    }
                    else
                    {
                        if (methods >= MIN_VTABLE_METHODS)
                        {
                            uint vtableRVA = sectionRVA + (uint)startOffset;
                            vtables.Add((vtableRVA, methods));
                        }
                        methods = 0;
                    }
                }

                // Handle vtable at end of section
                if (methods >= MIN_VTABLE_METHODS)
                {
                    uint vtableRVA = sectionRVA + (uint)startOffset;
                    vtables.Add((vtableRVA, methods));
                }
            }

            return vtables;
        }

        public static List<(uint rva, string value)> ExtractStrings(PEFile pe)
        {
            var strings = new List<(uint rva, string value)>();

            foreach (var section in pe.Sections)
            {
                if (section.Content == null || section.Content.Length == 0) continue;

                string name = section.Header.Name?.TrimEnd('\0') ?? "";
                if (name != ".rdata" && name != ".data" && name != "_rdata" && name != "_data") continue;

                byte[] data = section.Content;
                uint sectionRVA = section.Header.VirtualAddress;

                // ASCII strings
                int runStart = -1;
                for (int i = 0; i < data.Length; i++)
                {
                    bool printable = data[i] >= 0x20 && data[i] < 0x7F;
                    if (printable)
                    {
                        if (runStart < 0) runStart = i;
                    }
                    else
                    {
                        if (runStart >= 0)
                        {
                            int len = i - runStart;
                            if (len >= MIN_ASCII_STRING_LENGTH)
                            {
                                string s = Encoding.ASCII.GetString(data, runStart, len);
                                strings.Add((sectionRVA + (uint)runStart, s));
                            }
                            runStart = -1;
                        }
                    }
                }

                // Unicode (UTF-16LE) strings
                for (int i = 0; i < data.Length - 1; i += 2)
                {
                    int uniRunStart = -1;
                    int charCount = 0;

                    for (int j = i; j < data.Length - 1; j += 2)
                    {
                        char c = (char)(data[j] | (data[j + 1] << 8));
                        if (c >= 0x20 && c < 0x7F)
                        {
                            if (uniRunStart < 0) uniRunStart = j;
                            charCount++;
                        }
                        else
                        {
                            if (charCount >= MIN_UNICODE_STRING_LENGTH)
                            {
                                string s = Encoding.Unicode.GetString(data, uniRunStart, charCount * 2);
                                uint rva = sectionRVA + (uint)uniRunStart;
                                // Avoid duplicating ASCII strings found above
                                bool duplicate = false;
                                foreach (var existing in strings)
                                    if (existing.rva == rva) { duplicate = true; break; }
                                if (!duplicate)
                                    strings.Add((rva, s));
                            }
                            uniRunStart = -1;
                            charCount = 0;
                            break;
                        }
                    }
                }
            }

            return strings;
        }

        public static void CleanupForIDA(PEFile pe)
        {
            if (pe is PE64File pe64)
            {
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
                pe64.PEHeader.OptionalHeader.CheckSum = 0;
                var tlsDir64 = pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                NullifyTlsCallbacks(pe, true, pe64.PEHeader.OptionalHeader.ImageBase,
                    tlsDir64.VirtualAddress, tlsDir64.Size);
            }
            else if (pe is PE32File pe32)
            {
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
                pe32.PEHeader.OptionalHeader.CheckSum = 0;
                var tlsDir32 = pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
                NullifyTlsCallbacks(pe, false, pe32.PEHeader.OptionalHeader.ImageBase,
                    tlsDir32.VirtualAddress, tlsDir32.Size);
            }
        }

        private static void NullifyTlsCallbacks(PEFile pe, bool is64, ulong imageBase, uint tlsRVA, uint tlsSize)
        {
            if (tlsRVA == 0 || tlsSize == 0) return;

            PESection tlsSection = FindSectionByRVA(pe, tlsRVA);
            if (tlsSection?.Content == null) return;

            uint tlsOffset = tlsRVA - tlsSection.Header.VirtualAddress;
            byte[] data = tlsSection.Content;

            // IMAGE_TLS_DIRECTORY: AddressOfCallBacks is at offset 24 (64-bit) or 12 (32-bit)
            int cbFieldOffset = is64 ? 24 : 12;
            int ptrSize = is64 ? 8 : 4;

            if (tlsOffset + cbFieldOffset + ptrSize > data.Length) return;

            ulong callbacksVA = is64
                ? BitConverter.ToUInt64(data, (int)tlsOffset + cbFieldOffset)
                : BitConverter.ToUInt32(data, (int)tlsOffset + cbFieldOffset);

            if (callbacksVA == 0) return;

            // Convert VA to RVA
            if (callbacksVA < imageBase) return;
            uint callbacksRVA = (uint)(callbacksVA - imageBase);

            PESection cbSection = FindSectionByRVA(pe, callbacksRVA);
            if (cbSection?.Content == null) return;

            uint cbOffset = callbacksRVA - cbSection.Header.VirtualAddress;
            byte[] cbData = cbSection.Content;

            // Zero out callback pointers until we hit a null terminator or end of section
            int pos = (int)cbOffset;
            int zeroed = 0;
            while (pos + ptrSize <= cbData.Length)
            {
                ulong entry = is64
                    ? BitConverter.ToUInt64(cbData, pos)
                    : BitConverter.ToUInt32(cbData, pos);

                if (entry == 0) break;

                for (int b = 0; b < ptrSize; b++)
                    cbData[pos + b] = 0;

                zeroed++;
                pos += ptrSize;
            }

            if (zeroed > 0)
                Logger.Log("TLS: nullified {0} callback(s)", zeroed);
        }

        public static void NormalizeImageBase(PEFile pe)
        {
            // Strip DYNAMIC_BASE flag (bit 6) so IDA doesn't try to rebase
            ushort dynamicBase = 0x0040;

            if (pe is PE64File pe64)
            {
                pe64.PEHeader.OptionalHeader.ImageBase = 0x140000000;
                pe64.PEHeader.OptionalHeader.DllCharacteristics &= (ushort)~dynamicBase;
            }
            else if (pe is PE32File pe32)
            {
                pe32.PEHeader.OptionalHeader.ImageBase = 0x00400000;
                pe32.PEHeader.OptionalHeader.DllCharacteristics &= (ushort)~dynamicBase;
            }
        }

        public static (int total, int resolved, int dllCount) GetImportStats(PEFile pe)
        {
            bool is64 = pe.Type == PEFile.PEType.PE64;
            int thunkSize = is64 ? 8 : 4;
            int total = 0, resolved = 0, dllCount = 0;

            uint importDirRVA = GetImportDirRVA(pe);
            uint importDirSize = GetImportDirSize(pe);
            if (importDirRVA == 0) return (0, 0, 0);

            PESection section = FindSectionByRVA(pe, importDirRVA);
            if (section?.Content == null) return (0, 0, 0);

            uint offset = importDirRVA - section.Header.VirtualAddress;
            byte[] data = section.Content;

            while (offset + 20 <= data.Length)
            {
                uint nameRVA = BitConverter.ToUInt32(data, (int)offset + 12);
                uint firstThunkRVA = BitConverter.ToUInt32(data, (int)offset + 16);

                if (nameRVA == 0 && firstThunkRVA == 0) break;

                dllCount++;

                uint iatOffset = firstThunkRVA - section.Header.VirtualAddress;
                if (iatOffset < data.Length)
                {
                    for (int t = 0; ; t++)
                    {
                        int pos = (int)(iatOffset + t * thunkSize);
                        if (pos + thunkSize > data.Length) break;

                        ulong thunkValue = is64
                            ? BitConverter.ToUInt64(data, pos)
                            : BitConverter.ToUInt32(data, pos);

                        if (thunkValue == 0) break;
                        total++;

                        // "Resolved" = not an import-by-ordinal (high bit clear)
                        // and the value has been replaced by our rebuilder (points to new data)
                        bool isOrdinal = is64
                            ? (thunkValue & 0x8000000000000000) != 0
                            : (thunkValue & 0x80000000) != 0;

                        if (!isOrdinal)
                            resolved++;
                    }
                }

                offset += 20;
            }

            return (total, resolved, dllCount);
        }

        public static void WriteReport(string outputPath, PEFile pe,
            List<string> rttiClasses, List<(uint rva, int methods)> vtables,
            List<(uint rva, string value)> strings, (int total, int resolved, int dlls) importStats)
        {
            using (var writer = new StreamWriter(outputPath, false, Encoding.UTF8))
            {
                writer.WriteLine("=== KsDumper PE Analysis Report ===");
                writer.WriteLine("Generated: {0}", DateTime.Now);
                writer.WriteLine("PE Type: {0}", pe.Type);
                writer.WriteLine();

                // Import Stats
                writer.WriteLine("--- Import Statistics ---");
                writer.WriteLine("Total imports: {0}", importStats.total);
                writer.WriteLine("Resolved (import-by-name): {0}", importStats.resolved);
                writer.WriteLine("Unresolved/ordinal: {0}", importStats.total - importStats.resolved);
                writer.WriteLine("DLL count: {0}", importStats.dlls);
                double pct = importStats.total > 0 ? (100.0 * importStats.resolved / importStats.total) : 0;
                writer.WriteLine("Resolution rate: {0:F1}%", pct);
                writer.WriteLine();

                // RTTI Classes
                writer.WriteLine("--- RTTI Classes ({0} found) ---", rttiClasses.Count);
                foreach (var cls in rttiClasses)
                    writer.WriteLine("  {0}", cls);
                writer.WriteLine();

                // VTables
                writer.WriteLine("--- Virtual Method Tables ({0} found) ---", vtables.Count);
                foreach (var vt in vtables)
                    writer.WriteLine("  RVA: 0x{0:X8}  Methods: {1}", vt.rva, vt.methods);
                writer.WriteLine();

                // Strings (top 200)
                int stringLimit = Math.Min(strings.Count, 200);
                writer.WriteLine("--- Strings (showing {0} of {1}) ---", stringLimit, strings.Count);
                for (int i = 0; i < stringLimit; i++)
                {
                    var s = strings[i];
                    string truncated = s.value.Length > 120 ? s.value.Substring(0, 120) + "..." : s.value;
                    writer.WriteLine("  0x{0:X8}: {1}", s.rva, truncated);
                }
                if (strings.Count > stringLimit)
                    writer.WriteLine("  ... and {0} more strings", strings.Count - stringLimit);
            }
        }

        // --- Helpers ---

        private static string DemangleClassName(string name)
        {
            // Strip common MSVC decorations
            // "class std::basic_string<char,..." → keep as-is for now
            // Remove template parameters for cleaner output: "Foo<int>" → "Foo"
            int templateDepth = 0;
            var sb = new StringBuilder();
            for (int i = 0; i < name.Length; i++)
            {
                if (name[i] == '<') templateDepth++;
                else if (name[i] == '>') templateDepth--;
                else if (templateDepth == 0) sb.Append(name[i]);
            }
            return sb.ToString();
        }

        private static uint GetImportDirRVA(PEFile pe)
        {
            if (pe is PE64File pe64) return pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            if (pe is PE32File pe32) return pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
            return 0;
        }

        private static uint GetImportDirSize(PEFile pe)
        {
            if (pe is PE64File pe64) return pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            if (pe is PE32File pe32) return pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            return 0;
        }

        private static PESection FindSectionByRVA(PEFile pe, uint rva)
        {
            foreach (var s in pe.Sections)
            {
                if (rva >= s.Header.VirtualAddress &&
                    rva < s.Header.VirtualAddress + Math.Max(s.Header.VirtualSize, s.Header.SizeOfRawData))
                    return s;
            }
            return null;
        }

        public struct SectionEntropy
        {
            public string Name;
            public uint RVA;
            public int Size;
            public double Entropy;
            public string Assessment; // "Normal", "Packed/Encrypted", "Empty/Sparse"
        }

        // Calculates Shannon entropy for each PE section.
        // Normal code: ~5.0-6.5, packed/encrypted: 7.0+, empty/sparse: <3.0
        public static List<SectionEntropy> CalculateEntropy(PEFile pe)
        {
            var results = new List<SectionEntropy>();

            foreach (var section in pe.Sections)
            {
                if (section.Content == null || section.Content.Length == 0)
                    continue;

                double entropy = ShannonEntropy(section.Content);
                string assessment;
                if (entropy < 1.0) assessment = "Empty/Sparse";
                else if (entropy < 5.0) assessment = "Low (data/strings)";
                else if (entropy <= 6.8) assessment = "Normal (code)";
                else assessment = "HIGH - likely packed/encrypted";

                results.Add(new SectionEntropy
                {
                    Name = section.Header.Name?.TrimEnd('\0') ?? "",
                    RVA = section.Header.VirtualAddress,
                    Size = section.Content.Length,
                    Entropy = entropy,
                    Assessment = assessment
                });
            }

            return results;
        }

        private static double ShannonEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;

            int[] freq = new int[256];
            foreach (byte b in data)
                freq[b]++;

            double entropy = 0;
            int len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / len;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }
    }
}
