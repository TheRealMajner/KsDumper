using System;
using System.Collections.Generic;
using System.IO;
using KsDumperClient.PE;

namespace KsDumperClient.Utility
{
    public static class StringXrefScanner
    {
        public struct XrefResult
        {
            public string StringValue;
            public ulong StringAddress;
            public bool IsUnicode;
            public List<ulong> ReferencedFrom; // addresses in .text that reference this string
        }

        // Scans the .text section of a dumped PE for RIP-relative references to known string addresses.
        // For x64: looks for LEA reg, [rip+disp32] and MOV reg, [rip+disp32] patterns.
        // imageBase = the base address where the module was loaded in the target process.
        public static List<XrefResult> FindXrefs(PEFile pe, List<(ulong address, bool isUnicode, string value)> strings, ulong imageBase)
        {
            var results = new List<XrefResult>();

            // Find .text section
            PESection textSection = null;
            foreach (var sec in pe.Sections)
            {
                if (sec.Header.Name.StartsWith(".text"))
                {
                    textSection = sec;
                    break;
                }
            }

            if (textSection == null || textSection.Content == null || textSection.Content.Length == 0)
                return results;

            // Build a lookup: RVA → (string, isUnicode)
            // String addresses are absolute VAs in the target process. Convert to RVA.
            var rvaToString = new Dictionary<uint, (string value, bool isUnicode)>();
            foreach (var (address, isUnicode, value) in strings)
            {
                if (address > imageBase)
                {
                    uint rva = (uint)(address - imageBase);
                    if (!rvaToString.ContainsKey(rva))
                        rvaToString[rva] = (value, isUnicode);
                }
            }

            if (rvaToString.Count == 0)
                return results;

            byte[] textData = textSection.Content;
            uint textRVA = textSection.Header.VirtualAddress;
            ulong textBaseVA = imageBase + textRVA;

            // Track which strings have been referenced
            var stringRefs = new Dictionary<uint, List<ulong>>();

            // Scan .text for RIP-relative addressing patterns
            for (int i = 0; i < textData.Length - 7; i++)
            {
                byte b0 = textData[i];
                byte b1 = textData[i + 1];

                // Check for REX prefix (0x40-0x4F)
                int offset = i;
                if (b0 >= 0x40 && b0 <= 0x4F)
                {
                    offset++;
                    if (offset + 1 >= textData.Length) continue;
                    b0 = textData[offset];
                    b1 = textData[offset + 1];
                }

                // LEA reg, [rip+disp32]: 8D xx (mod=00, rm=101)
                bool isLea = (b0 == 0x8D && (b1 & 0xC7) == 0x05);
                // MOV reg, [rip+disp32]: 8B xx (mod=00, rm=101)
                bool isMov = (b0 == 0x8B && (b1 & 0xC7) == 0x05);

                if ((isLea || isMov) && offset + 6 < textData.Length)
                {
                    int dispOffset = offset + 2;
                    int disp32 = BitConverter.ToInt32(textData, dispOffset);
                    // RIP = address of next instruction (after the full instruction)
                    // For LEA: REX(1) + opcode(1) + modrm(1) + disp32(4) = 7 bytes total from i
                    ulong rip = textBaseVA + (ulong)(i + 7);
                    ulong targetVA = rip + (ulong)disp32;

                    if (targetVA > imageBase)
                    {
                        uint targetRVA = (uint)(targetVA - imageBase);
                        if (rvaToString.ContainsKey(targetRVA))
                        {
                            if (!stringRefs.ContainsKey(targetRVA))
                                stringRefs[targetRVA] = new List<ulong>();
                            stringRefs[targetRVA].Add(textBaseVA + (ulong)i);
                        }
                    }
                }
            }

            // Build results for strings that have at least one reference
            foreach (var kvp in stringRefs)
            {
                if (rvaToString.TryGetValue(kvp.Key, out var strInfo))
                {
                    results.Add(new XrefResult
                    {
                        StringValue = strInfo.value,
                        StringAddress = imageBase + kvp.Key,
                        IsUnicode = strInfo.isUnicode,
                        ReferencedFrom = kvp.Value
                    });
                }
            }

            results.Sort((a, b) => b.ReferencedFrom.Count.CompareTo(a.ReferencedFrom.Count));
            return results;
        }

        public static void SaveXrefReport(string outputPath, List<XrefResult> xrefs, ulong imageBase)
        {
            using (var writer = new StreamWriter(outputPath, false, System.Text.Encoding.UTF8))
            {
                writer.WriteLine("// KsDumper - String Cross-Reference Report");
                writer.WriteLine($"// ImageBase: 0x{imageBase:X}");
                writer.WriteLine($"// Referenced strings: {xrefs.Count}");
                writer.WriteLine();

                foreach (var xref in xrefs)
                {
                    string type = xref.IsUnicode ? "U" : "A";
                    string escaped = xref.StringValue.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
                    if (escaped.Length > 120) escaped = escaped.Substring(0, 120) + "...";

                    writer.WriteLine($"[0x{xref.StringAddress:x}] [{type}] \"{escaped}\"");
                    writer.WriteLine($"  Referenced {xref.ReferencedFrom.Count} time(s):");
                    foreach (ulong refAddr in xref.ReferencedFrom)
                    {
                        uint refRVA = (uint)(refAddr - imageBase);
                        writer.WriteLine($"    @ 0x{refAddr:x} (RVA: 0x{refRVA:x})");
                    }
                    writer.WriteLine();
                }
            }
        }
    }
}
