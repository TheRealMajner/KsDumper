using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using KsDumperClient.PE;

namespace KsDumperClient.Utility
{
    public static class PEComparator
    {
        public struct SectionDiff
        {
            public string SectionName;
            public uint RVA;
            public bool Identical;
            public int DifferentBytes;
            public int TotalBytes;
            public double DifferencePercent;
            public List<(uint offset, byte originalByte, byte dumpedByte)> FirstDifferences;
        }

        // Compare sections of a dumped PE against an on-disk original.
        public static List<SectionDiff> Compare(PEFile dumpedPe, string originalFilePath)
        {
            var results = new List<SectionDiff>();

            if (!File.Exists(originalFilePath))
                return results;

            byte[] originalBytes;
            try { originalBytes = File.ReadAllBytes(originalFilePath); }
            catch { return results; }

            // Parse original PE to get section file offsets and sizes
            if (originalBytes.Length < 64) return results;

            int peOffset = BitConverter.ToInt32(originalBytes, 60);
            if (peOffset + 24 > originalBytes.Length) return results;

            ushort magic = BitConverter.ToUInt16(originalBytes, peOffset + 24);
            int numSections = BitConverter.ToUInt16(originalBytes, peOffset + 6);
            int sizeOfOptionalHeader = BitConverter.ToUInt16(originalBytes, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + sizeOfOptionalHeader;

            // Build section map from original
            var originalSections = new Dictionary<string, (int fileOffset, int virtualSize, int rawSize)>();
            for (int i = 0; i < numSections; i++)
            {
                int off = sectionTableOffset + i * 40;
                if (off + 40 > originalBytes.Length) break;

                string name = System.Text.Encoding.ASCII.GetString(originalBytes, off, 8).TrimEnd('\0');
                int vSize = BitConverter.ToInt32(originalBytes, off + 8);
                int rawSize = BitConverter.ToInt32(originalBytes, off + 16);
                int rawOffset = BitConverter.ToInt32(originalBytes, off + 20);

                originalSections[name] = (rawOffset, vSize, rawSize);
            }

            // Compare each dumped section against original
            foreach (var sec in dumpedPe.Sections)
            {
                string secName = sec.Header.Name;
                if (!originalSections.TryGetValue(secName, out var origInfo))
                    continue;

                byte[] dumpedData = sec.Content;
                if (dumpedData == null || dumpedData.Length == 0)
                    continue;

                int compareLen = Math.Min(dumpedData.Length, origInfo.rawSize);
                if (origInfo.fileOffset + compareLen > originalBytes.Length)
                    compareLen = Math.Min(compareLen, originalBytes.Length - origInfo.fileOffset);

                if (compareLen <= 0) continue;

                int diffCount = 0;
                var firstDiffs = new List<(uint, byte, byte)>();

                for (int j = 0; j < compareLen; j++)
                {
                    if (dumpedData[j] != originalBytes[origInfo.fileOffset + j])
                    {
                        diffCount++;
                        if (firstDiffs.Count < 20)
                            firstDiffs.Add(((uint)j, originalBytes[origInfo.fileOffset + j], dumpedData[j]));
                    }
                }

                results.Add(new SectionDiff
                {
                    SectionName = secName,
                    RVA = sec.Header.VirtualAddress,
                    Identical = diffCount == 0,
                    DifferentBytes = diffCount,
                    TotalBytes = compareLen,
                    DifferencePercent = compareLen > 0 ? (100.0 * diffCount / compareLen) : 0,
                    FirstDifferences = firstDiffs
                });
            }

            return results;
        }

        public static void SaveReport(string outputPath, List<SectionDiff> diffs, string originalPath)
        {
            using (var writer = new StreamWriter(outputPath))
            {
                writer.WriteLine("// KsDumper - PE Section Comparison Report");
                writer.WriteLine($"// Original: {originalPath}");
                writer.WriteLine($"// Generated: {DateTime.Now}");
                writer.WriteLine();

                foreach (var diff in diffs)
                {
                    string status = diff.Identical ? "IDENTICAL" : $"DIFFERS ({diff.DifferentBytes} bytes, {diff.DifferencePercent:F1}%)";
                    writer.WriteLine($"[{diff.SectionName}] RVA: 0x{diff.RVA:x} - {status}");

                    if (!diff.Identical && diff.FirstDifferences.Count > 0)
                    {
                        writer.WriteLine($"  First differences (up to 20):");
                        foreach (var (offset, orig, dumped) in diff.FirstDifferences)
                        {
                            writer.WriteLine($"    +0x{offset:x}: 0x{orig:x2} → 0x{dumped:x2}");
                        }
                    }
                    writer.WriteLine();
                }
            }
        }
    }
}
