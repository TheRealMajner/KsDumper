using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KsDumperClient.Utility
{
    /// <summary>
    /// Holds an on-disk Unity DLL (GameAssembly.dll / UnityPlayer.dll) for comparison
    /// against the decrypted in-memory version. Used to identify which sections were
    /// decrypted/unpacked at runtime and to map IL2CPP API exports.
    /// </summary>
    public class UnityReference
    {
        public struct PeSection
        {
            public string Name;
            public uint VirtualAddress;
            public uint VirtualSize;
            public uint RawSize;
            public uint RawOffset;
            public byte[] Data;           // Raw section bytes from disk
            public uint Characteristics;
        }

        public struct ExportEntry
        {
            public string Name;
            public uint Rva;
            public ushort Ordinal;
        }

        public string FilePath;
        public string FileName;
        public byte[] RawBytes;
        public PeSection[] Sections;
        public ExportEntry[] Exports;
        public ulong ImageBase;
        public uint ImageSize;
        public uint EntryPointRva;

        // ---------- Loading ----------

        public static UnityReference Load(string dllPath)
        {
            if (!File.Exists(dllPath))
                return null;

            byte[] raw = File.ReadAllBytes(dllPath);
            if (raw.Length < 64) return null;

            var uref = new UnityReference
            {
                FilePath = dllPath,
                FileName = Path.GetFileName(dllPath),
                RawBytes = raw
            };

            // Parse DOS header
            if (BitConverter.ToUInt16(raw, 0) != 0x5A4D) return null;
            int peOffset = BitConverter.ToInt32(raw, 60);
            if (peOffset + 24 > raw.Length) return null;

            // PE signature
            if (BitConverter.ToUInt32(raw, peOffset) != 0x00004550) return null;

            ushort magic = BitConverter.ToUInt16(raw, peOffset + 24);
            bool is64 = magic == 0x20b;

            ushort numSections = BitConverter.ToUInt16(raw, peOffset + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(raw, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + sizeOfOptHdr;

            // Image base and size
            if (is64)
            {
                uref.ImageBase = BitConverter.ToUInt64(raw, peOffset + 24 + 24);
                uref.ImageSize = BitConverter.ToUInt32(raw, peOffset + 24 + 56);
                uref.EntryPointRva = BitConverter.ToUInt32(raw, peOffset + 24 + 16);
            }
            else
            {
                uref.ImageBase = BitConverter.ToUInt32(raw, peOffset + 24 + 28);
                uref.ImageSize = BitConverter.ToUInt32(raw, peOffset + 24 + 56);
                uref.EntryPointRva = BitConverter.ToUInt32(raw, peOffset + 24 + 16);
            }

            // Parse sections
            uref.Sections = new PeSection[numSections];
            for (int i = 0; i < numSections; i++)
            {
                int off = sectionTableOffset + i * 40;
                if (off + 40 > raw.Length) break;

                var sec = new PeSection();
                sec.Name = Encoding.ASCII.GetString(raw, off, 8).TrimEnd('\0');
                sec.VirtualSize = BitConverter.ToUInt32(raw, off + 8);
                sec.VirtualAddress = BitConverter.ToUInt32(raw, off + 12);
                sec.RawSize = BitConverter.ToUInt32(raw, off + 16);
                sec.RawOffset = BitConverter.ToUInt32(raw, off + 20);
                sec.Characteristics = BitConverter.ToUInt32(raw, off + 36);

                // Read section data
                if (sec.RawOffset > 0 && sec.RawSize > 0 && sec.RawOffset + sec.RawSize <= raw.Length)
                {
                    sec.Data = new byte[sec.RawSize];
                    Array.Copy(raw, sec.RawOffset, sec.Data, 0, sec.RawSize);
                }

                uref.Sections[i] = sec;
            }

            // Parse export table
            uref.Exports = ParseExports(raw, peOffset, is64);

            return uref;
        }

        // ---------- Section comparison ----------

        public struct SectionComparison
        {
            public string Name;
            public uint Rva;
            public bool IsDecrypted;      // true if disk != memory (section was modified at runtime)
            public int DifferentBytes;
            public int TotalCompared;
            public double DiffPercent;
            public byte[] DecryptedData;   // The in-memory (decrypted) version
            public byte[] OriginalData;    // The on-disk (encrypted) version
        }

        public List<SectionComparison> CompareSections(byte[] inMemoryDump)
        {
            var results = new List<SectionComparison>();
            if (inMemoryDump == null || Sections == null)
                return results;

            foreach (var sec in Sections)
            {
                if (sec.Data == null) continue;

                int memOffset = (int)sec.VirtualAddress;
                int compareLen = (int)Math.Min(sec.RawSize, sec.VirtualSize);
                if (compareLen <= 0) continue;
                if (memOffset + compareLen > inMemoryDump.Length)
                    compareLen = Math.Min(compareLen, inMemoryDump.Length - memOffset);
                if (compareLen <= 0) continue;

                int diffCount = 0;
                for (int j = 0; j < compareLen; j++)
                {
                    if (sec.Data[j] != inMemoryDump[memOffset + j])
                        diffCount++;
                }

                bool isDecrypted = diffCount > 0;
                byte[] memSection = new byte[compareLen];
                Array.Copy(inMemoryDump, memOffset, memSection, 0, compareLen);

                results.Add(new SectionComparison
                {
                    Name = sec.Name,
                    Rva = sec.VirtualAddress,
                    IsDecrypted = isDecrypted,
                    DifferentBytes = diffCount,
                    TotalCompared = compareLen,
                    DiffPercent = compareLen > 0 ? (100.0 * diffCount / compareLen) : 0,
                    DecryptedData = memSection,
                    OriginalData = sec.Data
                });
            }

            return results;
        }

        // ---------- In-memory full dump ----------

        /// <summary>
        /// Dumps the full in-memory image of GameAssembly.dll into a flat byte array
        /// (indexed by RVA) using the kernel driver's CopyVirtualMemory.
        /// </summary>
        public byte[] DumpInMemoryImage(Driver.IMemoryReader driver, int processId, ulong baseAddress)
        {
            byte[] image = new byte[ImageSize];

            foreach (var sec in Sections)
            {
                if (sec.VirtualSize == 0 || sec.VirtualAddress == 0) continue;

                int readSize = (int)Math.Min(sec.VirtualSize, ImageSize - sec.VirtualAddress);
                if (readSize <= 0) continue;

                IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)readSize, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (buffer == IntPtr.Zero) continue;
                try
                {
                    ulong srcAddr = baseAddress + sec.VirtualAddress;
                    if (driver.CopyVirtualMemory(processId, (IntPtr)srcAddr, buffer, readSize))
                    {
                        System.Runtime.InteropServices.Marshal.Copy(buffer, image, (int)sec.VirtualAddress, readSize);
                    }
                }
                finally
                {
                    WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
                }
            }

            return image;
        }

        // ---------- Decrypted section extraction ----------

        public void SaveDecryptedSections(string outputDir, List<SectionComparison> comparisons)
        {
            Directory.CreateDirectory(outputDir);

            foreach (var cmp in comparisons)
            {
                if (!cmp.IsDecrypted || cmp.DecryptedData == null) continue;

                string safeName = cmp.Name.Replace("/", "_").Replace("\\", "_");
                string path = Path.Combine(outputDir, $"{safeName}_decrypted.bin");
                File.WriteAllBytes(path, cmp.DecryptedData);

                // Also save original alongside for diffing
                string origPath = Path.Combine(outputDir, $"{safeName}_original.bin");
                File.WriteAllBytes(origPath, cmp.OriginalData);
            }
        }

        public void SaveComparisonReport(string outputPath, List<SectionComparison> comparisons)
        {
            using (var writer = new StreamWriter(outputPath))
            {
                writer.WriteLine("// KsDumper - Unity On-Disk vs In-Memory Section Comparison");
                writer.WriteLine($"// Reference DLL: {FilePath}");
                writer.WriteLine($"// Image Base: 0x{ImageBase:X}");
                writer.WriteLine($"// Image Size: 0x{ImageSize:X}");
                writer.WriteLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                writer.WriteLine();

                writer.WriteLine("// Legend: DECRYPTED = section differs at runtime (unpacked/decrypted by IL2CPP)");
                writer.WriteLine("//         IDENTICAL = section unchanged from on-disk version");
                writer.WriteLine();

                foreach (var cmp in comparisons)
                {
                    string status = cmp.IsDecrypted
                        ? $"DECRYPTED ({cmp.DifferentBytes} bytes changed, {cmp.DiffPercent:F1}%)"
                        : "IDENTICAL";

                    writer.WriteLine($"[{cmp.Name}] RVA: 0x{cmp.Rva:X} - {status}");

                    if (cmp.IsDecrypted)
                    {
                        writer.WriteLine($"  Decrypted section saved: {cmp.Name}_decrypted.bin");
                        writer.WriteLine($"  Original section saved:  {cmp.Name}_original.bin");
                    }
                    writer.WriteLine();
                }

                // Export table summary
                if (Exports != null && Exports.Length > 0)
                {
                    writer.WriteLine("// ---- Export Table (from on-disk DLL) ----");
                    writer.WriteLine($"// {Exports.Length} exported functions");
                    writer.WriteLine();

                    foreach (var exp in Exports)
                    {
                        writer.WriteLine($"  0x{exp.Rva:X8}  {exp.Name}");
                    }
                }
            }
        }

        // ---------- Export parsing ----------

        private static ExportEntry[] ParseExports(byte[] raw, int peOffset, bool is64)
        {
            int exportDirOffset = is64 ? peOffset + 24 + 112 : peOffset + 24 + 96;
            if (exportDirOffset + 8 > raw.Length) return new ExportEntry[0];

            uint exportRva = BitConverter.ToUInt32(raw, exportDirOffset);
            uint exportSize = BitConverter.ToUInt32(raw, exportDirOffset + 4);
            if (exportRva == 0 || exportSize == 0) return new ExportEntry[0];

            int exportFileOff = RvaToFileOffset(raw, peOffset, is64, exportRva);
            if (exportFileOff <= 0 || exportFileOff + 40 > raw.Length) return new ExportEntry[0];

            // IMAGE_EXPORT_DIRECTORY
            uint numFunctions = BitConverter.ToUInt32(raw, exportFileOff + 20);
            uint numNames = BitConverter.ToUInt32(raw, exportFileOff + 24);
            uint funcAddrRva = BitConverter.ToUInt32(raw, exportFileOff + 28);
            uint namePtrRva = BitConverter.ToUInt32(raw, exportFileOff + 32);
            uint ordinalRva = BitConverter.ToUInt32(raw, exportFileOff + 36);

            if (numNames == 0 || numNames > 100000) return new ExportEntry[0];

            int funcAddrOff = RvaToFileOffset(raw, peOffset, is64, funcAddrRva);
            int namePtrOff = RvaToFileOffset(raw, peOffset, is64, namePtrRva);
            int ordinalOff = RvaToFileOffset(raw, peOffset, is64, ordinalRva);

            if (funcAddrOff <= 0 || namePtrOff <= 0 || ordinalOff <= 0) return new ExportEntry[0];

            var exports = new List<ExportEntry>((int)numNames);

            for (uint i = 0; i < numNames; i++)
            {
                int nameRvaOff = namePtrOff + (int)(i * 4);
                if (nameRvaOff + 4 > raw.Length) break;
                uint nameRva = BitConverter.ToUInt32(raw, nameRvaOff);

                int nameOff = RvaToFileOffset(raw, peOffset, is64, nameRva);
                if (nameOff <= 0 || nameOff >= raw.Length) continue;

                int nameEnd = nameOff;
                while (nameEnd < raw.Length && raw[nameEnd] != 0) nameEnd++;
                string name = Encoding.ASCII.GetString(raw, nameOff, nameEnd - nameOff);

                int ordOff = ordinalOff + (int)(i * 2);
                if (ordOff + 2 > raw.Length) break;
                ushort ordinal = BitConverter.ToUInt16(raw, ordOff);

                int funcOff = funcAddrOff + ordinal * 4;
                if (funcOff + 4 > raw.Length) break;
                uint funcRva = BitConverter.ToUInt32(raw, funcOff);

                exports.Add(new ExportEntry { Name = name, Rva = funcRva, Ordinal = ordinal });
            }

            return exports.ToArray();
        }

        private static int RvaToFileOffset(byte[] raw, int peOffset, bool is64, uint rva)
        {
            ushort numSections = BitConverter.ToUInt16(raw, peOffset + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(raw, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + sizeOfOptHdr;

            for (int i = 0; i < numSections; i++)
            {
                int off = sectionTableOffset + i * 40;
                if (off + 40 > raw.Length) break;

                uint secVA = BitConverter.ToUInt32(raw, off + 12);
                uint secRawSize = BitConverter.ToUInt32(raw, off + 16);
                uint secRawOff = BitConverter.ToUInt32(raw, off + 20);
                uint secVSize = BitConverter.ToUInt32(raw, off + 8);

                if (rva >= secVA && rva < secVA + Math.Max(secRawSize, secVSize))
                {
                    return (int)(secRawOff + (rva - secVA));
                }
            }
            return -1;
        }
    }
}
