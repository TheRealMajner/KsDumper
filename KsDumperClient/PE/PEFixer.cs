using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KsDumperClient.PE
{
    /// <summary>
    /// Comprehensive PE fixer that repairs stripped/corrupt PE headers and makes
    /// memory-dumped binaries fully analyzable in IDA Pro, Ghidra, x64dbg.
    /// </summary>
    public static class PEFixer
    {
        public struct FixReport
        {
            public bool Success;
            public List<string> Fixes;
            public List<string> Warnings;
            public string PEType;
            public int SectionCount;
            public uint ImageSize;
            public uint EntryPoint;

            public string Summary()
            {
                var sb = new StringBuilder();
                sb.AppendLine($"PE Fix Report ({PEType})");
                sb.AppendLine($"Sections: {SectionCount}, ImageSize: 0x{ImageSize:X}, EntryPoint: 0x{EntryPoint:X}");
                sb.AppendLine();
                if (Fixes.Count > 0) { sb.AppendLine("Fixes applied:"); foreach (var f in Fixes) sb.AppendLine($"  + {f}"); }
                if (Warnings.Count > 0) { sb.AppendLine("Warnings:"); foreach (var w in Warnings) sb.AppendLine($"  ! {w}"); }
                return sb.ToString();
            }
        }

        /// <summary>
        /// Fix a raw memory dump into a valid PE file on disk.
        /// </summary>
        public static FixReport FixAndSave(byte[] rawDump, ulong baseAddress, string outputPath)
        {
            var report = new FixReport { Fixes = new List<string>(), Warnings = new List<string>() };

            if (rawDump == null || rawDump.Length < 64)
            {
                report.Warnings.Add("Dump too small");
                return report;
            }

            // Validate/fix DOS header
            bool dosFixed = false;
            if (BitConverter.ToUInt16(rawDump, 0) != 0x5A4D)
            {
                // Try to find MZ signature
                for (int i = 0; i < Math.Min(rawDump.Length - 2, 0x1000); i++)
                {
                    if (rawDump[i] == 0x4D && rawDump[i + 1] == 0x5A)
                    {
                        report.Warnings.Add($"MZ signature found at offset 0x{i:X} instead of 0 - PE may be malformed");
                        break;
                    }
                }
                report.Warnings.Add("Missing MZ signature - attempting to reconstruct DOS header");
                ReconstructDOSHeader(rawDump);
                dosFixed = true;
            }

            int e_lfanew = BitConverter.ToInt32(rawDump, 60);
            if (e_lfanew <= 0 || e_lfanew >= rawDump.Length - 4)
            {
                // Try to find PE signature
                e_lfanew = FindPESignature(rawDump);
                if (e_lfanew > 0)
                {
                    BitConverter.GetBytes(e_lfanew).CopyTo(rawDump, 60);
                    report.Fixes.Add($"Fixed e_lfanew to 0x{e_lfanew:X}");
                }
                else
                {
                    report.Warnings.Add("Cannot find PE signature");
                    return report;
                }
            }

            if (BitConverter.ToUInt32(rawDump, e_lfanew) != 0x00004550)
            {
                report.Warnings.Add("Invalid PE signature");
                return report;
            }

            bool is64 = BitConverter.ToUInt16(rawDump, e_lfanew + 24) == 0x20b;
            report.PEType = is64 ? "PE64" : "PE32";

            ushort numSections = BitConverter.ToUInt16(rawDump, e_lfanew + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(rawDump, e_lfanew + 20);
            uint sectionAlignment = BitConverter.ToUInt32(rawDump, e_lfanew + (is64 ? 56 : 52));
            uint fileAlignment = BitConverter.ToUInt32(rawDump, e_lfanew + (is64 ? 60 : 56));

            if (sectionAlignment == 0) { sectionAlignment = 0x1000; BitConverter.GetBytes(sectionAlignment).CopyTo(rawDump, e_lfanew + (is64 ? 56 : 52)); report.Fixes.Add("Fixed SectionAlignment to 0x1000"); }
            if (fileAlignment == 0) { fileAlignment = 0x200; BitConverter.GetBytes(fileAlignment).CopyTo(rawDump, e_lfanew + (is64 ? 60 : 56)); report.Fixes.Add("Fixed FileAlignment to 0x200"); }

            int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

            // Fix section headers
            FixSectionHeaders(rawDump, sectionTableOff, numSections, sectionAlignment, fileAlignment, report);

            // Fix data directories
            FixDataDirectories(rawDump, e_lfanew, is64, numSections, sectionTableOff, sectionAlignment, report);

            // Fix SizeOfImage
            uint sizeOfImage = CalculateSizeOfImage(rawDump, sectionTableOff, numSections, sectionAlignment);
            int sizeOfImageOff = e_lfanew + (is64 ? 80 : 80);
            BitConverter.GetBytes(sizeOfImage).CopyTo(rawDump, sizeOfImageOff);
            report.ImageSize = sizeOfImage;

            // Fix SizeOfHeaders
            uint sizeOfHeaders = Align((uint)(sectionTableOff + numSections * 40), fileAlignment);
            int sizeOfHeadersOff = e_lfanew + (is64 ? 84 : 84);
            BitConverter.GetBytes(sizeOfHeaders).CopyTo(rawDump, sizeOfHeadersOff);
            if (sizeOfHeaders > (uint)rawDump.Length / 2) report.Warnings.Add($"SizeOfHeaders (0x{sizeOfHeaders:X}) seems too large");

            // Fix EntryPoint
            uint entryPoint = BitConverter.ToUInt32(rawDump, e_lfanew + 40);
            report.EntryPoint = entryPoint;
            if (entryPoint > 0 && entryPoint >= sizeOfImage)
            {
                report.Warnings.Add($"EntryPoint 0x{entryPoint:X} is outside image (SizeOfImage=0x{sizeOfImage:X})");
            }

            // Fix checksum (set to 0 for memory dumps, recalculate if possible)
            int checksumOff = e_lfanew + 88;
            BitConverter.GetBytes((uint)0).CopyTo(rawDump, checksumOff);
            report.Fixes.Add("Zeroed PE checksum");

            // Clear certificate table directory (security)
            int secDirIdx = is64 ? e_lfanew + 24 + 112 + 4 * 8 : e_lfanew + 24 + 96 + 4 * 8;
            if (secDirIdx + 8 <= rawDump.Length)
            {
                BitConverter.GetBytes((uint)0).CopyTo(rawDump, secDirIdx);
                BitConverter.GetBytes((uint)0).CopyTo(rawDump, secDirIdx + 4);
                report.Fixes.Add("Cleared security directory");
            }

            // Fix DLL characteristics
            int dllCharsOff = e_lfanew + (is64 ? 94 : 94);
            if (dllCharsOff + 2 <= rawDump.Length)
            {
                ushort dllChars = BitConverter.ToUInt16(rawDump, dllCharsOff);
                // Strip FORCE_INTEGRITY and GUARD_CF for dumped binaries
                dllChars &= unchecked((ushort)~0x0080); // FORCE_INTEGRITY
                dllChars &= unchecked((ushort)~0x4000); // GUARD_CF
                BitConverter.GetBytes(dllChars).CopyTo(rawDump, dllCharsOff);
                report.Fixes.Add("Stripped FORCE_INTEGRITY and GUARD_CF flags");
            }

            // Convert from memory layout to file layout
            byte[] filePE = ConvertMemoryToFileLayout(rawDump, e_lfanew, numSections, sectionTableOff, fileAlignment, sectionAlignment, report);

            // Recalculate checksum
            uint checksum = CalculatePEChecksum(filePE, e_lfanew);
            BitConverter.GetBytes(checksum).CopyTo(filePE, e_lfanew + 88);
            report.Fixes.Add($"Calculated PE checksum: 0x{checksum:X}");

            report.SectionCount = numSections;
            report.Success = true;

            File.WriteAllBytes(outputPath, filePE);
            return report;
        }

        // ---- Section Header Fixes ----

        private static void FixSectionHeaders(byte[] data, int tableOff, ushort numSections,
            uint sectionAlignment, uint fileAlignment, FixReport report)
        {
            for (int i = 0; i < numSections; i++)
            {
                int off = tableOff + i * 40;
                if (off + 40 > data.Length) break;

                string name = Encoding.ASCII.GetString(data, off, 8).TrimEnd('\0');
                uint virtualSize = BitConverter.ToUInt32(data, off + 8);
                uint virtualAddr = BitConverter.ToUInt32(data, off + 12);
                uint rawSize = BitConverter.ToUInt32(data, off + 16);
                uint rawOff = BitConverter.ToUInt32(data, off + 20);
                uint chars = BitConverter.ToUInt32(data, off + 36);

                // Fix zero VirtualSize
                if (virtualSize == 0 && rawSize > 0)
                {
                    virtualSize = rawSize;
                    BitConverter.GetBytes(virtualSize).CopyTo(data, off + 8);
                    report.Fixes.Add($"[{name}] Fixed VirtualSize from 0 to 0x{virtualSize:X}");
                }

                // Fix zero RawSize
                if (rawSize == 0 && virtualSize > 0)
                {
                    rawSize = Align(virtualSize, fileAlignment);
                    BitConverter.GetBytes(rawSize).CopyTo(data, off + 16);
                    report.Fixes.Add($"[{name}] Fixed RawSize from 0 to 0x{rawSize:X}");
                }

                // Fix VirtualAddress alignment
                uint alignedVA = Align(virtualAddr, sectionAlignment);
                if (alignedVA != virtualAddr && virtualAddr > 0)
                {
                    // Don't fix - the VA should match what's in memory
                }

                // Fix section characteristics if zero
                if (chars == 0)
                {
                    // Infer from name
                    if (name == ".text" || name == "_text" || name == "CODE")
                        chars = 0x60000020; // CODE | EXECUTE | READ
                    else if (name == ".data" || name == "_data")
                        chars = 0xC0000040; // INITIALIZED_DATA | READ | WRITE
                    else if (name == ".rdata" || name == ".rodata")
                        chars = 0x40000040; // INITIALIZED_DATA | READ
                    else if (name == ".rsrc")
                        chars = 0x40000040; // INITIALIZED_DATA | READ
                    else if (name == ".reloc")
                        chars = 0x42000040; // INITIALIZED_DATA | DISCARDABLE | READ
                    else if (name == ".pdata")
                        chars = 0x40000040; // INITIALIZED_DATA | READ
                    else
                        chars = 0xE0000060; // CODE | INITIALIZED_DATA | EXECUTE | READ | WRITE

                    if (chars != 0)
                    {
                        BitConverter.GetBytes(chars).CopyTo(data, off + 36);
                        report.Fixes.Add($"[{name}] Inferred section characteristics: 0x{chars:X}");
                    }
                }

                // Strip IMAGE_SCN_MEM_NOT_CACHED (0x200) which can cause issues
                if ((chars & 0x200) != 0)
                {
                    chars &= ~0x200u;
                    BitConverter.GetBytes(chars).CopyTo(data, off + 36);
                }
            }
        }

        // ---- Data Directory Fixes ----

        private static void FixDataDirectories(byte[] data, int e_lfanew, bool is64,
            ushort numSections, int sectionTableOff, uint sectionAlignment, FixReport report)
        {
            int dataDirBase = is64 ? e_lfanew + 24 + 112 : e_lfanew + 24 + 96;
            int numDirs = is64 ? 16 : 16;

            // Clear known-invalid directories for memory dumps
            int[] clearDirs = {
                4,  // IMAGE_DIRECTORY_ENTRY_SECURITY (certificates don't exist in memory)
                11, // IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (loader modifies this)
                14  // IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (CLR header, may be invalid)
            };

            foreach (int dirIdx in clearDirs)
            {
                int dirOff = dataDirBase + dirIdx * 8;
                if (dirOff + 8 > data.Length) continue;
                uint rva = BitConverter.ToUInt32(data, dirOff);
                uint size = BitConverter.ToUInt32(data, dirOff + 4);
                if (rva != 0 || size != 0)
                {
                    BitConverter.GetBytes((uint)0).CopyTo(data, dirOff);
                    BitConverter.GetBytes((uint)0).CopyTo(data, dirOff + 4);
                    string dirName = dirIdx == 4 ? "Security" : dirIdx == 11 ? "Bound Import" : dirIdx == 14 ? "COM Descriptor" : $"Dir[{dirIdx}]";
                    report.Fixes.Add($"Cleared {dirName} directory (RVA=0x{rva:X}, Size=0x{size:X})");
                }
            }

            // Validate import directory
            int importDirOff = dataDirBase + 1 * 8;
            if (importDirOff + 8 <= data.Length)
            {
                uint importRVA = BitConverter.ToUInt32(data, importDirOff);
                uint importSize = BitConverter.ToUInt32(data, importDirOff + 4);
                if (importRVA > 0 && importSize > 0)
                {
                    if (!RVAExistsInSection(data, importRVA, numSections, sectionTableOff))
                    {
                        BitConverter.GetBytes((uint)0).CopyTo(data, importDirOff);
                        BitConverter.GetBytes((uint)0).CopyTo(data, importDirOff + 4);
                        report.Warnings.Add($"Import directory RVA 0x{importRVA:X} not in any section - cleared");
                    }
                }
            }

            // Validate export directory
            int exportDirOff = dataDirBase + 0 * 8;
            if (exportDirOff + 8 <= data.Length)
            {
                uint exportRVA = BitConverter.ToUInt32(data, exportDirOff);
                uint exportSize = BitConverter.ToUInt32(data, exportDirOff + 4);
                if (exportRVA > 0 && exportSize > 0)
                {
                    if (!RVAExistsInSection(data, exportRVA, numSections, sectionTableOff))
                    {
                        BitConverter.GetBytes((uint)0).CopyTo(data, exportDirOff);
                        BitConverter.GetBytes((uint)0).CopyTo(data, exportDirOff + 4);
                        report.Warnings.Add($"Export directory RVA 0x{exportRVA:X} not in any section - cleared");
                    }
                }
            }

            // Validate exception directory (.pdata for x64)
            if (is64)
            {
                int excDirOff = dataDirBase + 3 * 8;
                if (excDirOff + 8 <= data.Length)
                {
                    uint excRVA = BitConverter.ToUInt32(data, excDirOff);
                    if (excRVA > 0 && !RVAExistsInSection(data, excRVA, numSections, sectionTableOff))
                    {
                        BitConverter.GetBytes((uint)0).CopyTo(data, excDirOff);
                        BitConverter.GetBytes((uint)0).CopyTo(data, excDirOff + 4);
                        report.Warnings.Add($"Exception directory RVA 0x{excRVA:X} not in any section - cleared");
                    }
                }
            }

            // Validate resource directory
            int rsrcDirOff = dataDirBase + 2 * 8;
            if (rsrcDirOff + 8 <= data.Length)
            {
                uint rsrcRVA = BitConverter.ToUInt32(data, rsrcDirOff);
                uint rsrcSize = BitConverter.ToUInt32(data, rsrcDirOff + 4);
                if (rsrcRVA > 0 && rsrcSize > 0x10000000)
                {
                    // Unreasonably large resource section - likely corrupt
                    BitConverter.GetBytes((uint)0).CopyTo(data, rsrcDirOff);
                    BitConverter.GetBytes((uint)0).CopyTo(data, rsrcDirOff + 4);
                    report.Warnings.Add($"Resource directory size 0x{rsrcSize:X} unreasonably large - cleared");
                }
            }

            // Validate TLS directory
            int tlsDirOff = dataDirBase + 9 * 8;
            if (tlsDirOff + 8 <= data.Length)
            {
                uint tlsRVA = BitConverter.ToUInt32(data, tlsDirOff);
                if (tlsRVA > 0 && !RVAExistsInSection(data, tlsRVA, numSections, sectionTableOff))
                {
                    BitConverter.GetBytes((uint)0).CopyTo(data, tlsDirOff);
                    BitConverter.GetBytes((uint)0).CopyTo(data, tlsDirOff + 4);
                    report.Warnings.Add($"TLS directory RVA 0x{tlsRVA:X} not in any section - cleared");
                }
            }

            // Validate debug directory
            int debugDirOff = dataDirBase + 6 * 8;
            if (debugDirOff + 8 <= data.Length)
            {
                uint debugRVA = BitConverter.ToUInt32(data, debugDirOff);
                if (debugRVA > 0 && !RVAExistsInSection(data, debugRVA, numSections, sectionTableOff))
                {
                    BitConverter.GetBytes((uint)0).CopyTo(data, debugDirOff);
                    BitConverter.GetBytes((uint)0).CopyTo(data, debugDirOff + 4);
                    report.Fixes.Add("Cleared invalid debug directory");
                }
            }

            // Set NumberOfRvaAndSizes to 16
            int numRvaOff = e_lfanew + (is64 ? 132 : 116);
            if (numRvaOff + 4 <= data.Length)
            {
                uint current = BitConverter.ToUInt32(data, numRvaOff);
                if (current != 16)
                {
                    BitConverter.GetBytes((uint)16).CopyTo(data, numRvaOff);
                    report.Fixes.Add($"Fixed NumberOfRvaAndSizes from {current} to 16");
                }
            }
        }

        // ---- Memory to File Layout Conversion ----

        private static byte[] ConvertMemoryToFileLayout(byte[] memDump, int e_lfanew, ushort numSections,
            int sectionTableOff, uint fileAlignment, uint sectionAlignment, FixReport report)
        {
            // Calculate file size
            uint fileSize = Align((uint)(sectionTableOff + numSections * 40), fileAlignment);
            var sectionData = new List<(uint rawOff, uint rawSize, uint virtAddr, uint virtSize, byte[] data)>();

            for (int i = 0; i < numSections; i++)
            {
                int off = sectionTableOff + i * 40;
                if (off + 40 > memDump.Length) break;

                string name = Encoding.ASCII.GetString(memDump, off, 8).TrimEnd('\0');
                uint virtualSize = BitConverter.ToUInt32(memDump, off + 8);
                uint virtualAddr = BitConverter.ToUInt32(memDump, off + 12);
                uint rawSize = BitConverter.ToUInt32(memDump, off + 16);

                if (virtualAddr == 0 || (virtualSize == 0 && rawSize == 0)) continue;

                // Read section data from memory layout
                int readSize = (int)Math.Min(virtualSize > 0 ? virtualSize : rawSize, memDump.Length - virtualAddr);
                if (readSize <= 0 || virtualAddr >= (ulong)memDump.Length) continue;

                byte[] secBytes = new byte[readSize];
                Array.Copy(memDump, virtualAddr, secBytes, 0, readSize);

                uint alignedRawSize = Align((uint)readSize, fileAlignment);
                uint rawOff = fileSize;
                fileSize += alignedRawSize;

                sectionData.Add((rawOff, alignedRawSize, virtualAddr, virtualSize, secBytes));

                // Update section header with file offsets
                BitConverter.GetBytes(alignedRawSize).CopyTo(memDump, off + 16); // SizeOfRawData
                BitConverter.GetBytes(rawOff).CopyTo(memDump, off + 20); // PointerToRawData
            }

            // Build output file
            byte[] filePE = new byte[fileSize];

            // Copy headers
            int headerCopySize = Math.Min((int)Align((uint)(sectionTableOff + numSections * 40), fileAlignment), memDump.Length);
            Array.Copy(memDump, 0, filePE, 0, headerCopySize);

            // Copy section data
            foreach (var (rawOff, rawSize, virtAddr, virtSize, data) in sectionData)
            {
                if (rawOff + data.Length <= filePE.Length)
                    Array.Copy(data, 0, filePE, rawOff, data.Length);
            }

            report.Fixes.Add($"Converted memory layout to file layout ({sectionData.Count} sections, {fileSize} bytes)");
            return filePE;
        }

        // ---- DOS Header Reconstruction ----

        private static void ReconstructDOSHeader(byte[] data)
        {
            // Minimal DOS header
            byte[] dosHeader = new byte[64];
            dosHeader[0] = 0x4D; dosHeader[1] = 0x5A; // MZ
            // Set e_lfanew to 0x80 (standard location)
            BitConverter.GetBytes(0x80).CopyTo(dosHeader, 60);

            // Copy DOS stub (minimal "This program..." message)
            byte[] stub = new byte[0x80 - 64];
            // Minimal stub: just enough to make PE valid
            for (int i = 0; i < stub.Length; i++) stub[i] = 0;

            // Write header
            Array.Copy(dosHeader, 0, data, 0, Math.Min(dosHeader.Length, data.Length));
            if (data.Length > 64)
                Array.Copy(stub, 0, data, 64, Math.Min(stub.Length, data.Length - 64));
        }

        private static int FindPESignature(byte[] data)
        {
            for (int i = 0x40; i < Math.Min(data.Length - 4, 0x1000); i += 4)
            {
                if (BitConverter.ToUInt32(data, i) == 0x00004550)
                    return i;
            }
            return -1;
        }

        // ---- Checksum Calculation ----

        private static uint CalculatePEChecksum(byte[] data, int e_lfanew)
        {
            // Standard PE checksum: sum all 16-bit words, fold carries, subtract checksum field
            uint checksum = 0;
            int checksumOff = e_lfanew + 88;

            for (int i = 0; i < data.Length - 1; i += 2)
            {
                if (i == checksumOff || i == checksumOff + 2) continue; // Skip checksum field
                ushort word = BitConverter.ToUInt16(data, i);
                checksum += word;
                if (checksum > 0xFFFF)
                    checksum = (checksum & 0xFFFF) + (checksum >> 16);
            }
            if (data.Length % 2 != 0)
                checksum += data[data.Length - 1];

            while (checksum >> 16 != 0)
                checksum = (checksum & 0xFFFF) + (checksum >> 16);

            return checksum + (uint)data.Length;
        }

        // ---- Helpers ----

        private static uint CalculateSizeOfImage(byte[] data, int sectionTableOff, ushort numSections, uint sectionAlignment)
        {
            uint maxEnd = 0;
            for (int i = 0; i < numSections; i++)
            {
                int off = sectionTableOff + i * 40;
                if (off + 40 > data.Length) break;
                uint va = BitConverter.ToUInt32(data, off + 12);
                uint vs = BitConverter.ToUInt32(data, off + 8);
                uint end = Align(va + Math.Max(vs, 1), sectionAlignment);
                if (end > maxEnd) maxEnd = end;
            }
            return maxEnd;
        }

        private static bool RVAExistsInSection(byte[] data, uint rva, ushort numSections, int sectionTableOff)
        {
            for (int i = 0; i < numSections; i++)
            {
                int off = sectionTableOff + i * 40;
                if (off + 40 > data.Length) break;
                uint va = BitConverter.ToUInt32(data, off + 12);
                uint vs = BitConverter.ToUInt32(data, off + 8);
                uint rs = BitConverter.ToUInt32(data, off + 16);
                uint maxEnd = va + Math.Max(vs, rs);
                if (rva >= va && rva < maxEnd) return true;
            }
            return false;
        }

        private static uint Align(uint value, uint alignment)
        {
            if (alignment == 0) return value;
            return ((value + alignment - 1) / alignment) * alignment;
        }
    }
}
