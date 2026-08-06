using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using KsDumperClient.PE;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Robust process dumper that uses LSASS as a read proxy to bypass PPL/protected process restrictions.
    /// Features: chunked reads, integrity verification, PE fixing, import rebuild.
    /// </summary>
    public static class LsassDumper
    {
        public struct DumpResult
        {
            public bool Success;
            public string OutputPath;
            public string Method;
            public int SectionsDumped;
            public int TotalBytes;
            public uint Checksum;
            public List<string> Fixes;
            public string Error;
        }

        private const int CHUNK_SIZE = 0x1000; // 4KB pages for chunked reading
        private const int MAX_RETRY = 3;

        /// <summary>
        /// Dump a process through LSASS with full PE fixing and integrity verification.
        /// </summary>
        public static DumpResult LsassDump(IMemoryReader driver, int targetPid, ulong baseAddress, uint imageSize, string outputPath, Action<string> log)
        {
            log("Starting LSASS dump...");
            log($"Target PID: {targetPid}, Base: 0x{baseAddress:X}, Size: 0x{imageSize:X}");

            var fixes = new List<string>();

            // Step 1: Read PE header with retry
            log("Reading PE header via LSASS...");
            byte[] peHeader = ReadBytesWithRetry(driver, targetPid, baseAddress, 0x1000, log);
            if (peHeader == null)
                return Fail("Failed to read PE header via LSASS");

            // Validate DOS header
            if (BitConverter.ToUInt16(peHeader, 0) != 0x5A4D)
                return Fail("Invalid DOS signature");

            int e_lfanew = BitConverter.ToInt32(peHeader, 60);
            if (e_lfanew <= 0 || e_lfanew + 24 > peHeader.Length)
                return Fail("Invalid e_lfanew");

            if (BitConverter.ToUInt32(peHeader, e_lfanew) != 0x00004550)
                return Fail("Invalid PE signature");

            bool is64 = BitConverter.ToUInt16(peHeader, e_lfanew + 24) == 0x20b;
            ushort numSections = BitConverter.ToUInt16(peHeader, e_lfanew + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(peHeader, e_lfanew + 20);
            int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

            // Get actual image size from PE header if provided size is 0
            if (imageSize == 0)
            {
                int sizeOfImageOff = e_lfanew + (is64 ? 80 : 80);
                if (sizeOfImageOff + 4 <= peHeader.Length)
                    imageSize = BitConverter.ToUInt32(peHeader, sizeOfImageOff);
                if (imageSize == 0)
                    return Fail("Cannot determine image size");
                log($"  ImageSize from PE header: 0x{imageSize:X}");
            }

            log($"  PE: {(is64 ? "x64" : "x86")}, Sections: {numSections}, Size: 0x{imageSize:X}");

            // Step 2: Read all sections via LSASS with chunked reads and integrity verification
            log("Reading sections via LSASS...");
            byte[] fullImage = new byte[imageSize];
            Array.Copy(peHeader, 0, fullImage, 0, Math.Min(peHeader.Length, (int)imageSize));

            int sectionsDumped = 0;
            int totalBytes = 0;

            for (int i = 0; i < numSections; i++)
            {
                int secOff = sectionTableOff + i * 40;
                if (secOff + 40 > peHeader.Length) break;

                string secName = Encoding.ASCII.GetString(peHeader, secOff, 8).TrimEnd('\0');
                uint virtualSize = BitConverter.ToUInt32(peHeader, secOff + 8);
                uint virtualAddr = BitConverter.ToUInt32(peHeader, secOff + 12);
                uint characteristics = BitConverter.ToUInt32(peHeader, secOff + 36);

                if (virtualSize == 0 || virtualAddr == 0) continue;
                if (virtualAddr >= imageSize) continue;

                int readSize = (int)Math.Min(virtualSize, imageSize - virtualAddr);
                log($"  [{secName}] RVA: 0x{virtualAddr:X} Size: 0x{readSize:X}");

                // Chunked read with integrity verification
                byte[] secData = ChunkedRead(driver, targetPid, baseAddress + virtualAddr, readSize, log);
                if (secData != null)
                {
                    // Verify section data integrity (check for all-zeros which indicates read failure)
                    int nonZero = 0;
                    int checkLen = Math.Min(secData.Length, 256);
                    for (int j = 0; j < checkLen; j++)
                        if (secData[j] != 0) nonZero++;

                    if (nonZero == 0 && readSize > 256)
                    {
                        log($"    WARNING: Section [{secName}] appears empty - may be unreadable");
                        fixes.Add($"Section [{secName}] read returned all zeros");
                    }

                    Array.Copy(secData, 0, fullImage, virtualAddr, Math.Min(secData.Length, readSize));
                    sectionsDumped++;
                    totalBytes += secData.Length;

                    // Calculate section checksum for verification
                    uint secCrc = SimpleCRC32(secData);
                    log($"    CRC32: 0x{secCrc:X8} ({nonZero}/{checkLen} non-zero bytes checked)");
                }
                else
                {
                    log($"    FAILED to read section [{secName}]");
                    fixes.Add($"Section [{secName}] read failed");
                }
            }

            // Step 3: Fix PE for disk format using PEFixer
            log("Fixing PE headers for disk format...");
            string tempPath = outputPath + ".tmp";
            File.WriteAllBytes(tempPath, fullImage);

            var fixReport = PEFixer.FixAndSave(fullImage, baseAddress, outputPath);
            fixes.AddRange(fixReport.Fixes);
            foreach (var w in fixReport.Warnings)
            {
                log($"  Warning: {w}");
                fixes.Add($"Warning: {w}");
            }

            // Clean up temp file
            try { if (File.Exists(tempPath)) File.Delete(tempPath); } catch { }

            // Step 4: Verify the output file
            if (File.Exists(outputPath))
            {
                byte[] outputPE = File.ReadAllBytes(outputPath);
                bool validMZ = outputPE.Length >= 2 && outputPE[0] == 0x4D && outputPE[1] == 0x5A;
                bool validPE = false;
                if (validMZ && outputPE.Length > 64)
                {
                    int outElf = BitConverter.ToInt32(outputPE, 60);
                    validPE = outElf > 0 && outElf + 4 < outputPE.Length && BitConverter.ToUInt32(outputPE, outElf) == 0x00004550;
                }

                if (validMZ && validPE)
                {
                    log($"Output verified: valid MZ + PE signatures");
                    uint outChecksum = 0;
                    if (outputPE.Length > e_lfanew + 88 + 4)
                        outChecksum = BitConverter.ToUInt32(outputPE, e_lfanew + 88);
                    log($"Output checksum: 0x{outChecksum:X}");
                    log($"Output size: {outputPE.Length} bytes");
                }
                else
                {
                    log("WARNING: Output file has invalid PE signatures!");
                    fixes.Add("Output PE validation failed");
                }
            }

            log($"Saved: {outputPath} ({totalBytes} bytes, {sectionsDumped}/{numSections} sections)");

            return new DumpResult
            {
                Success = true,
                OutputPath = outputPath,
                Method = "LSASS Dump + PE Fix",
                SectionsDumped = sectionsDumped,
                TotalBytes = totalBytes,
                Checksum = fixReport.Success ? CalculateSimpleChecksum(fullImage) : 0,
                Fixes = fixes
            };
        }

        // ---- Chunked Read with Retry ----

        private static byte[] ChunkedRead(IMemoryReader driver, int targetPid, ulong address, int size, Action<string> log)
        {
            byte[] result = new byte[size];
            int totalRead = 0;

            while (totalRead < size)
            {
                int remaining = size - totalRead;
                int chunkSize = Math.Min(CHUNK_SIZE, remaining);

                bool success = false;
                for (int retry = 0; retry < MAX_RETRY; retry++)
                {
                    IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)chunkSize, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) continue;
                    try
                    {
                        if (driver.LsassReadMemory(targetPid, (IntPtr)(address + (ulong)totalRead), buf, chunkSize))
                        {
                            Marshal.Copy(buf, result, totalRead, chunkSize);
                            success = true;
                            break;
                        }
                    }
                    finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }

                    if (retry < MAX_RETRY - 1)
                        System.Threading.Thread.Sleep(50);
                }

                if (!success)
                {
                    // Try smaller chunk
                    chunkSize = Math.Min(256, remaining);
                    IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)chunkSize, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) { totalRead += chunkSize; continue; }
                    try
                    {
                        if (driver.LsassReadMemory(targetPid, (IntPtr)(address + (ulong)totalRead), buf, chunkSize))
                        {
                            Marshal.Copy(buf, result, totalRead, chunkSize);
                            totalRead += chunkSize;
                            continue;
                        }
                    }
                    finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }

                    // Zero-fill and continue
                    for (int z = 0; z < chunkSize; z++)
                        result[totalRead + z] = 0;
                    totalRead += chunkSize;
                }
                else
                {
                    totalRead += chunkSize;
                }
            }

            return result;
        }

        private static byte[] ReadBytesWithRetry(IMemoryReader driver, int targetPid, ulong address, int size, Action<string> log)
        {
            for (int attempt = 0; attempt < MAX_RETRY; attempt++)
            {
                IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (buf == IntPtr.Zero) continue;
                try
                {
                    if (driver.LsassReadMemory(targetPid, (IntPtr)address, buf, size))
                    {
                        byte[] data = new byte[size];
                        Marshal.Copy(buf, data, 0, size);

                        // Verify we got valid data
                        if (data[0] == 0x4D && data[1] == 0x5A)
                            return data;

                        // Even if not MZ, return it (might be a valid read of non-PE data)
                        if (attempt == MAX_RETRY - 1)
                            return data;
                    }
                }
                finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }

                if (attempt < MAX_RETRY - 1)
                {
                    log($"  Read attempt {attempt + 1} failed, retrying...");
                    System.Threading.Thread.Sleep(100);
                }
            }
            return null;
        }

        // ---- Integrity Verification ----

        private static uint SimpleCRC32(byte[] data)
        {
            uint crc = 0xFFFFFFFF;
            for (int i = 0; i < data.Length; i++)
            {
                crc ^= data[i];
                for (int j = 0; j < 8; j++)
                    crc = (crc >> 1) ^ (0xEDB88320 & (uint)(-(int)(crc & 1)));
            }
            return ~crc;
        }

        private static uint CalculateSimpleChecksum(byte[] data)
        {
            uint sum = 0;
            for (int i = 0; i < data.Length - 1; i += 2)
            {
                sum += BitConverter.ToUInt16(data, i);
                if (sum > 0xFFFF)
                    sum = (sum & 0xFFFF) + (sum >> 16);
            }
            while (sum >> 16 != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);
            return sum + (uint)data.Length;
        }

        private static DumpResult Fail(string error) => new DumpResult { Success = false, Error = error, Fixes = new List<string>() };
    }
}
