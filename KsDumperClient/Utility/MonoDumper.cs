using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using KsDumperClient.Driver;
using KsDumperClient.PE;

namespace KsDumperClient.Utility
{
    public static class MonoDumper
    {
        public struct MonoDumpResult
        {
            public int AssembliesFound;
            public int AssembliesDumped;
            public string OutputDirectory;
            public List<string> DumpedFiles;
            public List<string> FailedModules;
            public List<StringDecryptor.DecryptionResult> DecryptedStrings;
            public List<StringDecryptor.StackString> StackStrings;
        }

        public static MonoDumpResult DumpManagedAssemblies(
            IMemoryReader reader,
            int processId,
            ModuleSummary[] allModules,
            ProcessDumper dumper,
            string outputDir,
            Action<string> log)
        {
            var managedModules = EngineDetector.FindManagedAssemblies(allModules);
            var result = new MonoDumpResult
            {
                AssembliesFound = managedModules.Count,
                AssembliesDumped = 0,
                OutputDirectory = outputDir,
                DumpedFiles = new List<string>(),
                FailedModules = new List<string>(),
                DecryptedStrings = new List<StringDecryptor.DecryptionResult>(),
                StackStrings = new List<StringDecryptor.StackString>()
            };

            log($"Found {managedModules.Count} managed assemblies");
            Directory.CreateDirectory(outputDir);

            // Phase 1: Dump each managed assembly as PE
            foreach (var mod in managedModules)
            {
                try
                {
                    var modPS = new ProcessSummary(processId, "mono_process",
                        mod.BaseAddress, mod.FileName, mod.ImageSize, mod.EntryPoint);

                    if (dumper.DumpProcess(modPS, out PEFile peFile, rebuildImports: false))
                    {
                        string fileName = mod.ModuleName.Replace(".dll", "_dump.dll");
                        string savePath = Path.Combine(outputDir, fileName);
                        peFile.SaveToDisk(savePath);
                        result.DumpedFiles.Add(savePath);
                        result.AssembliesDumped++;
                        log($"  Dumped: {mod.ModuleName}");

                        // Phase 2: Run string decryption on the dumped assembly
                        AnalyzeAssembly(reader, processId, mod, outputDir, result, log);
                    }
                    else
                    {
                        result.FailedModules.Add(mod.ModuleName);
                        log($"  FAILED: {mod.ModuleName}");
                    }
                }
                catch (Exception ex)
                {
                    result.FailedModules.Add(mod.ModuleName);
                    log($"  ERROR: {mod.ModuleName}: {ex.Message}");
                }
            }

            // Phase 3: Scan Mono runtime DLL for encrypted strings
            ScanMonoRuntime(reader, processId, allModules, outputDir, result, log);

            // Phase 4: Extract .NET string table from assemblies
            ExtractDotNetStringTables(outputDir, result, log);

            // Write comprehensive summary
            WriteSummary(outputDir, result, processId, log);

            return result;
        }

        private static void AnalyzeAssembly(IMemoryReader reader, int processId, ModuleSummary mod,
            string outputDir, MonoDumpResult result, Action<string> log)
        {
            try
            {
                byte[] peHeader = ReadBytes(reader, processId, mod.BaseAddress, 0x400);
                if (peHeader == null || peHeader.Length < 64) return;
                if (BitConverter.ToUInt16(peHeader, 0) != 0x5A4D) return;

                int e_lfanew = BitConverter.ToInt32(peHeader, 60);
                if (e_lfanew + 24 > peHeader.Length) return;

                ushort numSections = BitConverter.ToUInt16(peHeader, e_lfanew + 6);
                ushort sizeOfOptHdr = BitConverter.ToUInt16(peHeader, e_lfanew + 20);
                int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

                for (int s = 0; s < numSections; s++)
                {
                    int secOff = sectionTableOff + s * 40;
                    if (secOff + 40 > peHeader.Length) break;

                    string secName = Encoding.ASCII.GetString(peHeader, secOff, 8).TrimEnd('\0');
                    uint virtualSize = BitConverter.ToUInt32(peHeader, secOff + 8);
                    uint virtualAddr = BitConverter.ToUInt32(peHeader, secOff + 12);
                    uint characteristics = BitConverter.ToUInt32(peHeader, secOff + 36);
                    if (virtualSize == 0 || virtualAddr == 0) continue;

                    int readSize = (int)Math.Min(virtualSize, 0x8000);
                    byte[] secData = ReadBytes(reader, processId, mod.BaseAddress + virtualAddr, readSize);
                    if (secData == null) continue;

                    ulong secBase = mod.BaseAddress + virtualAddr;
                    bool isCode = (characteristics & 0x20) != 0;

                    if (!isCode)
                    {
                        // Decrypt strings in data sections
                        var xorStrings = StringDecryptor.FindXorEncryptedStrings(secData, secBase);
                        result.DecryptedStrings.AddRange(xorStrings);

                        var addsubStrings = StringDecryptor.FindAddSubEncryptedStrings(secData, secBase);
                        result.DecryptedStrings.AddRange(addsubStrings);

                        var rotStrings = StringDecryptor.FindRotEncryptedStrings(secData, secBase);
                        result.DecryptedStrings.AddRange(rotStrings);

                        var b64Strings = StringDecryptor.FindBase64Strings(secData, secBase);
                        result.DecryptedStrings.AddRange(b64Strings);
                    }

                    if (isCode)
                    {
                        var stackStrs = StringDecryptor.FindStackStrings(secData, secBase);
                        result.StackStrings.AddRange(stackStrs);
                    }
                }
            }
            catch (Exception ex)
            {
                log($"  Analysis error for {mod.ModuleName}: {ex.Message}");
            }
        }

        private static void ScanMonoRuntime(IMemoryReader reader, int processId, ModuleSummary[] allModules,
            string outputDir, MonoDumpResult result, Action<string> log)
        {
            // Find mono runtime DLL
            ModuleSummary monoDll = null;
            foreach (var mod in allModules)
            {
                string name = (mod.ModuleName ?? "").ToLowerInvariant();
                if (name == "mono.dll" || name == "mono-2.0-bdwgc.dll" || name == "mono-2.0-sgen.dll")
                {
                    monoDll = mod;
                    break;
                }
            }

            if (monoDll == null)
            {
                log("  Mono runtime DLL not found in module list");
                return;
            }

            log($"  Scanning Mono runtime: {monoDll.ModuleName} (0x{monoDll.ImageSize:X} bytes)");

            try
            {
                // Read Mono runtime code section for decryptor patterns
                byte[] peHeader = ReadBytes(reader, processId, monoDll.BaseAddress, 0x400);
                if (peHeader == null || BitConverter.ToUInt16(peHeader, 0) != 0x5A4D) return;

                int e_lfanew = BitConverter.ToInt32(peHeader, 60);
                ushort numSections = BitConverter.ToUInt16(peHeader, e_lfanew + 6);
                ushort sizeOfOptHdr = BitConverter.ToUInt16(peHeader, e_lfanew + 20);
                int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

                for (int s = 0; s < numSections; s++)
                {
                    int secOff = sectionTableOff + s * 40;
                    if (secOff + 40 > peHeader.Length) break;

                    uint characteristics = BitConverter.ToUInt32(peHeader, secOff + 36);
                    uint virtualSize = BitConverter.ToUInt32(peHeader, secOff + 8);
                    uint virtualAddr = BitConverter.ToUInt32(peHeader, secOff + 12);
                    if (virtualSize == 0 || virtualAddr == 0) continue;

                    bool isCode = (characteristics & 0x20) != 0;
                    if (!isCode) continue;

                    int readSize = (int)Math.Min(virtualSize, 0x8000);
                    byte[] codeData = ReadBytes(reader, processId, monoDll.BaseAddress + virtualAddr, readSize);
                    if (codeData == null) continue;

                    var patterns = StringDecryptor.FindDecryptorPatterns(codeData, monoDll.BaseAddress + virtualAddr);
                    if (patterns.Count > 0)
                    {
                        log($"    Mono runtime decryptor patterns: {patterns.Count}");
                        // Store as stack strings for the report
                        foreach (var p in patterns)
                        {
                            result.StackStrings.Add(new StringDecryptor.StackString
                            {
                                Address = p.Address,
                                Value = $"[{p.PatternName}] {p.Description}",
                                Length = p.PatternName.Length
                            });
                        }
                    }
                }

                // Try to find Mono's string intern table
                FindMonoInternTable(reader, processId, monoDll, result, log);
            }
            catch (Exception ex)
            {
                log($"  Mono runtime scan error: {ex.Message}");
            }
        }

        private static void FindMonoInternTable(IMemoryReader reader, int processId, ModuleSummary monoDll,
            MonoDumpResult result, Action<string> log)
        {
            // Mono stores interned strings in a hash table accessible via mono_string_intern
            // We scan the .data section for clusters of UTF-8 strings that look like interned strings
            byte[] peHeader = ReadBytes(reader, processId, monoDll.BaseAddress, 0x400);
            if (peHeader == null) return;

            int e_lfanew = BitConverter.ToInt32(peHeader, 60);
            ushort numSections = BitConverter.ToUInt16(peHeader, e_lfanew + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(peHeader, e_lfanew + 20);
            int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

            for (int s = 0; s < numSections; s++)
            {
                int secOff = sectionTableOff + s * 40;
                if (secOff + 40 > peHeader.Length) break;

                string secName = Encoding.ASCII.GetString(peHeader, secOff, 8).TrimEnd('\0');
                if (secName != ".data" && secName != ".rdata") continue;

                uint virtualSize = BitConverter.ToUInt32(peHeader, secOff + 8);
                uint virtualAddr = BitConverter.ToUInt32(peHeader, secOff + 12);
                if (virtualSize == 0 || virtualAddr == 0) continue;

                int readSize = (int)Math.Min(virtualSize, 0x8000);
                byte[] data = ReadBytes(reader, processId, monoDll.BaseAddress + virtualAddr, readSize);
                if (data == null) continue;

                // Find Unicode strings in Mono data sections (Mono uses UTF-16 internally)
                var unicodeStrings = StringDecryptor.FindUnicodeStrings(data, monoDll.BaseAddress + virtualAddr, 6);
                foreach (var (addr, val) in unicodeStrings)
                {
                    result.StackStrings.Add(new StringDecryptor.StackString
                    {
                        Address = addr,
                        Value = val,
                        Length = val.Length
                    });
                }
            }
        }

        private static void ExtractDotNetStringTables(string outputDir, MonoDumpResult result, Action<string> log)
        {
            // Parse #US (User Strings) heap from dumped .NET assemblies
            foreach (var filePath in result.DumpedFiles)
            {
                try
                {
                    byte[] peBytes = File.ReadAllBytes(filePath);
                    var strings = ExtractUserStringsHeap(peBytes);

                    if (strings.Count > 0)
                    {
                        string usPath = Path.Combine(outputDir,
                            Path.GetFileNameWithoutExtension(filePath) + "_user_strings.txt");

                        using (var w = new StreamWriter(usPath))
                        {
                            w.WriteLine($"// .NET User Strings from {Path.GetFileName(filePath)}");
                            w.WriteLine($"// Extracted from #US heap");
                            w.WriteLine($"// Count: {strings.Count}");
                            w.WriteLine();
                            foreach (var (offset, str) in strings)
                                w.WriteLine($"[0x{offset:X}] \"{str}\"");
                        }

                        log($"  Extracted {strings.Count} .NET user strings from {Path.GetFileName(filePath)}");
                    }
                }
                catch (Exception ex)
                {
                    log($"  .NET string extraction failed for {Path.GetFileName(filePath)}: {ex.Message}");
                }
            }
        }

        private static List<(int offset, string value)> ExtractUserStringsHeap(byte[] peBytes)
        {
            var results = new List<(int, string)>();
            if (peBytes == null || peBytes.Length < 64) return results;

            if (BitConverter.ToUInt16(peBytes, 0) != 0x5A4D) return results;
            int e_lfanew = BitConverter.ToInt32(peBytes, 60);
            if (e_lfanew + 24 > peBytes.Length) return results;
            if (BitConverter.ToUInt32(peBytes, e_lfanew) != 0x00004550) return results;

            ushort magic = BitConverter.ToUInt16(peBytes, e_lfanew + 24);
            bool is64 = magic == 0x20b;

            // CLI descriptor is DataDirectory[14]
            int dataDirOff = is64 ? e_lfanew + 24 + 112 : e_lfanew + 24 + 96;
            int cliDirIdx = dataDirOff + 14 * 8;
            if (cliDirIdx + 8 > peBytes.Length) return results;

            uint cliRVA = BitConverter.ToUInt32(peBytes, cliDirIdx);
            if (cliRVA == 0) return results;

            int cliOff = RvaToFileOffset(peBytes, e_lfanew, cliRVA);
            if (cliOff <= 0 || cliOff + 72 > peBytes.Length) return results;

            // Metadata RVA is at CLI header offset 8
            uint metaRVA = BitConverter.ToUInt32(peBytes, cliOff + 8);
            uint metaSize = BitConverter.ToUInt32(peBytes, cliOff + 12);
            if (metaRVA == 0 || metaSize == 0) return results;

            int metaOff = RvaToFileOffset(peBytes, e_lfanew, metaRVA);
            if (metaOff <= 0 || metaOff + 20 > peBytes.Length) return results;
            if (BitConverter.ToUInt32(peBytes, metaOff) != 0x424A5342) return results; // BSJB

            // Parse stream headers to find #US
            int p = metaOff + 12;
            if (p + 4 > peBytes.Length) return results;
            int versionLen = BitConverter.ToInt32(peBytes, p);
            p += 4 + versionLen + 2; // skip version + flags
            if (p + 2 > peBytes.Length) return results;
            ushort streamCount = BitConverter.ToUInt16(peBytes, p);
            p += 2;

            for (int s = 0; s < streamCount && p + 8 <= peBytes.Length; s++)
            {
                uint streamOff = BitConverter.ToUInt32(peBytes, p);
                uint streamSize = BitConverter.ToUInt32(peBytes, p + 4);
                p += 8;

                int nameStart = p;
                while (p < peBytes.Length && peBytes[p] != 0) p++;
                string name = Encoding.ASCII.GetString(peBytes, nameStart, p - nameStart);
                p++;
                while (p % 4 != 0 && p < peBytes.Length) p++;

                if (name == "#US" && streamSize > 1)
                {
                    int usOff = metaOff + (int)streamOff;
                    if (usOff >= 0 && usOff + streamSize <= peBytes.Length)
                    {
                        // Parse #US heap: each entry is a length-prefixed UTF-16 string
                        int pos = usOff + 1; // skip first null byte
                        while (pos < usOff + streamSize)
                        {
                            int entryOffset = pos - usOff;
                            // Read compressed length
                            int len;
                            byte first = peBytes[pos];
                            if ((first & 0x80) == 0) { len = first; pos += 1; }
                            else if ((first & 0xC0) == 0x80) { if (pos + 1 >= peBytes.Length) break; len = ((first & 0x3F) << 8) | peBytes[pos + 1]; pos += 2; }
                            else { if (pos + 3 >= peBytes.Length) break; len = ((first & 0x1F) << 24) | (peBytes[pos + 1] << 16) | (peBytes[pos + 2] << 8) | peBytes[pos + 3]; pos += 4; }

                            if (len <= 0 || pos + len > usOff + streamSize) break;

                            // String is UTF-16, last byte is a flag
                            int strBytes = len - 1;
                            if (strBytes >= 2 && strBytes % 2 == 0)
                            {
                                try
                                {
                                    string str = Encoding.Unicode.GetString(peBytes, pos, strBytes);
                                    // Filter: only keep strings with reasonable text content
                                    if (str.Length >= 2 && str.All(c => c >= 0x20 || c == '\n' || c == '\r' || c == '\t'))
                                        results.Add((entryOffset, str));
                                }
                                catch { }
                            }

                            pos += len;
                        }
                    }
                    break;
                }
            }

            return results;
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
                    return (int)(secRawOff + (rva - secVA));
            }
            return -1;
        }

        private static void WriteSummary(string outputDir, MonoDumpResult result, int processId, Action<string> log)
        {
            string summaryPath = Path.Combine(outputDir, "mono_dump_summary.txt");
            using (var w = new StreamWriter(summaryPath))
            {
                w.WriteLine("// KsDumper - Mono Assembly Dump Summary");
                w.WriteLine($"// Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                w.WriteLine($"// Process ID: {processId}");
                w.WriteLine();
                w.WriteLine($"Assemblies Found: {result.AssembliesFound}");
                w.WriteLine($"Assemblies Dumped: {result.AssembliesDumped}");
                w.WriteLine($"Failed: {result.FailedModules.Count}");
                w.WriteLine($"Decrypted Strings: {result.DecryptedStrings.Count}");
                w.WriteLine($"Stack Strings: {result.StackStrings.Count}");
                w.WriteLine();

                w.WriteLine("// Dumped Files:");
                foreach (var file in result.DumpedFiles)
                    w.WriteLine($"//   {Path.GetFileName(file)}");

                if (result.DecryptedStrings.Count > 0)
                {
                    w.WriteLine();
                    w.WriteLine("// Decrypted Strings:");
                    foreach (var r in result.DecryptedStrings)
                        w.WriteLine($"//   [0x{r.Address:X}] [{r.Method}] \"{r.Decrypted}\"");
                }
            }
            log($"Summary saved: {summaryPath}");
        }

        private static byte[] ReadBytes(IMemoryReader driver, int processId, ulong address, int size)
        {
            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, buf, size)) return null;
                byte[] data = new byte[size];
                System.Runtime.InteropServices.Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }
    }
}
