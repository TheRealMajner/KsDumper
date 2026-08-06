using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class FileStringScanner
    {
        public struct FileScanResult
        {
            public string FileName;
            public string FilePath;
            public List<AdvancedStringDecryptor.DecryptedString> Strings;
            public List<StringDecryptor.StackString> StackStrings;
            public List<StringDecryptor.DecryptorPattern> Patterns;
            public List<(ulong address, string value)> UnicodeStrings;
            public string Summary;
        }

        public static FileScanResult ScanFile(string filePath, Action<string> log)
        {
            var empty = new FileScanResult { FileName = Path.GetFileName(filePath), FilePath = filePath,
                Strings = new List<AdvancedStringDecryptor.DecryptedString>(),
                StackStrings = new List<StringDecryptor.StackString>(),
                Patterns = new List<StringDecryptor.DecryptorPattern>(),
                UnicodeStrings = new List<(ulong, string)>()
            };

            if (!File.Exists(filePath))
            {
                log($"File not found: {filePath}");
                return empty;
            }

            byte[] fileBytes;
            try { fileBytes = File.ReadAllBytes(filePath); }
            catch (Exception ex) { log($"Failed to read file: {ex.Message}"); return empty; }

            string fileName = Path.GetFileName(filePath);
            log($"Loaded {fileName} ({fileBytes.Length / 1024} KB)");

            return ScanFileBytes(fileBytes, fileName, 0, msg => log(msg));
        }

        public static FileScanResult ScanFileBytes(byte[] fileBytes, string fileName, ulong imageBase, Action<string> log)
        {
            var result = new FileScanResult
            {
                FileName = fileName,
                Strings = new List<AdvancedStringDecryptor.DecryptedString>(),
                StackStrings = new List<StringDecryptor.StackString>(),
                Patterns = new List<StringDecryptor.DecryptorPattern>(),
                UnicodeStrings = new List<(ulong, string)>()
            };

            // Validate DOS header
            if (fileBytes == null || fileBytes.Length < 64)
            {
                log("File too small for PE header");
                return result;
            }

            if (BitConverter.ToUInt16(fileBytes, 0) != 0x5A4D)
            {
                log("Invalid DOS signature (not a PE file)");
                return result;
            }

            int e_lfanew = BitConverter.ToInt32(fileBytes, 60);
            if (e_lfanew <= 0 || e_lfanew + 24 > fileBytes.Length)
            {
                log("Invalid e_lfanew offset");
                return result;
            }

            if (BitConverter.ToUInt32(fileBytes, e_lfanew) != 0x00004550)
            {
                log("Invalid PE signature");
                return result;
            }

            // Read machine type and optional header
            ushort machine = BitConverter.ToUInt16(fileBytes, e_lfanew + 4);
            ushort numSections = BitConverter.ToUInt16(fileBytes, e_lfanew + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(fileBytes, e_lfanew + 20);
            int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

            // Determine image base from optional header
            bool is64 = false;
            if (sizeOfOptHdr > 0 && e_lfanew + 24 + 2 <= fileBytes.Length)
            {
                ushort magic = BitConverter.ToUInt16(fileBytes, e_lfanew + 24);
                is64 = magic == 0x20b;
            }

            if (imageBase == 0)
            {
                if (is64 && e_lfanew + 24 + 32 <= fileBytes.Length)
                    imageBase = BitConverter.ToUInt64(fileBytes, e_lfanew + 24 + 24);
                else if (!is64 && e_lfanew + 24 + 28 <= fileBytes.Length)
                    imageBase = BitConverter.ToUInt32(fileBytes, e_lfanew + 24 + 28);
                if (imageBase == 0)
                    imageBase = is64 ? 0x140000000UL : 0x400000UL;
            }

            log($"PE: {(is64 ? "x64" : "x86")}, {numSections} sections, ImageBase=0x{imageBase:X}");

            // Parse sections from disk layout
            for (int s = 0; s < numSections; s++)
            {
                try
                {
                    int secOff = sectionTableOff + s * 40;
                    if (secOff + 40 > fileBytes.Length) break;

                    string secName = Encoding.ASCII.GetString(fileBytes, secOff, 8).TrimEnd('\0');
                    uint virtualSize = BitConverter.ToUInt32(fileBytes, secOff + 8);
                    uint virtualAddr = BitConverter.ToUInt32(fileBytes, secOff + 12);
                    uint rawSize = BitConverter.ToUInt32(fileBytes, secOff + 16);
                    uint rawPtr = BitConverter.ToUInt32(fileBytes, secOff + 20);
                    uint characteristics = BitConverter.ToUInt32(fileBytes, secOff + 36);

                    if (rawSize == 0 || rawPtr == 0) continue;
                    if (rawPtr + rawSize > fileBytes.Length) continue;

                    bool isCode = (characteristics & 0x20) != 0;
                    int readSize = (int)Math.Min(rawSize, 0x10000); // 64KB max per section
                    byte[] secData = new byte[readSize];
                    Array.Copy(fileBytes, rawPtr, secData, 0, readSize);

                    ulong secBase = imageBase + virtualAddr;
                    log($"  [{secName}] {readSize / 1024}KB {(isCode ? "CODE" : "DATA")} @ VA 0x{virtualAddr:X}");

                    if (isCode)
                    {
                        // Stack strings
                        var stack = StringDecryptor.FindStackStrings(secData, secBase);
                        result.StackStrings.AddRange(stack);
                        if (stack.Count > 0) log($"    Stack strings: {stack.Count}");

                        // Decryptor patterns
                        var patterns = StringDecryptor.FindDecryptorPatterns(secData, secBase);
                        result.Patterns.AddRange(patterns);
                        if (patterns.Count > 0) log($"    Decryptor patterns: {patterns.Count}");
                    }
                    else
                    {
                        // XOR encrypted strings
                        var xor = StringDecryptor.FindXorEncryptedStrings(secData, secBase);
                        foreach (var r in xor)
                            result.Strings.Add(new AdvancedStringDecryptor.DecryptedString
                            {
                                Address = r.Address, Decrypted = r.Decrypted,
                                Method = r.Method, Confidence = 0.7,
                                Category = CategorizeString(r.Decrypted), Key = r.Key
                            });
                        if (xor.Count > 0) log($"    XOR strings: {xor.Count}");

                        // ADD/SUB encrypted strings
                        var addsub = StringDecryptor.FindAddSubEncryptedStrings(secData, secBase);
                        foreach (var r in addsub)
                            result.Strings.Add(new AdvancedStringDecryptor.DecryptedString
                            {
                                Address = r.Address, Decrypted = r.Decrypted,
                                Method = r.Method, Confidence = 0.7,
                                Category = CategorizeString(r.Decrypted), Key = r.Key
                            });
                        if (addsub.Count > 0) log($"    ADD/SUB strings: {addsub.Count}");

                        // ROT encrypted strings
                        var rot = StringDecryptor.FindRotEncryptedStrings(secData, secBase);
                        foreach (var r in rot)
                            result.Strings.Add(new AdvancedStringDecryptor.DecryptedString
                            {
                                Address = r.Address, Decrypted = r.Decrypted,
                                Method = r.Method, Confidence = 0.7,
                                Category = CategorizeString(r.Decrypted), Key = r.Key
                            });
                        if (rot.Count > 0) log($"    ROT strings: {rot.Count}");

                        // Base64 strings
                        var b64 = StringDecryptor.FindBase64Strings(secData, secBase);
                        foreach (var r in b64)
                            result.Strings.Add(new AdvancedStringDecryptor.DecryptedString
                            {
                                Address = r.Address, Decrypted = r.Decrypted,
                                Method = r.Method, Confidence = 0.8,
                                Category = CategorizeString(r.Decrypted), Key = r.Key
                            });
                        if (b64.Count > 0) log($"    Base64 strings: {b64.Count}");

                        // Unicode strings
                        var unicode = StringDecryptor.FindUnicodeStrings(secData, secBase, 6);
                        result.UnicodeStrings.AddRange(unicode);
                        if (unicode.Count > 0) log($"    Unicode strings: {unicode.Count}");
                    }
                }
                catch (Exception ex)
                {
                    log($"  Error scanning section {s}: {ex.Message}");
                }
            }

            // Deduplicate results
            var seen = new HashSet<string>();
            var deduped = new List<AdvancedStringDecryptor.DecryptedString>();
            foreach (var ds in result.Strings.OrderByDescending(d => d.Confidence))
            {
                if (ds.Decrypted.Length < 4) continue;
                if (seen.Add(ds.Decrypted))
                    deduped.Add(ds);
            }
            result.Strings = deduped;

            int total = result.Strings.Count + result.StackStrings.Count + result.Patterns.Count + result.UnicodeStrings.Count;
            result.Summary = $"{result.Strings.Count} encrypted, {result.StackStrings.Count} stack, {result.UnicodeStrings.Count} unicode, {result.Patterns.Count} patterns ({total} total)";
            result.FilePath = fileName;
            log(result.Summary);

            return result;
        }

        private static string CategorizeString(string s)
        {
            if (string.IsNullOrEmpty(s)) return "String";
            if (s.Contains("://") || s.StartsWith("http") || s.StartsWith("www")) return "URL";
            if (s.Contains("\\") && s.Length > 3) return "File Path";
            if (s.StartsWith("HKEY_") || s.Contains("\\Registry\\")) return "Registry";
            if (s.EndsWith(".dll") || s.EndsWith(".exe") || s.EndsWith(".sys")) return "Module";
            if (s.Contains("Error") || s.Contains("error") || s.Contains("Failed")) return "Error Message";
            return "String";
        }

        public static void SaveReport(string outputPath, FileScanResult result)
        {
            try
            {
                using (var w = new StreamWriter(outputPath))
                {
                    w.WriteLine("// KsDumper - File String Scan Report");
                    w.WriteLine($"// File: {result.FileName}");
                    w.WriteLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                    w.WriteLine($"// {result.Summary}");
                    w.WriteLine();

                    if (result.Strings.Count > 0)
                    {
                        w.WriteLine("// ==== Decrypted Strings ====");
                        w.WriteLine("// [CONFIDENCE] [CATEGORY] [METHOD] [ADDRESS] VALUE");
                        foreach (var r in result.Strings)
                            w.WriteLine($"[{r.Confidence:F2}] [{r.Category}] [{r.Method}] [0x{r.Address:X}] \"{Escape(r.Decrypted)}\"");
                        w.WriteLine();
                    }

                    if (result.StackStrings.Count > 0)
                    {
                        w.WriteLine("// ==== Stack Strings ====");
                        foreach (var s in result.StackStrings)
                            w.WriteLine($"[0x{s.Address:X}] \"{Escape(s.Value)}\"");
                        w.WriteLine();
                    }

                    if (result.UnicodeStrings.Count > 0)
                    {
                        w.WriteLine("// ==== Unicode Strings ====");
                        foreach (var (addr, val) in result.UnicodeStrings)
                            w.WriteLine($"[0x{addr:X}] \"{Escape(val)}\"");
                        w.WriteLine();
                    }

                    if (result.Patterns.Count > 0)
                    {
                        w.WriteLine("// ==== Decryptor Patterns ====");
                        foreach (var p in result.Patterns)
                            w.WriteLine($"[0x{p.Address:X}] {p.PatternName}: {p.Description}");
                    }
                }
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"Failed to save report: {ex.Message}");
            }
        }

        private static string Escape(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
        }
    }
}
