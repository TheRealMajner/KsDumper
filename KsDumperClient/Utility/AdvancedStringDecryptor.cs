using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    /// <summary>
    /// Advanced string decryption with human-readable reconstruction.
    /// Applies multiple decryption methods, scores results, and reconstructs
    /// meaningful strings from encrypted data.
    /// </summary>
    public static class AdvancedStringDecryptor
    {
        public struct DecryptedString
        {
            public ulong Address;
            public string Original;       // Raw encrypted bytes as hex
            public string Decrypted;      // Decrypted result
            public string Method;         // How it was decrypted
            public double Confidence;     // 0.0 - 1.0 confidence score
            public string Category;       // URL, File Path, API, Message, etc.
            public byte[] Key;
        }

        public struct ScanResult
        {
            public List<DecryptedString> Strings;
            public int TotalEncryptedRegions;
            public int DecryptedCount;
            public string Summary;
        }

        /// <summary>
        /// Scan a module for encrypted strings and attempt full decryption with reconstruction.
        /// </summary>
        public static ScanResult ScanModule(IMemoryReader driver, int processId, ulong baseAddress, uint imageSize, Action<string> log)
        {
            var result = new ScanResult { Strings = new List<DecryptedString>() };

            byte[] peHeader = ReadBytes(driver, processId, baseAddress, 0x400);
            if (peHeader == null || peHeader.Length < 64 || BitConverter.ToUInt16(peHeader, 0) != 0x5A4D)
            {
                log("Invalid PE header");
                return result;
            }

            int e_lfanew = BitConverter.ToInt32(peHeader, 60);
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
                bool isCode = (characteristics & 0x20) != 0;
                if (isCode) continue; // Skip code sections for string scanning

                int readSize = (int)Math.Min(virtualSize, 0x10000); // 64KB max per section
                byte[] secData = ReadBytes(driver, processId, baseAddress + virtualAddr, readSize);
                if (secData == null) continue;

                ulong secBase = baseAddress + virtualAddr;
                log($"  Scanning [{secName}] ({readSize / 1024}KB)...");

                // Phase 1: Find encrypted-looking regions
                var encryptedRegions = FindEncryptedRegions(secData, secBase);
                result.TotalEncryptedRegions += encryptedRegions.Count;

                // Phase 2: Try all decryption methods on each region
                foreach (var region in encryptedRegions)
                {
                    var decrypted = DecryptRegion(region.Data, region.Address);
                    result.Strings.AddRange(decrypted);
                }
            }

            // Phase 3: Deduplicate and sort by confidence
            var seen = new HashSet<string>();
            var deduped = new List<DecryptedString>();
            foreach (var ds in result.Strings.OrderByDescending(d => d.Confidence))
            {
                if (ds.Decrypted.Length < 4) continue;
                if (seen.Add(ds.Decrypted))
                    deduped.Add(ds);
            }
            result.Strings = deduped;
            result.DecryptedCount = deduped.Count;
            result.Summary = $"Found {result.TotalEncryptedRegions} encrypted regions, decrypted {result.DecryptedCount} unique strings";
            log(result.Summary);

            return result;
        }

        // ---- Phase 1: Find encrypted regions ----

        private struct EncryptedRegion
        {
            public byte[] Data;
            public ulong Address;
        }

        private static List<EncryptedRegion> FindEncryptedRegions(byte[] data, ulong baseAddress)
        {
            var regions = new List<EncryptedRegion>();
            int windowSize = 256;

            for (int i = 0; i <= data.Length - windowSize; i += 64)
            {
                byte[] window = new byte[windowSize];
                Array.Copy(data, i, window, 0, windowSize);

                // Check if this region looks encrypted
                double entropy = ShannonEntropy(window);
                double printableRatio = PrintableRatio(window);

                // Encrypted regions: high entropy (>6.5) and low printable ratio (<30%)
                // But NOT already-readable strings (high printable ratio)
                if (entropy > 6.0 && printableRatio < 0.35 && printableRatio > 0.01)
                {
                    // Find the actual extent of encrypted data
                    int start = i;
                    int end = Math.Min(i + 1024, data.Length); // Up to 1KB region

                    byte[] regionData = new byte[end - start];
                    Array.Copy(data, start, regionData, 0, regionData.Length);
                    regions.Add(new EncryptedRegion { Data = regionData, Address = baseAddress + (ulong)start });

                    i = end - 64; // Skip ahead
                }
            }

            return regions;
        }

        // ---- Phase 2: Multi-method decryption ----

        private static List<DecryptedString> DecryptRegion(byte[] data, ulong address)
        {
            var results = new List<DecryptedString>();

            // Try all single-byte XOR keys
            for (int key = 1; key <= 255; key++)
            {
                byte[] decrypted = XorDecrypt(data, new byte[] { (byte)key });
                var extracted = ExtractAndScore(decrypted, address, $"XOR-1 (0x{key:X2})");
                results.AddRange(extracted);
            }

            // Try ADD/SUB with common values
            for (int val = 1; val <= 127; val++)
            {
                byte[] addDec = new byte[data.Length];
                byte[] subDec = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                {
                    addDec[i] = (byte)(data[i] + val);
                    subDec[i] = (byte)(data[i] - val);
                }
                results.AddRange(ExtractAndScore(addDec, address, $"ADD (0x{val:X2})"));
                results.AddRange(ExtractAndScore(subDec, address, $"SUB (0x{val:X2})"));
            }

            // Try ROT-N
            for (int shift = 1; shift <= 25; shift++)
            {
                byte[] rotated = new byte[data.Length];
                for (int i = 0; i < data.Length; i++)
                {
                    byte b = data[i];
                    if (b >= (byte)'A' && b <= (byte)'Z')
                        rotated[i] = (byte)('A' + (b - 'A' + shift) % 26);
                    else if (b >= (byte)'a' && b <= (byte)'z')
                        rotated[i] = (byte)('a' + (b - 'a' + shift) % 26);
                    else
                        rotated[i] = b;
                }
                string label = shift == 13 ? "ROT13" : $"ROT{shift}";
                results.AddRange(ExtractAndScore(rotated, address, label));
            }

            // Try multi-byte XOR with known-plaintext
            string[] knownPrefixes = { "http://", "https://", "C:\\", "D:\\", "Error",
                "System.", "Microsoft.", "kernel32", "ntdll", "user32", "advapi32",
                "HKEY_", "SOFTWARE\\", "\\Registry\\", "NtQuery", "ZwQuery",
                "VirtualAlloc", "LoadLibrary", "GetProcAddress", "CreateFile",
                "ws2_32", "wininet", "WinHttp", "MSVCRT", "ucrtbase" };

            foreach (var prefix in knownPrefixes)
            {
                byte[] pfx = Encoding.ASCII.GetBytes(prefix);
                for (int keyLen = 2; keyLen <= 4; keyLen++)
                {
                    // Try to derive key from each offset
                    for (int off = 0; off < Math.Min(data.Length - pfx.Length, 512); off += 4)
                    {
                        byte[] key = new byte[keyLen];
                        for (int k = 0; k < keyLen; k++)
                            key[k] = (byte)(data[off + k] ^ pfx[k]);
                        if (key.All(b => b == 0)) continue;

                        // Verify key
                        bool valid = true;
                        for (int k = keyLen; k < pfx.Length && off + k < data.Length; k++)
                        {
                            if ((byte)(data[off + k] ^ pfx[k]) != key[k % keyLen])
                            { valid = false; break; }
                        }
                        if (!valid) continue;

                        byte[] decrypted = XorDecrypt(data, key);
                        string keyHex = "0x" + BitConverter.ToString(key).Replace("-", "");
                        results.AddRange(ExtractAndScore(decrypted, address, $"XOR-{keyLen} ({keyHex})"));
                    }
                }
            }

            // Try Base64 decode
            try
            {
                string ascii = Encoding.ASCII.GetString(data);
                var b64Matches = Regex.Matches(ascii, @"[A-Za-z0-9+/]{16,}={0,2}");
                foreach (Match match in b64Matches)
                {
                    try
                    {
                        byte[] decoded = Convert.FromBase64String(match.Value);
                        string decodedStr = Encoding.UTF8.GetString(decoded);
                        if (decodedStr.Length >= 4 && ScoreText(decodedStr) >= 0.5)
                        {
                            results.Add(new DecryptedString
                            {
                                Address = address + (ulong)match.Index,
                                Original = match.Value.Substring(0, Math.Min(32, match.Value.Length)),
                                Decrypted = decodedStr,
                                Method = "Base64",
                                Confidence = ScoreText(decodedStr),
                                Category = CategorizeString(decodedStr),
                                Key = Encoding.ASCII.GetBytes(match.Value.Substring(0, Math.Min(8, match.Value.Length)))
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return results;
        }

        // ---- String extraction and scoring ----

        private static List<DecryptedString> ExtractAndScore(byte[] decrypted, ulong baseAddress, string method)
        {
            var results = new List<DecryptedString>();
            int runStart = -1;

            for (int i = 0; i < decrypted.Length; i++)
            {
                bool printable = decrypted[i] >= 0x20 && decrypted[i] < 0x7F;
                if (printable)
                {
                    if (runStart < 0) runStart = i;
                }
                else
                {
                    if (runStart >= 0)
                    {
                        int len = i - runStart;
                        if (len >= 6)
                        {
                            string str = Encoding.ASCII.GetString(decrypted, runStart, len);
                            double confidence = ScoreText(str);
                            if (confidence >= 0.5)
                            {
                                // Build original hex for reference
                                int origLen = Math.Min(len, 32);
                                string original = BitConverter.ToString(decrypted, runStart, origLen).Replace("-", " ");

                                results.Add(new DecryptedString
                                {
                                    Address = baseAddress + (ulong)runStart,
                                    Original = original,
                                    Decrypted = str,
                                    Method = method,
                                    Confidence = confidence,
                                    Category = CategorizeString(str),
                                    Key = Encoding.ASCII.GetBytes(method)
                                });
                            }
                        }
                        runStart = -1;
                    }
                }
            }
            return results;
        }

        private static double ScoreText(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4) return 0;

            int alpha = 0, digits = 0, space = 0, punct = 0, special = 0;
            foreach (char c in s)
            {
                if (char.IsLetter(c)) alpha++;
                else if (char.IsDigit(c)) digits++;
                else if (c == ' ') space++;
                else if (".,;:!?/\\-_()[]{}@#$%&*+=<>~`\"'".Contains(c)) punct++;
                else special++;
            }

            double textChars = alpha + digits + space + punct;
            double ratio = textChars / s.Length;

            // Bonus for word-like patterns
            double bonus = 0;
            if (space > 0 && alpha > 3) bonus += 0.1; // Has words
            if (s.Contains("://")) bonus += 0.15; // URL
            if (s.Contains("\\") && alpha > 2) bonus += 0.1; // File path
            if (Regex.IsMatch(s, @"^[A-Z][a-z]+[A-Z]")) bonus += 0.1; // CamelCase
            if (Regex.IsMatch(s, @"^[a-z_][a-z0-9_]*$")) bonus += 0.1; // identifier

            // Penalty for too many special chars
            double penalty = special > s.Length * 0.3 ? 0.2 : 0;

            return Math.Max(0, Math.Min(1.0, ratio + bonus - penalty));
        }

        private static string CategorizeString(string s)
        {
            if (s.Contains("://") || s.StartsWith("http") || s.StartsWith("www")) return "URL";
            if (s.Contains("\\") || s.Contains("/") && s.Length > 3 && (s[1] == ':' || s[0] == '/')) return "File Path";
            if (s.StartsWith("HKEY_") || s.Contains("\\Registry\\")) return "Registry";
            if (Regex.IsMatch(s, @"^(Nt|Zw|Rtl)[A-Z]")) return "NT API";
            if (Regex.IsMatch(s, @"^[A-Z][a-zA-Z]+[A-Z]")) return "API/Class";
            if (s.EndsWith(".dll") || s.EndsWith(".exe") || s.EndsWith(".sys")) return "Module";
            if (s.Contains("Error") || s.Contains("error") || s.Contains("Failed") || s.Contains("failed")) return "Error Message";
            if (s.Contains("%s") || s.Contains("%d") || s.Contains("{0}")) return "Format String";
            if (Regex.IsMatch(s, @"^[a-z_][a-z0-9_]*$")) return "Identifier";
            if (s.Contains("=") || s.Contains("<") || s.Contains(">")) return "Expression";
            if (space_ratio(s) > 0.2) return "Message";
            return "String";
        }

        private static double space_ratio(string s)
        {
            if (s.Length == 0) return 0;
            return (double)s.Count(c => c == ' ') / s.Length;
        }

        // ---- Helpers ----

        private static byte[] XorDecrypt(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];
            for (int i = 0; i < data.Length; i++)
                result[i] = (byte)(data[i] ^ key[i % key.Length]);
            return result;
        }

        private static double ShannonEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;
            int[] freq = new int[256];
            foreach (byte b in data) freq[b]++;
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

        private static double PrintableRatio(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;
            int printable = 0;
            foreach (byte b in data)
                if (b >= 0x20 && b < 0x7F) printable++;
            return (double)printable / data.Length;
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

        // ---- Report Generation ----

        public static void SaveReport(string outputPath, ScanResult result, string moduleName)
        {
            using (var w = new System.IO.StreamWriter(outputPath))
            {
                w.WriteLine($"// KsDumper - Advanced String Decryption Report");
                w.WriteLine($"// Module: {moduleName}");
                w.WriteLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                w.WriteLine($"// {result.Summary}");
                w.WriteLine();
                w.WriteLine("// Format: [CONFIDENCE] [CATEGORY] [METHOD] [ADDRESS] DECRYPTED");
                w.WriteLine();

                // Group by category
                var grouped = result.Strings.GroupBy(s => s.Category).OrderBy(g => g.Key);
                foreach (var group in grouped)
                {
                    w.WriteLine($"// ═══ {group.Key} ({group.Count()}) ═══");
                    foreach (var ds in group.OrderByDescending(d => d.Confidence))
                    {
                        w.WriteLine($"[{ds.Confidence:F2}] [{ds.Category}] [{ds.Method}] [0x{ds.Address:X}] \"{EscapeString(ds.Decrypted)}\"");
                    }
                    w.WriteLine();
                }
            }
        }

        private static string EscapeString(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
        }
    }
}
