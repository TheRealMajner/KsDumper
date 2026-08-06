using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class StringDecryptor
    {
        public struct DecryptionResult
        {
            public ulong Address;
            public string Decrypted;
            public string Method;
            public byte[] Key;
            public string KeyHex;
        }

        public struct StackString
        {
            public ulong Address;
            public string Value;
            public int Length;
        }

        public struct DecryptorPattern
        {
            public ulong Address;
            public string PatternName;
            public string Description;
        }

        private const int MAX_RESULTS = 100;
        private const int MAX_SCAN_PER_SECTION = 32768; // 32KB

        // ==================== XOR DECRYPTION ====================

        public static List<DecryptionResult> FindXorEncryptedStrings(byte[] data, ulong baseAddress)
        {
            var results = new List<DecryptionResult>();
            var seen = new HashSet<string>();
            int scanLen = Math.Min(data.Length, MAX_SCAN_PER_SECTION);

            // Single-byte XOR with frequency pre-check
            for (int key = 1; key <= 255 && results.Count < MAX_RESULTS; key++)
            {
                int sampleLen = Math.Min(512, scanLen);
                int printable = 0, nulls = 0;
                for (int i = 0; i < sampleLen; i++)
                {
                    byte b = (byte)(data[i] ^ (byte)key);
                    if (b >= 0x20 && b < 0x7F) printable++;
                    if (b == 0) nulls++;
                }
                // Need >40% printable and some nulls (string terminators)
                if (printable < sampleLen * 0.4) continue;
                if (nulls < 2) continue;

                byte[] region = new byte[scanLen];
                Array.Copy(data, region, scanLen);
                XorInPlace(region, new byte[] { (byte)key });
                var found = ExtractStrings(region, baseAddress, 8);

                foreach (var (addr, str) in found)
                {
                    if (results.Count >= MAX_RESULTS) break;
                    if (!seen.Contains(str) && ScoreText(str) >= 0.6)
                    {
                        seen.Add(str);
                        results.Add(new DecryptionResult { Address = addr, Decrypted = str, Method = $"XOR-1 (key=0x{key:X2})", Key = new[] { (byte)key }, KeyHex = $"0x{key:X2}" });
                    }
                }
            }

            // Multi-byte XOR via known-plaintext (2-4 byte keys)
            string[] prefixes = { "http://", "https://", "www.", "Error:", "System.", "Microsoft.",
                "C:\\", "/bin/", "kernel32", "ntdll", "user32", "advapi32", "WSA", "ERROR_",
                "function", "class ", "public ", "private ", "return ", "void ", "int ",
                "HKEY_", "SOFTWARE\\", "HKLM\\", "HKCU\\", "REG_", "NtQuery", "ZwQuery" };

            foreach (var prefix in prefixes)
            {
                if (results.Count >= MAX_RESULTS) break;
                byte[] pfx = Encoding.ASCII.GetBytes(prefix);
                int kpLen = Math.Min(scanLen, 8192);

                for (int keyLen = 2; keyLen <= 4 && results.Count < MAX_RESULTS; keyLen++)
                {
                    for (int off = 0; off <= kpLen - pfx.Length && results.Count < MAX_RESULTS; off += 8)
                    {
                        byte[] key = new byte[keyLen];
                        for (int k = 0; k < keyLen; k++)
                            key[k] = (byte)(data[off + k] ^ pfx[k]);
                        if (key.All(b => b == 0)) continue;

                        // Verify key against full prefix
                        bool ok = true;
                        for (int k = keyLen; k < pfx.Length && off + k < data.Length; k++)
                            if ((byte)(data[off + k] ^ pfx[k]) != key[k % keyLen]) { ok = false; break; }
                        if (!ok) continue;

                        int rLen = Math.Min(512, data.Length - off);
                        byte[] region = new byte[rLen];
                        Array.Copy(data, off, region, 0, rLen);
                        XorInPlace(region, key);
                        var strs = ExtractStrings(region, baseAddress + (ulong)off, 8);

                        foreach (var (addr, str) in strs)
                        {
                            if (results.Count >= MAX_RESULTS) break;
                            if (!seen.Contains(str) && str.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) && ScoreText(str) >= 0.5)
                            {
                                seen.Add(str);
                                results.Add(new DecryptionResult { Address = addr, Decrypted = str, Method = $"XOR-{keyLen} (plaintext: \"{prefix}\")", Key = key, KeyHex = "0x" + BitConverter.ToString(key).Replace("-", "") });
                            }
                        }
                    }
                }
            }
            return results;
        }

        // ==================== ADD/SUB DECRYPTION ====================

        public static List<DecryptionResult> FindAddSubEncryptedStrings(byte[] data, ulong baseAddress)
        {
            var results = new List<DecryptionResult>();
            var seen = new HashSet<string>();
            int scanLen = Math.Min(data.Length, MAX_SCAN_PER_SECTION);

            for (int val = 1; val <= 127 && results.Count < MAX_RESULTS; val++)
            {
                // ADD decryption
                int printable = 0;
                int sampleLen = Math.Min(256, scanLen);
                for (int i = 0; i < sampleLen; i++)
                {
                    byte b = (byte)(data[i] + (byte)val);
                    if (b >= 0x20 && b < 0x7F) printable++;
                }
                if (printable < sampleLen * 0.4) { /* try SUB */ }
                else
                {
                    byte[] region = new byte[scanLen];
                    Array.Copy(data, region, scanLen);
                    for (int i = 0; i < region.Length; i++) region[i] = (byte)(region[i] + (byte)val);
                    foreach (var (addr, str) in ExtractStrings(region, baseAddress, 8))
                    {
                        if (results.Count >= MAX_RESULTS) break;
                        if (!seen.Contains(str) && ScoreText(str) >= 0.6) { seen.Add(str); results.Add(new DecryptionResult { Address = addr, Decrypted = str, Method = $"ADD (val=0x{val:X2})", Key = new[] { (byte)val }, KeyHex = $"0x{val:X2}" }); }
                    }
                }

                // SUB decryption
                printable = 0;
                for (int i = 0; i < sampleLen; i++)
                {
                    byte b = (byte)(data[i] - (byte)val);
                    if (b >= 0x20 && b < 0x7F) printable++;
                }
                if (printable >= sampleLen * 0.4)
                {
                    byte[] region = new byte[scanLen];
                    Array.Copy(data, region, scanLen);
                    for (int i = 0; i < region.Length; i++) region[i] = (byte)(region[i] - (byte)val);
                    foreach (var (addr, str) in ExtractStrings(region, baseAddress, 8))
                    {
                        if (results.Count >= MAX_RESULTS) break;
                        if (!seen.Contains(str) && ScoreText(str) >= 0.6) { seen.Add(str); results.Add(new DecryptionResult { Address = addr, Decrypted = str, Method = $"SUB (val=0x{val:X2})", Key = new[] { (byte)val }, KeyHex = $"0x{val:X2}" }); }
                    }
                }
            }
            return results;
        }

        // ==================== ROT DECRYPTION ====================

        public static List<DecryptionResult> FindRotEncryptedStrings(byte[] data, ulong baseAddress)
        {
            var results = new List<DecryptionResult>();
            var seen = new HashSet<string>();
            int scanLen = Math.Min(data.Length, MAX_SCAN_PER_SECTION);

            // ROT-N for shifts 1-25 (ROT13 is most common)
            for (int shift = 1; shift <= 25 && results.Count < MAX_RESULTS; shift++)
            {
                int sampleLen = Math.Min(256, scanLen);
                int alpha = 0, printable = 0;
                for (int i = 0; i < sampleLen; i++)
                {
                    byte b = data[i];
                    byte rotated = b;
                    if (b >= (byte)'A' && b <= (byte)'Z')
                        rotated = (byte)('A' + (b - 'A' + shift) % 26);
                    else if (b >= (byte)'a' && b <= (byte)'z')
                        rotated = (byte)('a' + (b - 'a' + shift) % 26);

                    if (rotated >= 0x20 && rotated < 0x7F) printable++;
                    if ((rotated >= 'A' && rotated <= 'Z') || (rotated >= 'a' && rotated <= 'z')) alpha++;
                }
                if (alpha < sampleLen * 0.3) continue;

                byte[] region = new byte[scanLen];
                Array.Copy(data, region, scanLen);
                for (int i = 0; i < region.Length; i++)
                {
                    byte b = region[i];
                    if (b >= (byte)'A' && b <= (byte)'Z')
                        region[i] = (byte)('A' + (b - 'A' + shift) % 26);
                    else if (b >= (byte)'a' && b <= (byte)'z')
                        region[i] = (byte)('a' + (b - 'a' + shift) % 26);
                }

                string label = shift == 13 ? "ROT13" : $"ROT{shift}";
                foreach (var (addr, str) in ExtractStrings(region, baseAddress, 8))
                {
                    if (results.Count >= MAX_RESULTS) break;
                    if (!seen.Contains(str) && ScoreText(str) >= 0.6)
                    {
                        seen.Add(str);
                        results.Add(new DecryptionResult { Address = addr, Decrypted = str, Method = label, Key = new[] { (byte)shift }, KeyHex = shift.ToString() });
                    }
                }
            }
            return results;
        }

        // ==================== BASE64 DETECTION ====================

        public static List<DecryptionResult> FindBase64Strings(byte[] data, ulong baseAddress)
        {
            var results = new List<DecryptionResult>();
            var seen = new HashSet<string>();
            var b64Pattern = new Regex(@"[A-Za-z0-9+/]{16,}={0,2}");
            string ascii = Encoding.ASCII.GetString(data);

            foreach (Match match in b64Pattern.Matches(ascii))
            {
                if (results.Count >= MAX_RESULTS) break;
                string b64 = match.Value;
                try
                {
                    byte[] decoded = Convert.FromBase64String(b64);
                    string decodedStr = Encoding.UTF8.GetString(decoded);
                    if (decodedStr.Length >= 4 && ScoreText(decodedStr) >= 0.5 && !seen.Contains(decodedStr))
                    {
                        seen.Add(decodedStr);
                        ulong addr = baseAddress + (ulong)match.Index;
                        results.Add(new DecryptionResult
                        {
                            Address = addr, Decrypted = decodedStr,
                            Method = "Base64", Key = Encoding.ASCII.GetBytes(b64.Substring(0, Math.Min(16, b64.Length))),
                            KeyHex = b64.Substring(0, Math.Min(32, b64.Length))
                        });
                    }
                }
                catch { }
            }
            return results;
        }

        // ==================== UNICODE STRING DETECTION ====================

        public static List<(ulong address, string value)> FindUnicodeStrings(byte[] data, ulong baseAddress, int minLength = 4)
        {
            var results = new List<(ulong, string)>();
            int runStart = -1;
            int charCount = 0;

            for (int i = 0; i < data.Length - 1; i += 2)
            {
                ushort ch = BitConverter.ToUInt16(data, i);
                bool printable = ch >= 0x20 && ch < 0x7F;

                if (printable)
                {
                    if (runStart < 0) { runStart = i; charCount = 0; }
                    charCount++;
                }
                else
                {
                    if (charCount >= minLength)
                    {
                        string s = Encoding.Unicode.GetString(data, runStart, charCount * 2);
                        if (ScoreText(s) >= 0.5)
                            results.Add((baseAddress + (ulong)runStart, s));
                    }
                    runStart = -1;
                    charCount = 0;
                }
            }
            return results;
        }

        // ==================== STACK STRING EXTRACTION ====================

        public static List<StackString> FindStackStrings(byte[] codeData, ulong codeBaseAddress)
        {
            var results = new List<StackString>();
            var seen = new HashSet<ulong>();
            int i = 0;

            while (i < codeData.Length - 4)
            {
                // x64: mov byte ptr [rsp+XX], imm8  (C6 44 24 XX YY)
                if (i + 5 <= codeData.Length && codeData[i] == 0xC6 && codeData[i + 1] == 0x44 && codeData[i + 2] == 0x24)
                {
                    byte charVal = codeData[i + 4];
                    if (charVal >= 0x20 && charVal < 0x7F)
                    {
                        var sb = new StringBuilder();
                        sb.Append((char)charVal);
                        ulong startAddr = codeBaseAddress + (ulong)i;
                        int j = i + 5;
                        while (j + 5 <= codeData.Length && codeData[j] == 0xC6 && codeData[j + 1] == 0x44 && codeData[j + 2] == 0x24)
                        {
                            byte nc = codeData[j + 4];
                            if (nc >= 0x20 && nc < 0x7F) { sb.Append((char)nc); j += 5; }
                            else if (nc == 0) { j += 5; break; }
                            else break;
                        }
                        if (sb.Length >= 4 && !seen.Contains(startAddr)) { seen.Add(startAddr); results.Add(new StackString { Address = startAddr, Value = sb.ToString(), Length = sb.Length }); }
                        i = j; continue;
                    }
                }

                // x86: mov byte ptr [ebp-XX], imm8  (C6 45 XX YY)
                if (i + 4 <= codeData.Length && codeData[i] == 0xC6 && codeData[i + 1] == 0x45)
                {
                    byte charVal = codeData[i + 3];
                    if (charVal >= 0x20 && charVal < 0x7F)
                    {
                        var sb = new StringBuilder();
                        sb.Append((char)charVal);
                        ulong startAddr = codeBaseAddress + (ulong)i;
                        int j = i + 4;
                        while (j + 4 <= codeData.Length && codeData[j] == 0xC6 && codeData[j + 1] == 0x45)
                        {
                            byte nc = codeData[j + 3];
                            if (nc >= 0x20 && nc < 0x7F) { sb.Append((char)nc); j += 4; }
                            else if (nc == 0) { j += 4; break; }
                            else break;
                        }
                        if (sb.Length >= 4 && !seen.Contains(startAddr)) { seen.Add(startAddr); results.Add(new StackString { Address = startAddr, Value = sb.ToString(), Length = sb.Length }); }
                        i = j; continue;
                    }
                }

                // mov dword ptr [reg], imm32 (4 chars at once)
                if (i + 8 <= codeData.Length && codeData[i] == 0xC7)
                {
                    bool valid = (codeData[i + 1] == 0x44 && codeData[i + 2] == 0x24) || codeData[i + 1] == 0x45;
                    if (valid)
                    {
                        int immOff = codeData[i + 1] == 0x44 ? i + 4 : i + 3;
                        if (immOff + 4 <= codeData.Length)
                        {
                            uint imm32 = BitConverter.ToUInt32(codeData, immOff);
                            byte b0 = (byte)(imm32), b1 = (byte)(imm32 >> 8), b2 = (byte)(imm32 >> 16), b3 = (byte)(imm32 >> 24);
                            if (b0 >= 0x20 && b0 < 0x7F && b1 >= 0x20 && b1 < 0x7F && b2 >= 0x20 && b2 < 0x7F && b3 >= 0x20 && b3 < 0x7F)
                            {
                                ulong addr = codeBaseAddress + (ulong)i;
                                if (!seen.Contains(addr)) { seen.Add(addr); results.Add(new StackString { Address = addr, Value = new string(new[] { (char)b0, (char)b1, (char)b2, (char)b3 }), Length = 4 }); }
                            }
                        }
                    }
                }

                // x64: mov qword ptr [rsp+XX], imm (8 chars at once via LEA + MOV)
                // push imm32 (68 XX XX XX XX) - 4 char string pushed on stack
                if (i + 5 <= codeData.Length && codeData[i] == 0x68)
                {
                    uint imm32 = BitConverter.ToUInt32(codeData, i + 1);
                    byte b0 = (byte)(imm32), b1 = (byte)(imm32 >> 8), b2 = (byte)(imm32 >> 16), b3 = (byte)(imm32 >> 24);
                    if (b0 >= 0x20 && b0 < 0x7F && b1 >= 0x20 && b1 < 0x7F && b2 >= 0x20 && b2 < 0x7F && b3 >= 0x20 && b3 < 0x7F)
                    {
                        ulong addr = codeBaseAddress + (ulong)i;
                        if (!seen.Contains(addr)) { seen.Add(addr); results.Add(new StackString { Address = addr, Value = new string(new[] { (char)b0, (char)b1, (char)b2, (char)b3 }), Length = 4 }); }
                    }
                }

                i++;
            }
            return results;
        }

        // ==================== DECRYPTOR PATTERN DETECTION ====================

        public static List<DecryptorPattern> FindDecryptorPatterns(byte[] codeData, ulong codeBaseAddress)
        {
            var results = new List<DecryptorPattern>();

            for (int i = 0; i < codeData.Length - 6; i++)
            {
                // XOR decrypt loop: 80 30-37 XX + increment + loop
                if (codeData[i] == 0x80 && codeData[i + 1] >= 0x30 && codeData[i + 1] <= 0x37)
                {
                    byte key = codeData[i + 2];
                    if (key != 0 && HasLoopAfter(codeData, i + 3, 20))
                        results.Add(new DecryptorPattern { Address = codeBaseAddress + (ulong)i, PatternName = "XOR Decrypt Loop", Description = $"XOR key=0x{key:X2} + loop" });
                }

                // ROL/ROR decrypt: C0 00-0F XX
                if (codeData[i] == 0xC0 && codeData[i + 1] >= 0x00 && codeData[i + 1] <= 0x0F)
                {
                    byte shift = codeData[i + 2];
                    if (shift > 0 && shift < 8)
                        results.Add(new DecryptorPattern { Address = codeBaseAddress + (ulong)i, PatternName = "ROT Decrypt", Description = $"Rotation shift={shift}" });
                }

                // SUB/ADD decrypt: 80 28/00 XX
                if (codeData[i] == 0x80 && (codeData[i + 1] == 0x28 || codeData[i + 1] == 0x00))
                {
                    byte val = codeData[i + 2];
                    if (val >= 1 && val <= 0x7F && HasLoopAfter(codeData, i + 3, 15))
                    {
                        string op = codeData[i + 1] == 0x28 ? "SUB" : "ADD";
                        results.Add(new DecryptorPattern { Address = codeBaseAddress + (ulong)i, PatternName = $"{op} Decrypt Loop", Description = $"{op} val=0x{val:X2} + loop" });
                    }
                }

                // CALL to decryption function followed by data block
                // E8 XX XX XX XX (relative call) - if followed by string-like data, likely a decryptor
                if (codeData[i] == 0xE8 && i + 5 < codeData.Length)
                {
                    int relOff = BitConverter.ToInt32(codeData, i + 1);
                    ulong targetAddr = codeBaseAddress + (ulong)(i + 5 + relOff);
                    // Check if the call target is within the module
                    if (targetAddr >= codeBaseAddress && targetAddr < codeBaseAddress + (ulong)codeData.Length)
                    {
                        // Look for a data block after the call (push offset, call pattern)
                        if (i >= 5 && codeData[i - 5] == 0x68) // push imm32 before call
                        {
                            uint dataAddr = BitConverter.ToUInt32(codeData, i - 4);
                            if (dataAddr >= codeBaseAddress && dataAddr < codeBaseAddress + (ulong)codeData.Length)
                            {
                                results.Add(new DecryptorPattern { Address = codeBaseAddress + (ulong)(i - 5), PatternName = "String Decrypt Call", Description = $"CALL 0x{targetAddr:X} with data at 0x{dataAddr:X}" });
                            }
                        }
                    }
                }
            }

            // Crypto constant detection
            DetectCryptoConstants(codeData, codeBaseAddress, results);

            return results;
        }

        private static void DetectCryptoConstants(byte[] data, ulong baseAddr, List<DecryptorPattern> results)
        {
            // AES S-box
            byte[] aesSbox = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5 };
            int idx = FindBytes(data, aesSbox);
            if (idx >= 0)
                results.Add(new DecryptorPattern { Address = baseAddr + (ulong)idx, PatternName = "AES S-Box", Description = "AES substitution box" });

            // AES inverse S-box
            byte[] aesInvSbox = { 0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38 };
            idx = FindBytes(data, aesInvSbox);
            if (idx >= 0)
                results.Add(new DecryptorPattern { Address = baseAddr + (ulong)idx, PatternName = "AES Inverse S-Box", Description = "AES inverse substitution box" });

            // CRC32 polynomial
            byte[] crc32 = { 0x20, 0x83, 0xB8, 0xED };
            idx = FindBytes(data, crc32);
            if (idx >= 0)
                results.Add(new DecryptorPattern { Address = baseAddr + (ulong)idx, PatternName = "CRC32", Description = "CRC32 polynomial 0xEDB88320" });

            // SHA-256 initial hash values
            byte[] sha256 = { 0x67, 0xE6, 0x09, 0x6A }; // 0x6A09E667 LE
            idx = FindBytes(data, sha256);
            if (idx >= 0)
                results.Add(new DecryptorPattern { Address = baseAddr + (ulong)idx, PatternName = "SHA-256", Description = "SHA-256 initial hash constants" });

            // MD5 initialization constants
            byte[] md5 = { 0x01, 0x23, 0x45, 0x67 };
            idx = FindBytes(data, md5);
            if (idx >= 0)
                results.Add(new DecryptorPattern { Address = baseAddr + (ulong)idx, PatternName = "MD5", Description = "MD5 initialization constant" });

            // DES S-box fragment
            byte[] des = { 0x0E, 0x04, 0x0D, 0x01, 0x02, 0x0F, 0x0B, 0x08 };
            idx = FindBytes(data, des);
            if (idx >= 0)
                results.Add(new DecryptorPattern { Address = baseAddr + (ulong)idx, PatternName = "DES S-Box", Description = "DES S-box fragment" });

            // Blowfish P-array fragment
            byte[] blowfish = { 0xD1, 0x31, 0x0B, 0xA6, 0xCC, 0xD0, 0x92, 0x29 };
            idx = FindBytes(data, blowfish);
            if (idx >= 0)
                results.Add(new DecryptorPattern { Address = baseAddr + (ulong)idx, PatternName = "Blowfish", Description = "Blowfish P-array constant" });

            // RC4 detection (KSA pattern): repeated XOR with incrementing index
            // Look for: MOV AL,[ESI+ECX], XOR AL,[EDI+EBX], MOV [ESI+ECX],AL pattern
            for (int i = 0; i < data.Length - 10; i++)
            {
                if (data[i] == 0x8A && data[i + 2] == 0x30 && data[i + 4] == 0x88)
                {
                    if (HasLoopAfter(data, i + 5, 10))
                    {
                        results.Add(new DecryptorPattern { Address = baseAddr + (ulong)i, PatternName = "RC4 KSA", Description = "RC4 Key Scheduling Algorithm pattern" });
                        break;
                    }
                }
            }
        }

        // ==================== FULL MODULE SCAN ====================

        public struct FullScanResult
        {
            public List<DecryptionResult> EncryptedStrings;
            public List<StackString> StackStrings;
            public List<DecryptorPattern> DecryptorPatterns;
            public List<(ulong address, string value)> UnicodeStrings;
            public string Summary;
        }

        public static FullScanResult ScanModule(IMemoryReader driver, int processId, ulong baseAddress, uint imageSize, Action<string> log)
        {
            var result = new FullScanResult
            {
                EncryptedStrings = new List<DecryptionResult>(),
                StackStrings = new List<StackString>(),
                DecryptorPatterns = new List<DecryptorPattern>(),
                UnicodeStrings = new List<(ulong, string)>()
            };

            byte[] peHeader = ReadBytes(driver, processId, baseAddress, 0x400);
            if (peHeader == null || peHeader.Length < 64) { log("Failed to read PE header"); return result; }
            if (BitConverter.ToUInt16(peHeader, 0) != 0x5A4D) { log("Invalid DOS signature"); return result; }

            int e_lfanew = BitConverter.ToInt32(peHeader, 60);
            if (e_lfanew + 24 > peHeader.Length || BitConverter.ToUInt32(peHeader, e_lfanew) != 0x00004550) { log("Invalid PE signature"); return result; }

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

                int readSize = (int)Math.Min(virtualSize, MAX_SCAN_PER_SECTION);
                byte[] secData = ReadBytes(driver, processId, baseAddress + virtualAddr, readSize);
                if (secData == null) continue;

                ulong secBase = baseAddress + virtualAddr;
                bool isCode = (characteristics & 0x20) != 0;
                log($"  [{secName}] {readSize / 1024}KB {(isCode ? "CODE" : "DATA")}...");

                if (isCode)
                {
                    var stack = FindStackStrings(secData, secBase);
                    result.StackStrings.AddRange(stack);
                    if (stack.Count > 0) log($"    Stack strings: {stack.Count}");

                    var patterns = FindDecryptorPatterns(secData, secBase);
                    result.DecryptorPatterns.AddRange(patterns);
                    if (patterns.Count > 0) log($"    Decryptor patterns: {patterns.Count}");
                }
                else
                {
                    // XOR decryption
                    var xor = FindXorEncryptedStrings(secData, secBase);
                    result.EncryptedStrings.AddRange(xor);
                    if (xor.Count > 0) log($"    XOR strings: {xor.Count}");

                    // ADD/SUB decryption
                    var addsub = FindAddSubEncryptedStrings(secData, secBase);
                    result.EncryptedStrings.AddRange(addsub);
                    if (addsub.Count > 0) log($"    ADD/SUB strings: {addsub.Count}");

                    // ROT decryption
                    var rot = FindRotEncryptedStrings(secData, secBase);
                    result.EncryptedStrings.AddRange(rot);
                    if (rot.Count > 0) log($"    ROT strings: {rot.Count}");

                    // Base64 encoded strings
                    var b64 = FindBase64Strings(secData, secBase);
                    result.EncryptedStrings.AddRange(b64);
                    if (b64.Count > 0) log($"    Base64 strings: {b64.Count}");

                    // Unicode strings
                    var unicode = FindUnicodeStrings(secData, secBase);
                    result.UnicodeStrings.AddRange(unicode);
                    if (unicode.Count > 0) log($"    Unicode strings: {unicode.Count}");
                }
            }

            int total = result.EncryptedStrings.Count + result.StackStrings.Count + result.DecryptorPatterns.Count + result.UnicodeStrings.Count;
            result.Summary = $"{result.EncryptedStrings.Count} encrypted, {result.StackStrings.Count} stack, {result.UnicodeStrings.Count} unicode, {result.DecryptorPatterns.Count} patterns ({total} total)";
            log(result.Summary);
            return result;
        }

        // ==================== HELPERS ====================

        private static void XorInPlace(byte[] data, byte[] key)
        {
            for (int i = 0; i < data.Length; i++)
                data[i] = (byte)(data[i] ^ key[i % key.Length]);
        }

        private static double ScoreText(string s)
        {
            if (string.IsNullOrEmpty(s)) return 0;
            int alpha = 0, space = 0, digit = 0, punct = 0;
            foreach (char c in s)
            {
                if (char.IsLetter(c)) alpha++;
                else if (c == ' ') space++;
                else if (char.IsDigit(c)) digit++;
                else if (".,;:!?/\\-_()[]{}@#$%&*+=<>~`\"'".Contains(c)) punct++;
            }
            double ratio = (double)(alpha + space + digit + punct) / s.Length;
            // Bonus for having spaces and mixed case
            if (space > 0 && alpha > 3) ratio += 0.1;
            return Math.Min(ratio, 1.0);
        }

        private static bool HasLoopAfter(byte[] data, int start, int range)
        {
            for (int j = start; j < Math.Min(start + range, data.Length - 2); j++)
            {
                if (data[j] == 0xE2 || data[j] == 0x75 || data[j] == 0xEB) return true; // LOOP, JNE, JMP short
                if (data[j] >= 0x40 && data[j] <= 0x47) return true; // INC reg (x86)
                if (j + 2 < data.Length && data[j] == 0x83 && data[j + 1] >= 0xC0 && data[j + 1] <= 0xC7 && data[j + 2] == 0x01) return true; // ADD reg, 1
                if (j + 1 < data.Length && data[j] == 0xFF && data[j + 1] >= 0xC0 && data[j + 1] <= 0xC7) return true; // INC reg (x64)
            }
            return false;
        }

        private static int FindBytes(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < needle.Length; j++)
                    if (haystack[i + j] != needle[j]) { match = false; break; }
                if (match) return i;
            }
            return -1;
        }

        private static List<(ulong address, string value)> ExtractStrings(byte[] data, ulong baseAddress, int minLength)
        {
            var results = new List<(ulong, string)>();
            int runStart = -1;
            for (int i = 0; i < data.Length; i++)
            {
                bool printable = data[i] >= 0x20 && data[i] < 0x7F;
                if (printable) { if (runStart < 0) runStart = i; }
                else
                {
                    if (runStart >= 0)
                    {
                        int len = i - runStart;
                        if (len >= minLength)
                            results.Add((baseAddress + (ulong)runStart, Encoding.ASCII.GetString(data, runStart, len)));
                        runStart = -1;
                    }
                }
            }
            return results;
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

        // ==================== REPORT ====================

        public static void SaveReport(string outputPath, FullScanResult result, string moduleName)
        {
            using (var w = new System.IO.StreamWriter(outputPath))
            {
                w.WriteLine($"// KsDumper - String Decryption Report");
                w.WriteLine($"// Module: {moduleName}");
                w.WriteLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                w.WriteLine($"// {result.Summary}");
                w.WriteLine();

                if (result.EncryptedStrings.Count > 0)
                {
                    w.WriteLine("// ==== Decrypted Strings ====");
                    w.WriteLine("// [ADDR] [METHOD] [KEY] VALUE");
                    foreach (var r in result.EncryptedStrings)
                        w.WriteLine($"[0x{r.Address:X}] [{r.Method}] [{r.KeyHex}] \"{EscapeString(r.Decrypted)}\"");
                    w.WriteLine();
                }

                if (result.StackStrings.Count > 0)
                {
                    w.WriteLine("// ==== Stack Strings ====");
                    foreach (var s in result.StackStrings)
                        w.WriteLine($"[0x{s.Address:X}] {s.Length} \"{EscapeString(s.Value)}\"");
                    w.WriteLine();
                }

                if (result.UnicodeStrings.Count > 0)
                {
                    w.WriteLine("// ==== Unicode Strings ====");
                    foreach (var (addr, val) in result.UnicodeStrings)
                        w.WriteLine($"[0x{addr:X}] \"{EscapeString(val)}\"");
                    w.WriteLine();
                }

                if (result.DecryptorPatterns.Count > 0)
                {
                    w.WriteLine("// ==== Decryptor Patterns ====");
                    foreach (var p in result.DecryptorPatterns)
                        w.WriteLine($"[0x{p.Address:X}] {p.PatternName}: {p.Description}");
                }
            }
        }

        private static string EscapeString(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
        }
    }
}
