using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class AutoSignatureGenerator
    {
        public class SignatureResult
        {
            public ulong Address;
            public string Pattern;
            public string Mask;
            public string IDAPattern;
            public string X64DbgPattern;
            public string CEPattern;
            public string YaraHex;
            public int Length;
            public int WildcardCount;
            public bool IsUnique;
            public int MatchCount;
        }

        public static SignatureResult GenerateSignature(
            IMemoryReader driver, int pid,
            ulong address, ulong moduleBase, uint moduleSize,
            int sigLength = 32, int minLength = 8)
        {
            byte[] code = ReadMemory(driver, pid, address, sigLength);
            if (code == null) return null;

            // Read the full module .text section for uniqueness checking
            byte[] moduleData = ReadMemory(driver, pid, moduleBase, (int)Math.Min(moduleSize, 0x4000000));
            if (moduleData == null) return null;

            // Build mask: wildcard bytes that are likely relocations
            bool[] isWild = new bool[sigLength];
            MarkRelocations(code, isWild, address, moduleBase, moduleSize);

            // Find shortest unique signature
            int bestLen = sigLength;
            for (int tryLen = minLength; tryLen <= sigLength; tryLen++)
            {
                int matches = CountMatches(moduleData, code, isWild, tryLen);
                if (matches == 1)
                {
                    bestLen = tryLen;
                    break;
                }
            }

            int finalMatches = CountMatches(moduleData, code, isWild, bestLen);

            var result = new SignatureResult
            {
                Address = address,
                Length = bestLen,
                IsUnique = finalMatches == 1,
                MatchCount = finalMatches
            };

            // Build pattern strings in various formats
            var patBytes = new StringBuilder();
            var maskBytes = new StringBuilder();
            var idaPattern = new StringBuilder();
            var x64dbgPattern = new StringBuilder();
            var cePattern = new StringBuilder();
            var yaraHex = new StringBuilder();
            int wildcardCount = 0;

            for (int i = 0; i < bestLen; i++)
            {
                if (isWild[i])
                {
                    patBytes.Append("\\x00");
                    maskBytes.Append('?');
                    idaPattern.Append("? ");
                    x64dbgPattern.Append("?? ");
                    cePattern.Append("?? ");
                    yaraHex.Append("?? ");
                    wildcardCount++;
                }
                else
                {
                    patBytes.Append($"\\x{code[i]:X2}");
                    maskBytes.Append('x');
                    idaPattern.Append($"{code[i]:X2} ");
                    x64dbgPattern.Append($"{code[i]:X2} ");
                    cePattern.Append($"{code[i]:X2} ");
                    yaraHex.Append($"{code[i]:X2} ");
                }
            }

            result.Pattern = patBytes.ToString();
            result.Mask = maskBytes.ToString();
            result.IDAPattern = idaPattern.ToString().TrimEnd();
            result.X64DbgPattern = x64dbgPattern.ToString().TrimEnd();
            result.CEPattern = cePattern.ToString().TrimEnd();
            result.YaraHex = "{ " + yaraHex.ToString().TrimEnd() + " }";
            result.WildcardCount = wildcardCount;

            return result;
        }

        public static List<SignatureResult> GenerateMultiple(
            IMemoryReader driver, int pid,
            ulong moduleBase, uint moduleSize,
            List<(ulong address, string name)> targets,
            int sigLength = 32)
        {
            var results = new List<SignatureResult>();
            foreach (var (addr, name) in targets)
            {
                var sig = GenerateSignature(driver, pid, addr, moduleBase, moduleSize, sigLength);
                if (sig != null)
                    results.Add(sig);
            }
            return results;
        }

        private static void MarkRelocations(byte[] code, bool[] isWild, ulong codeAddr, ulong moduleBase, uint moduleSize)
        {
            ulong moduleEnd = moduleBase + moduleSize;

            for (int i = 0; i < code.Length; i++)
            {
                // E8/E9 rel32 — CALL/JMP relative (wildcard the 4 displacement bytes)
                if (i < code.Length - 5 && (code[i] == 0xE8 || code[i] == 0xE9))
                {
                    for (int j = 1; j <= 4 && i + j < code.Length; j++)
                        isWild[i + j] = true;
                    i += 4;
                    continue;
                }

                // 0F 8x rel32 — Jcc near (wildcard displacement)
                if (i < code.Length - 6 && code[i] == 0x0F && (code[i + 1] & 0xF0) == 0x80)
                {
                    for (int j = 2; j <= 5 && i + j < code.Length; j++)
                        isWild[i + j] = true;
                    i += 5;
                    continue;
                }

                // FF 15/25 disp32 — indirect CALL/JMP through IAT
                if (i < code.Length - 6 && code[i] == 0xFF && (code[i + 1] == 0x15 || code[i + 1] == 0x25))
                {
                    for (int j = 2; j <= 5 && i + j < code.Length; j++)
                        isWild[i + j] = true;
                    i += 5;
                    continue;
                }

                // LEA with RIP-relative: 48 8D xx disp32
                if (i < code.Length - 7 && code[i] == 0x48 && code[i + 1] == 0x8D)
                {
                    byte modrm = code[i + 2];
                    if ((modrm & 0xC7) == 0x05) // [rip+disp32]
                    {
                        for (int j = 3; j <= 6 && i + j < code.Length; j++)
                            isWild[i + j] = true;
                        i += 6;
                        continue;
                    }
                }

                // MOV with RIP-relative: 48 8B 05/0D/15/1D/25/2D/35/3D disp32
                if (i < code.Length - 7 && code[i] == 0x48 && code[i + 1] == 0x8B)
                {
                    byte modrm = code[i + 2];
                    if ((modrm & 0xC7) == 0x05)
                    {
                        for (int j = 3; j <= 6 && i + j < code.Length; j++)
                            isWild[i + j] = true;
                        i += 6;
                        continue;
                    }
                }

                // MOV r64, imm64 (48 B8+ imm64) — absolute address
                if (i < code.Length - 10 && code[i] == 0x48 && (code[i + 1] & 0xF8) == 0xB8)
                {
                    long imm = BitConverter.ToInt64(code, i + 2);
                    if ((ulong)imm >= moduleBase && (ulong)imm < moduleEnd)
                    {
                        for (int j = 2; j <= 9 && i + j < code.Length; j++)
                            isWild[i + j] = true;
                        i += 9;
                    }
                }
            }
        }

        private static int CountMatches(byte[] haystack, byte[] needle, bool[] mask, int length)
        {
            int count = 0;
            for (int i = 0; i <= haystack.Length - length; i++)
            {
                bool match = true;
                for (int j = 0; j < length; j++)
                {
                    if (!mask[j] && haystack[i + j] != needle[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match) count++;
                if (count > 10) break;
            }
            return count;
        }

        public static string GenerateReport(SignatureResult sig, string name = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Auto Signature Generator");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            if (!string.IsNullOrEmpty(name))
                sb.AppendLine($"// Target: {name}");
            sb.AppendLine($"// Address: 0x{sig.Address:X16}");
            sb.AppendLine($"// Length: {sig.Length} bytes ({sig.WildcardCount} wildcards)");
            sb.AppendLine($"// Unique: {sig.IsUnique} (matches: {sig.MatchCount})");
            sb.AppendLine();
            sb.AppendLine($"// IDA:     \"{sig.IDAPattern}\"");
            sb.AppendLine($"// x64dbg:  \"{sig.X64DbgPattern}\"");
            sb.AppendLine($"// CE:      \"{sig.CEPattern}\"");
            sb.AppendLine($"// C/C++:   \"{sig.Pattern}\" / \"{sig.Mask}\"");
            sb.AppendLine($"// YARA:    {sig.YaraHex}");

            return sb.ToString();
        }

        public static string GenerateMultiReport(List<SignatureResult> sigs, List<string> names = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Batch Signature Generation");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Total signatures: {sigs.Count}");
            sb.AppendLine($"// Unique: {sigs.Count(s => s.IsUnique)}");
            sb.AppendLine();

            for (int i = 0; i < sigs.Count; i++)
            {
                string name = names != null && i < names.Count ? names[i] : null;
                sb.AppendLine($"[{i}] {(name ?? $"0x{sigs[i].Address:X}")} ({(sigs[i].IsUnique ? "UNIQUE" : $"{sigs[i].MatchCount} matches")})");
                sb.AppendLine($"  IDA:  \"{sigs[i].IDAPattern}\"");
                sb.AppendLine($"  CE:   \"{sigs[i].CEPattern}\"");
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private static byte[] ReadMemory(IMemoryReader driver, int pid, ulong address, int size)
        {
            byte[] buf = new byte[size];
            GCHandle handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                if (!driver.CopyVirtualMemory(pid, (IntPtr)(long)address, handle.AddrOfPinnedObject(), size))
                    return null;
                return buf;
            }
            finally { handle.Free(); }
        }
    }
}
