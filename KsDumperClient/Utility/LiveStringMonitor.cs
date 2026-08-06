using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public class LiveStringMonitor : IDisposable
    {
        public struct StringAppearance
        {
            public ulong Address;
            public string Value;
            public bool IsUnicode;
            public DateTime FirstSeen;
            public string Source;
            public string DecryptedValue;
            public string DecryptionMethod;
            public double Confidence;
            public string Category;
            public bool IsDecrypted;
        }

        public event Action<StringAppearance> OnStringDetected;
        public event Action<string> OnLog;
        public event Action<int> OnScanComplete;

        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly HashSet<string> seenStrings;
        private readonly List<StringAppearance> allStrings;
        private readonly object syncLock;
        private CancellationTokenSource cts;
        private bool isMonitoring;

        private bool moduleMode;
        private ulong moduleBase;
        private uint moduleSize;
        private string moduleName;

        // Decryption settings
        private bool enableDecryption = true;
        private bool enableBase64 = true;
        private bool enableHexDecode = true;
        private bool enableXorScan = true;
        private bool enableRotScan = true;
        private int xorMaxKeyLen = 4;

        public bool IsMonitoring => isMonitoring;
        public int TotalStringsFound { get { lock (syncLock) return allStrings.Count; } }
        public int ScanCount { get; private set; }

        // Decryption toggles
        public bool EnableDecryption { get => enableDecryption; set => enableDecryption = value; }
        public bool EnableBase64 { get => enableBase64; set => enableBase64 = value; }
        public bool EnableHexDecode { get => enableHexDecode; set => enableHexDecode = value; }
        public bool EnableXorScan { get => enableXorScan; set => enableXorScan = value; }
        public bool EnableRotScan { get => enableRotScan; set => enableRotScan = value; }

        public LiveStringMonitor(IMemoryReader driver, int processId)
        {
            this.driver = driver;
            this.processId = processId;
            seenStrings = new HashSet<string>();
            allStrings = new List<StringAppearance>();
            syncLock = new object();
        }

        public void StartMonitoring(TimeSpan interval, bool fullProcess = true)
        {
            if (isMonitoring) return;
            moduleMode = !fullProcess;
            cts = new CancellationTokenSource();
            isMonitoring = true;
            Task.Run(() => MonitorLoop(interval));
            Log("Live monitor started (interval: {0}s, mode: {1}, decryption: {2})", interval.TotalSeconds, fullProcess ? "full process" : "module", enableDecryption ? "on" : "off");
        }

        public void StartMonitoring(TimeSpan interval, ulong moduleBase, uint moduleSize, string moduleName)
        {
            if (isMonitoring) return;
            this.moduleMode = true;
            this.moduleBase = moduleBase;
            this.moduleSize = moduleSize;
            this.moduleName = moduleName;
            cts = new CancellationTokenSource();
            isMonitoring = true;
            Task.Run(() => MonitorLoop(interval));
            Log("Live monitor started for {0} (interval: {1}s)", moduleName, interval.TotalSeconds);
        }

        public void StopMonitoring()
        {
            if (!isMonitoring) return;
            cts?.Cancel();
            isMonitoring = false;
            Log("Live monitor stopped after {0} scans, {1} strings found", ScanCount, allStrings.Count);
        }

        public List<StringAppearance> GetAllStrings()
        {
            lock (syncLock) return new List<StringAppearance>(allStrings);
        }

        public void ClearHistory()
        {
            lock (syncLock)
            {
                seenStrings.Clear();
                allStrings.Clear();
            }
            ScanCount = 0;
        }

        private async Task MonitorLoop(TimeSpan interval)
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(interval, cts.Token);
                    if (cts.IsCancellationRequested) break;

                    var newStrings = PerformScan();
                    int newCount = 0;
                    int decryptedCount = 0;

                    foreach (var sa in newStrings)
                    {
                        bool isNew;
                        lock (syncLock)
                        {
                            // Check both raw and decrypted values for dedup
                            string dedupKey = sa.IsDecrypted ? $"D:{sa.DecryptedValue}" : sa.Value;
                            isNew = seenStrings.Add(dedupKey);
                            if (isNew) allStrings.Add(sa);
                        }
                        if (isNew)
                        {
                            newCount++;
                            if (sa.IsDecrypted) decryptedCount++;
                            try { OnStringDetected?.Invoke(sa); } catch { }
                        }
                    }

                    ScanCount++;
                    try { OnScanComplete?.Invoke(newCount); } catch { }

                    if (newCount > 0)
                        Log("Scan #{0}: {1} new strings ({2} decrypted, {3} total)", ScanCount, newCount, decryptedCount, allStrings.Count);
                }
                catch (OperationCanceledException) { break; }
                catch (Exception ex) { Log("Scan error: {0}", ex.Message); }
            }

            isMonitoring = false;
        }

        private List<StringAppearance> PerformScan()
        {
            var results = new List<StringAppearance>();

            try
            {
                if (!moduleMode)
                {
                    // Full process scan via driver
                    var liveStrings = driver.DumpLiveStrings(processId, 4);
                    foreach (var (addr, isUnicode, value) in liveStrings)
                    {
                        if (value.Length < 4) continue;
                        if (IsGarbageString(value)) continue;

                        var sa = new StringAppearance
                        {
                            Address = addr,
                            Value = value,
                            IsUnicode = isUnicode,
                            FirstSeen = DateTime.Now,
                            Source = "Process"
                        };

                        // Try decryption on the raw string
                        if (enableDecryption)
                            TryDecrypt(ref sa);

                        results.Add(sa);
                    }
                }
                else
                {
                    // Module-specific scan
                    int readSize = (int)Math.Min(moduleSize, 0x100000); // 1MB max
                    byte[] data = ReadBytes(moduleBase, readSize);
                    if (data == null) return results;

                    // ASCII strings
                    ExtractAsciiStrings(data, moduleBase, results, moduleMode ? moduleName : "Module");

                    // Unicode strings
                    ExtractUnicodeStrings(data, moduleBase, results, moduleMode ? moduleName : "Module");

                    // Encrypted region scan (XOR/ROT on non-printable regions)
                    if (enableXorScan || enableRotScan)
                    {
                        ScanEncryptedRegions(data, moduleBase, results);
                    }
                }
            }
            catch (Exception ex)
            {
                Log("PerformScan error: {0}", ex.Message);
            }

            return results;
        }

        // ---- Inline Decryption ----

        private void TryDecrypt(ref StringAppearance sa)
        {
            // Base64 detection
            if (enableBase64 && TryBase64Decode(sa.Value, out string b64Result))
            {
                sa.DecryptedValue = b64Result;
                sa.DecryptionMethod = "Base64";
                sa.Confidence = ScoreText(b64Result);
                sa.Category = CategorizeString(b64Result);
                sa.IsDecrypted = true;
                return;
            }

            // Hex-encoded string detection (e.g., "48656C6C6F" → "Hello")
            if (enableHexDecode && TryHexDecode(sa.Value, out string hexResult))
            {
                sa.DecryptedValue = hexResult;
                sa.DecryptionMethod = "Hex-Encoded";
                sa.Confidence = ScoreText(hexResult);
                sa.Category = CategorizeString(hexResult);
                sa.IsDecrypted = true;
                return;
            }

            // URL-encoded string
            if (TryUrlDecode(sa.Value, out string urlResult))
            {
                sa.DecryptedValue = urlResult;
                sa.DecryptionMethod = "URL-Encoded";
                sa.Confidence = ScoreText(urlResult);
                sa.Category = CategorizeString(urlResult);
                sa.IsDecrypted = true;
                return;
            }

            // ROT13 detection (check if ROT13 produces more English-like text)
            if (enableRotScan)
            {
                string rot13 = RotN(sa.Value, 13);
                double origScore = ScoreText(sa.Value);
                double rotScore = ScoreText(rot13);
                if (rotScore > origScore + 0.15 && rotScore >= 0.5)
                {
                    sa.DecryptedValue = rot13;
                    sa.DecryptionMethod = "ROT13";
                    sa.Confidence = rotScore;
                    sa.Category = CategorizeString(rot13);
                    sa.IsDecrypted = true;
                    return;
                }
            }

            // Categorize non-encrypted strings
            sa.Category = CategorizeString(sa.Value);
            sa.Confidence = ScoreText(sa.Value);
            sa.IsDecrypted = false;
        }

        private bool TryBase64Decode(string input, out string result)
        {
            result = null;
            if (input.Length < 8 || input.Length % 4 != 0) return false;

            // Quick check: only valid base64 chars
            if (!Regex.IsMatch(input, @"^[A-Za-z0-9+/]+={0,2}$")) return false;

            try
            {
                byte[] decoded = Convert.FromBase64String(input);
                string decodedStr = Encoding.UTF8.GetString(decoded);
                if (decodedStr.Length >= 4 && ScoreText(decodedStr) >= 0.4)
                {
                    result = decodedStr;
                    return true;
                }
            }
            catch { }
            return false;
        }

        private bool TryHexDecode(string input, out string result)
        {
            result = null;
            // Must be even length, all hex chars, at least 8 chars (4 bytes)
            if (input.Length < 8 || input.Length % 2 != 0) return false;
            if (!Regex.IsMatch(input, @"^[0-9a-fA-F]+$")) return false;

            try
            {
                byte[] bytes = new byte[input.Length / 2];
                for (int i = 0; i < bytes.Length; i++)
                    bytes[i] = Convert.ToByte(input.Substring(i * 2, 2), 16);

                string decoded = Encoding.ASCII.GetString(bytes);
                if (decoded.Length >= 4 && ScoreText(decoded) >= 0.6)
                {
                    result = decoded;
                    return true;
                }
            }
            catch { }
            return false;
        }

        private bool TryUrlDecode(string input, out string result)
        {
            result = null;
            if (!input.Contains("%") || input.Length < 6) return false;

            try
            {
                string decoded = Uri.UnescapeDataString(input);
                if (decoded != input && decoded.Length >= 4 && ScoreText(decoded) >= 0.4)
                {
                    result = decoded;
                    return true;
                }
            }
            catch { }
            return false;
        }

        private string RotN(string input, int shift)
        {
            char[] result = new char[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                char c = input[i];
                if (c >= 'A' && c <= 'Z')
                    result[i] = (char)('A' + (c - 'A' + shift) % 26);
                else if (c >= 'a' && c <= 'z')
                    result[i] = (char)('a' + (c - 'a' + shift) % 26);
                else
                    result[i] = c;
            }
            return new string(result);
        }

        // ---- Encrypted Region Scanner ----

        private void ScanEncryptedRegions(byte[] data, ulong baseAddress, List<StringAppearance> results)
        {
            int windowSize = 128;
            for (int i = 0; i <= data.Length - windowSize; i += 64)
            {
                // Check if region looks encrypted (high entropy, low printable)
                double entropy = ShannonEntropy(data, i, windowSize);
                double printable = PrintableRatio(data, i, windowSize);

                if (entropy < 5.5 || printable > 0.4 || printable < 0.01) continue;

                // Try XOR single-byte keys
                if (enableXorScan)
                {
                    for (int key = 1; key <= 255; key++)
                    {
                        byte[] decrypted = new byte[windowSize];
                        for (int j = 0; j < windowSize; j++)
                            decrypted[j] = (byte)(data[i + j] ^ key);

                        var extracted = ExtractStrings(decrypted, baseAddress + (ulong)i, $"XOR-1(0x{key:X2})");
                        foreach (var sa in extracted)
                        {
                            if (sa.Confidence >= 0.6)
                            {
                                results.Add(sa);
                                goto nextRegion; // Found a good result, move on
                            }
                        }
                    }
                }

                // Try ROT-N (2-25)
                if (enableRotScan)
                {
                    for (int shift = 2; shift <= 25; shift++)
                    {
                        if (shift == 13) continue; // Already handled above
                        byte[] rotated = new byte[windowSize];
                        for (int j = 0; j < windowSize; j++)
                        {
                            byte b = data[i + j];
                            if (b >= (byte)'A' && b <= (byte)'Z')
                                rotated[j] = (byte)('A' + (b - 'A' + shift) % 26);
                            else if (b >= (byte)'a' && b <= (byte)'z')
                                rotated[j] = (byte)('a' + (b - 'a' + shift) % 26);
                            else
                                rotated[j] = b;
                        }

                        var extracted = ExtractStrings(rotated, baseAddress + (ulong)i, $"ROT{shift}");
                        foreach (var sa in extracted)
                        {
                            if (sa.Confidence >= 0.6)
                            {
                                results.Add(sa);
                                goto nextRegion;
                            }
                        }
                    }
                }

                nextRegion:
                i += 64; // Skip ahead
            }
        }

        private List<StringAppearance> ExtractStrings(byte[] data, ulong baseAddress, string method)
        {
            var results = new List<StringAppearance>();
            int runStart = -1;

            for (int i = 0; i < data.Length; i++)
            {
                bool printable = data[i] >= 0x20 && data[i] < 0x7F;
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
                            string value = Encoding.ASCII.GetString(data, runStart, len);
                            double confidence = ScoreText(value);
                            if (confidence >= 0.4)
                            {
                                results.Add(new StringAppearance
                                {
                                    Address = baseAddress + (ulong)runStart,
                                    Value = BitConverter.ToString(data, runStart, Math.Min(len, 16)).Replace("-", " "),
                                    IsUnicode = false,
                                    FirstSeen = DateTime.Now,
                                    Source = method,
                                    DecryptedValue = value,
                                    DecryptionMethod = method,
                                    Confidence = confidence,
                                    Category = CategorizeString(value),
                                    IsDecrypted = true
                                });
                            }
                        }
                        runStart = -1;
                    }
                }
            }
            return results;
        }

        // ---- String extraction ----

        private void ExtractAsciiStrings(byte[] data, ulong baseAddress, List<StringAppearance> results, string source)
        {
            int runStart = -1;
            for (int i = 0; i < data.Length; i++)
            {
                bool printable = data[i] >= 0x20 && data[i] < 0x7F;
                if (printable)
                {
                    if (runStart < 0) runStart = i;
                }
                else
                {
                    if (runStart >= 0)
                    {
                        int len = i - runStart;
                        if (len >= 4)
                        {
                            string value = Encoding.ASCII.GetString(data, runStart, len);
                            var sa = new StringAppearance
                            {
                                Address = baseAddress + (ulong)runStart,
                                Value = value,
                                IsUnicode = false,
                                FirstSeen = DateTime.Now,
                                Source = source
                            };
                            if (enableDecryption) TryDecrypt(ref sa);
                            results.Add(sa);
                        }
                        runStart = -1;
                    }
                }
            }
        }

        private void ExtractUnicodeStrings(byte[] data, ulong baseAddress, List<StringAppearance> results, string source)
        {
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
                    if (charCount >= 4)
                    {
                        string value = Encoding.Unicode.GetString(data, runStart, charCount * 2);
                        var sa = new StringAppearance
                        {
                            Address = baseAddress + (ulong)runStart,
                            Value = value,
                            IsUnicode = true,
                            FirstSeen = DateTime.Now,
                            Source = source
                        };
                        if (enableDecryption) TryDecrypt(ref sa);
                        results.Add(sa);
                    }
                    runStart = -1;
                    charCount = 0;
                }
            }
        }

        // ---- Scoring and categorization ----

        private static double ScoreText(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4) return 0;

            int alpha = 0, digits = 0, space = 0, punct = 0, special = 0;
            foreach (char c in s)
            {
                if (char.IsLetter(c)) alpha++;
                else if (char.IsDigit(c)) digits++;
                else if (c == ' ') space++;
                else if (".,;:!?/\\-_()[]{}@#$%&*+=<>~`\"'".IndexOf(c) >= 0) punct++;
                else special++;
            }

            double textChars = alpha + digits + space + punct;
            double ratio = textChars / s.Length;

            double bonus = 0;
            if (space > 0 && alpha > 3) bonus += 0.1;
            if (s.Contains("://")) bonus += 0.15;
            if (s.Contains("\\") && alpha > 2) bonus += 0.1;
            if (s.Length > 4 && char.IsUpper(s[0]) && char.IsLower(s[1])) bonus += 0.05;

            double penalty = special > s.Length * 0.3 ? 0.2 : 0;

            return Math.Max(0, Math.Min(1.0, ratio + bonus - penalty));
        }

        private static string CategorizeString(string s)
        {
            if (s.Contains("://") || s.StartsWith("http") || s.StartsWith("www")) return "URL";
            if ((s.Contains("\\") || s.Contains("/")) && s.Length > 3 && (s.Length > 1 && (s[1] == ':' || s[0] == '/'))) return "File Path";
            if (s.StartsWith("HKEY_") || s.Contains("\\Registry\\")) return "Registry";
            if (Regex.IsMatch(s, @"^(Nt|Zw|Rtl)[A-Z]")) return "NT API";
            if (Regex.IsMatch(s, @"^[A-Z][a-zA-Z]+[A-Z]")) return "API/Class";
            if (s.EndsWith(".dll") || s.EndsWith(".exe") || s.EndsWith(".sys")) return "Module";
            if (s.Contains("Error") || s.Contains("error") || s.Contains("Failed") || s.Contains("failed")) return "Error Message";
            if (s.Contains("%s") || s.Contains("%d") || s.Contains("{0}")) return "Format String";
            if (Regex.IsMatch(s, @"^[a-z_][a-z0-9_]*$")) return "Identifier";
            if (s.Contains("=") || s.Contains("<") || s.Contains(">")) return "Expression";
            if (s.Length > 0 && (double)s.Count(c => c == ' ') / s.Length > 0.2) return "Message";
            return "String";
        }

        // ---- Garbage filter ----

        private static bool IsGarbageString(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4) return true;

            int alpha = 0, digits = 0, spaces = 0, nonLatin = 0, control = 0;
            int total = s.Length;

            foreach (char c in s)
            {
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) alpha++;
                else if (c >= '0' && c <= '9') digits++;
                else if (c == ' ') spaces++;
                else if (c > 0x2FFF) nonLatin++;
                else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') control++;
            }

            if (nonLatin > total * 0.3) return true;
            if (control > total * 0.3) return true;

            // Require at least 40% alphanumeric content
            double alphaNumRatio = (double)(alpha + digits) / total;
            if (alphaNumRatio < 0.4) return true;

            // Short strings need higher quality — at least 3 consecutive alpha chars
            if (total < 10 && alpha < 3) return true;

            // Quick-accept well-known patterns
            if (s.Contains("://") || s.Contains(":\\") || s.Contains("./")) return false;
            if (s.EndsWith(".dll") || s.EndsWith(".exe") || s.EndsWith(".sys") || s.EndsWith(".cfg")) return false;

            // Reject if no run of 3+ consecutive letters exists (random punctuation soup)
            bool hasLetterRun = false;
            int letterRun = 0;
            foreach (char c in s)
            {
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))
                {
                    letterRun++;
                    if (letterRun >= 3) { hasLetterRun = true; break; }
                }
                else letterRun = 0;
            }
            if (!hasLetterRun) return true;

            return false;
        }

        // ---- Helpers ----

        private static double ShannonEntropy(byte[] data, int offset, int length)
        {
            if (data == null || length == 0 || offset + length > data.Length) return 0;
            int[] freq = new int[256];
            for (int i = offset; i < offset + length; i++) freq[data[i]]++;
            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / length;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        private static double PrintableRatio(byte[] data, int offset, int length)
        {
            if (data == null || length == 0 || offset + length > data.Length) return 0;
            int printable = 0;
            for (int i = offset; i < offset + length; i++)
                if (data[i] >= 0x20 && data[i] < 0x7F) printable++;
            return (double)printable / length;
        }

        private byte[] ReadBytes(ulong address, int size)
        {
            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, buf, size)) return null;
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private void Log(string message, params object[] args)
        {
            try { OnLog?.Invoke(string.Format(message, args)); } catch { }
        }

        public void Dispose()
        {
            StopMonitoring();
            cts?.Dispose();
        }
    }
}
