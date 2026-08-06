using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using ModelContextProtocol.Server;
using KsDumperClient.Driver;

namespace KsMcpServer.Tools
{
    [McpServerToolType]
    public class PatternTools
    {
        private readonly IMemoryReader _driver;

        public PatternTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Scans process memory for a byte pattern with wildcard support. Pattern format: '48 89 5C 24 ?? 48 89 74' where ?? is wildcard. Returns matching addresses.")]
        public string ScanPattern(int pid, string pattern, int maxResults = 100)
        {
            if (maxResults > 10000) maxResults = 10000;

            byte[] patternBytes = ParsePattern(pattern, out byte wildcard);
            if (patternBytes == null || patternBytes.Length == 0)
                return "Invalid pattern. Use format: '48 89 5C 24 ?? 48 89 74' where ?? is wildcard.";

            var matches = _driver.FindPattern(pid, patternBytes, wildcard, maxResults);
            if (matches == null || matches.Count == 0)
                return $"No matches found for pattern '{pattern}' in PID {pid}.";

            var sb = new StringBuilder();
            sb.AppendLine($"Found {matches.Count} match(es) for pattern:");
            sb.AppendLine($"Pattern: {pattern}");
            sb.AppendLine();

            foreach (var addr in matches)
            {
                sb.AppendLine($"  0x{addr:X16}");
            }

            return sb.ToString();
        }

        [McpServerTool, Description("Searches for a text string in process memory. Returns addresses where the string was found.")]
        public string ScanString(int pid, string searchText, bool unicode = false, int maxResults = 100)
        {
            byte[] searchBytes;
            if (unicode)
                searchBytes = Encoding.Unicode.GetBytes(searchText);
            else
                searchBytes = Encoding.ASCII.GetBytes(searchText);

            var matches = _driver.FindPattern(pid, searchBytes, 0xFF, maxResults); // 0xFF = no wildcard (exact match)
            if (matches == null || matches.Count == 0)
                return $"String '{searchText}' not found in PID {pid}.";

            var sb = new StringBuilder();
            sb.AppendLine($"Found {matches.Count} occurrence(s) of '{searchText}' ({(unicode ? "Unicode" : "ASCII")}):");

            foreach (var addr in matches)
            {
                sb.AppendLine($"  0x{addr:X16}");
            }

            return sb.ToString();
        }

        [McpServerTool, Description("Dumps all readable strings from a process's memory. Minimum length defaults to 6 characters.")]
        public string DumpStrings(int pid, int minLength = 6, int maxResults = 500)
        {
            var strings = _driver.DumpLiveStrings(pid, minLength);
            if (strings == null || strings.Count == 0)
                return $"No strings found in PID {pid}.";

            var sb = new StringBuilder();
            int count = 0;

            foreach (var (address, isUnicode, value) in strings)
            {
                if (count >= maxResults) break;
                string encoding = isUnicode ? "U" : "A";
                sb.AppendLine($"[{encoding}] 0x{address:X16}  {EscapeString(value)}");
                count++;
            }

            sb.AppendLine();
            sb.AppendLine($"Total: {strings.Count} strings found, showing {count}");
            return sb.ToString();
        }

        private byte[] ParsePattern(string pattern, out byte wildcard)
        {
            wildcard = 0xCC;
            if (string.IsNullOrEmpty(pattern)) return null;

            var parts = pattern.Trim().Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            var bytes = new List<byte>();

            foreach (var part in parts)
            {
                if (part == "??" || part == "?")
                {
                    bytes.Add(wildcard);
                }
                else
                {
                    if (!byte.TryParse(part, System.Globalization.NumberStyles.HexNumber, null, out byte b))
                        return null;
                    bytes.Add(b);
                }
            }

            return bytes.ToArray();
        }

        private string EscapeString(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                if (c >= 32 && c < 127)
                    sb.Append(c);
                else
                    sb.Append('.');
            }
            return sb.ToString();
        }
    }
}
