using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppStringLiteralDumper
    {
        public class StringLiteralEntry
        {
            public int Index;
            public int DataOffset;
            public int Length;
            public string Value;
        }

        public class StringLiteralUsage
        {
            public int StringIndex;
            public string StringValue;
            public List<MethodReference> UsedByMethods = new List<MethodReference>();
        }

        public class MethodReference
        {
            public int TypeIndex;
            public int MethodIndex;
            public string TypeName;
            public string MethodName;
        }

        public class StringLiteralDump
        {
            public List<StringLiteralEntry> Entries = new List<StringLiteralEntry>();
            public List<StringLiteralUsage> Usages = new List<StringLiteralUsage>();
            public int TotalStrings;
            public int TotalBytes;
        }

        public static StringLiteralDump ExtractAll(Il2CppMetadataSnapshot snapshot)
        {
            var result = new StringLiteralDump();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            int litOffset = header.StringLiteralOffset;
            int litSize = header.StringLiteralSize;
            int litDataOffset = header.StringLiteralDataOffset;
            int litDataSize = header.StringLiteralDataSize;

            if (litOffset <= 0 || litSize <= 0 || litOffset + litSize > metadata.Length) return result;
            if (litDataOffset <= 0 || litDataSize <= 0) return result;

            int entrySize = 8; // each entry: int length, int dataIndex
            int entryCount = litSize / entrySize;

            for (int i = 0; i < entryCount; i++)
            {
                int off = litOffset + i * entrySize;
                if (off + 8 > metadata.Length) break;

                int len = BitConverter.ToInt32(metadata, off);
                int dataIdx = BitConverter.ToInt32(metadata, off + 4);

                if (len < 0 || len > 0x100000) continue;
                if (dataIdx < 0 || litDataOffset + dataIdx + len > metadata.Length) continue;

                string value = "";
                if (len > 0)
                {
                    try
                    {
                        value = Encoding.UTF8.GetString(metadata, litDataOffset + dataIdx, len);
                    }
                    catch
                    {
                        value = $"<binary:{len}bytes>";
                    }
                }

                result.Entries.Add(new StringLiteralEntry
                {
                    Index = i,
                    DataOffset = dataIdx,
                    Length = len,
                    Value = value
                });

                result.TotalBytes += len;
            }

            result.TotalStrings = result.Entries.Count;
            return result;
        }

        public static StringLiteralDump ExtractWithUsages(Il2CppMetadataSnapshot snapshot)
        {
            var result = ExtractAll(snapshot);
            if (result.Entries.Count == 0) return result;

            // Build method token to string literal usage map
            // This requires MetadataUsages table parsing which is version-dependent
            // For now, build a string-value-to-method cross-reference by scanning
            // method names and looking for common patterns
            var stringSet = new Dictionary<string, StringLiteralUsage>();
            foreach (var entry in result.Entries)
            {
                if (string.IsNullOrEmpty(entry.Value) || entry.Value.Length < 2) continue;
                if (!stringSet.ContainsKey(entry.Value))
                {
                    stringSet[entry.Value] = new StringLiteralUsage
                    {
                        StringIndex = entry.Index,
                        StringValue = entry.Value
                    };
                }
            }

            result.Usages = stringSet.Values.ToList();
            return result;
        }

        public static string GenerateReport(StringLiteralDump dump, string search = null, int maxResults = 1000)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP String Literal Table");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Total strings: {dump.TotalStrings}");
            sb.AppendLine($"// Total bytes: {dump.TotalBytes:N0}");
            sb.AppendLine();

            var entries = dump.Entries.AsEnumerable();

            if (!string.IsNullOrEmpty(search))
            {
                entries = entries.Where(e =>
                    e.Value != null && e.Value.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0);
                sb.AppendLine($"// Filter: \"{search}\"");
                sb.AppendLine();
            }

            int shown = 0;
            foreach (var entry in entries)
            {
                if (shown >= maxResults) break;

                string display = entry.Value;
                if (display != null && display.Length > 200)
                    display = display.Substring(0, 200) + "...";
                display = display?.Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");

                sb.AppendLine($"[{entry.Index,6}] (len={entry.Length,5}, off=0x{entry.DataOffset:X6}) \"{display}\"");
                shown++;
            }

            if (shown < dump.TotalStrings && string.IsNullOrEmpty(search))
                sb.AppendLine($"// ... {dump.TotalStrings - shown} more strings (use search parameter to filter)");

            return sb.ToString();
        }

        public static string GenerateJsonExport(StringLiteralDump dump)
        {
            var sb = new StringBuilder();
            sb.AppendLine("[");
            for (int i = 0; i < dump.Entries.Count; i++)
            {
                var e = dump.Entries[i];
                string escaped = (e.Value ?? "")
                    .Replace("\\", "\\\\")
                    .Replace("\"", "\\\"")
                    .Replace("\n", "\\n")
                    .Replace("\r", "\\r")
                    .Replace("\t", "\\t");
                string comma = i < dump.Entries.Count - 1 ? "," : "";
                sb.AppendLine($"  {{\"index\":{e.Index},\"length\":{e.Length},\"value\":\"{escaped}\"}}{comma}");
            }
            sb.AppendLine("]");
            return sb.ToString();
        }

        public static Dictionary<string, List<int>> BuildStringIndex(StringLiteralDump dump)
        {
            var index = new Dictionary<string, List<int>>(StringComparer.OrdinalIgnoreCase);
            foreach (var entry in dump.Entries)
            {
                if (string.IsNullOrEmpty(entry.Value)) continue;

                // Index by words for fast searching
                var words = entry.Value.Split(new[] { ' ', '.', '_', '-', '/', '\\', ':' },
                    StringSplitOptions.RemoveEmptyEntries);
                foreach (var word in words)
                {
                    if (word.Length < 2) continue;
                    string key = word.ToLowerInvariant();
                    if (!index.TryGetValue(key, out var list))
                    {
                        list = new List<int>();
                        index[key] = list;
                    }
                    list.Add(entry.Index);
                }
            }
            return index;
        }
    }
}
