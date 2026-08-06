using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace KsDumperClient.Utility
{
    /// <summary>
    /// Advanced string deduplication with fuzzy matching, similarity scoring,
    /// structural grouping, and text comparison.
    /// </summary>
    public static class StringDeduplicator
    {
        public struct DedupResult
        {
            public string Value;
            public bool IsUnicode;
            public List<ulong> Addresses;
            public int OccurrenceCount;
            public string StructuralPattern;
            public List<string> SimilarStrings;
            public double MaxSimilarity;
        }

        public struct DedupReport
        {
            public List<DedupResult> Results;
            public int TotalInput;
            public int UniqueExact;
            public int UniqueStructural;
            public int FuzzyGroups;
            public string Summary;
        }

        /// <summary>
        /// Basic exact-match deduplication (backward compatible).
        /// </summary>
        public static List<DedupResult> Deduplicate(List<(ulong address, bool isUnicode, string value)> strings)
        {
            var groups = new Dictionary<string, DedupResult>();

            foreach (var (address, isUnicode, value) in strings)
            {
                if (groups.TryGetValue(value, out var existing))
                {
                    existing.Addresses.Add(address);
                    existing.OccurrenceCount = existing.Addresses.Count;
                    groups[value] = existing;
                }
                else
                {
                    groups[value] = new DedupResult
                    {
                        Value = value,
                        IsUnicode = isUnicode,
                        Addresses = new List<ulong> { address },
                        OccurrenceCount = 1,
                        StructuralPattern = GetStructuralPattern(value),
                        SimilarStrings = new List<string>(),
                        MaxSimilarity = 0
                    };
                }
            }

            var result = new List<DedupResult>(groups.Values);
            result.Sort((a, b) => b.OccurrenceCount.CompareTo(a.OccurrenceCount));
            return result;
        }

        /// <summary>
        /// Advanced deduplication with fuzzy matching and structural grouping.
        /// </summary>
        public static DedupReport DeduplicateAdvanced(
            List<(ulong address, bool isUnicode, string value)> strings,
            double similarityThreshold = 0.8)
        {
            // Phase 1: Exact dedup
            var exact = Deduplicate(strings);

            // Phase 2: Compute structural patterns and group
            var structuralGroups = new Dictionary<string, List<DedupResult>>();
            foreach (var d in exact)
            {
                string pattern = d.StructuralPattern;
                if (!structuralGroups.ContainsKey(pattern))
                    structuralGroups[pattern] = new List<DedupResult>();
                structuralGroups[pattern].Add(d);
            }

            // Phase 3: Fuzzy matching within structural groups
            int fuzzyGroups = 0;
            foreach (var group in structuralGroups.Values)
            {
                if (group.Count < 2) continue;

                // Find similar strings within the same structural group
                for (int i = 0; i < group.Count; i++)
                {
                    var current = group[i];
                    current.SimilarStrings = new List<string>();
                    current.MaxSimilarity = 0;

                    for (int j = 0; j < group.Count; j++)
                    {
                        if (i == j) continue;
                        double sim = ComputeSimilarity(current.Value, group[j].Value);
                        if (sim >= similarityThreshold)
                        {
                            current.SimilarStrings.Add(group[j].Value);
                            if (sim > current.MaxSimilarity)
                                current.MaxSimilarity = sim;
                        }
                    }

                    if (current.SimilarStrings.Count > 0)
                    {
                        group[i] = current;
                        fuzzyGroups++;
                    }
                }
            }

            // Phase 4: Sort by relevance (occurrence count × uniqueness)
            var results = exact.OrderByDescending(d => d.OccurrenceCount)
                               .ThenByDescending(d => 1.0 - d.MaxSimilarity)
                               .ToList();

            return new DedupReport
            {
                Results = results,
                TotalInput = strings.Count,
                UniqueExact = exact.Count,
                UniqueStructural = structuralGroups.Count,
                FuzzyGroups = fuzzyGroups,
                Summary = $"{strings.Count} input → {exact.Count} exact unique → {structuralGroups.Count} structural patterns ({fuzzyGroups} fuzzy matches)"
            };
        }

        /// <summary>
        /// Find strings similar to a query string in a list.
        /// </summary>
        public static List<(string value, double similarity)> FindSimilar(
            string query, List<DedupResult> candidates, double threshold = 0.6)
        {
            var results = new List<(string, double)>();
            string queryPattern = GetStructuralPattern(query);

            foreach (var c in candidates)
            {
                double sim = ComputeSimilarity(query, c.Value);

                // Bonus for same structural pattern
                if (c.StructuralPattern == queryPattern)
                    sim = Math.Min(1.0, sim + 0.1);

                if (sim >= threshold)
                    results.Add((c.Value, sim));
            }

            return results.OrderByDescending(r => r.Item2).ToList();
        }

        /// <summary>
        /// Compute similarity between two strings (0.0 to 1.0).
        /// Uses a combination of Levenshtein distance, Jaccard similarity, and structural matching.
        /// </summary>
        public static double ComputeSimilarity(string a, string b)
        {
            if (a == null || b == null) return 0;
            if (a == b) return 1.0;
            if (a.Length == 0 || b.Length == 0) return 0;

            // Length ratio penalty
            double lenRatio = (double)Math.Min(a.Length, b.Length) / Math.Max(a.Length, b.Length);
            if (lenRatio < 0.3) return 0; // Too different in length

            // Normalized Levenshtein similarity
            double levSim = 1.0 - (double)LevenshteinDistance(a, b) / Math.Max(a.Length, b.Length);

            // Bigram Jaccard similarity
            double jaccardSim = BigramJaccard(a, b);

            // Structural pattern match
            string patA = GetStructuralPattern(a);
            string patB = GetStructuralPattern(b);
            double structSim = patA == patB ? 1.0 : (patA.Length > 0 && patB.Length > 0 ? BigramJaccard(patA, patB) : 0);

            // Weighted combination
            return Math.Max(0, Math.Min(1.0,
                0.4 * levSim + 0.3 * jaccardSim + 0.3 * structSim));
        }

        /// <summary>
        /// Generate a structural pattern string that abstracts away specific values.
        /// Numbers → N, Hex → H, Paths → P, URLs → U, etc.
        /// </summary>
        public static string GetStructuralPattern(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";

            string result = s;

            // Replace URLs
            result = Regex.Replace(result, @"https?://[^\s""'<>]+", "<URL>");

            // Replace file paths (Windows and Unix)
            result = Regex.Replace(result, @"[A-Za-z]:\\[^\s""'<>]+", "<PATH>");
            result = Regex.Replace(result, @"/[a-zA-Z0-9_./-]+", "<PATH>");

            // Replace hex strings (8+ hex chars)
            result = Regex.Replace(result, @"\b[0-9a-fA-F]{8,}\b", "<HEX>");

            // Replace IP addresses
            result = Regex.Replace(result, @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<IP>");

            // Replace numbers (but keep short ones that might be enum values)
            result = Regex.Replace(result, @"\b\d{4,}\b", "<NUM>");

            // Replace GUIDs
            result = Regex.Replace(result, @"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", "<GUID>");

            // Replace timestamps
            result = Regex.Replace(result, @"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}", "<TIMESTAMP>");

            // Replace email addresses
            result = Regex.Replace(result, @"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "<EMAIL>");

            return result;
        }

        // ---- Internal algorithms ----

        /// <summary>
        /// Compute Levenshtein edit distance between two strings.
        /// Optimized with single-row DP for memory efficiency.
        /// </summary>
        private static int LevenshteinDistance(string a, string b)
        {
            // Optimize: use shorter string for columns
            if (a.Length > b.Length)
            {
                string tmp = a; a = b; b = tmp;
            }

            int m = a.Length;
            int n = b.Length;

            // Early exit for very different lengths
            if (n - m > m) return n; // Too different

            int[] prev = new int[m + 1];
            int[] curr = new int[m + 1];

            for (int i = 0; i <= m; i++) prev[i] = i;

            for (int j = 1; j <= n; j++)
            {
                curr[0] = j;
                for (int i = 1; i <= m; i++)
                {
                    int cost = a[i - 1] == b[j - 1] ? 0 : 1;
                    curr[i] = Math.Min(Math.Min(
                        curr[i - 1] + 1,      // Insert
                        prev[i] + 1),          // Delete
                        prev[i - 1] + cost);   // Substitute
                }
                // Swap rows
                int[] temp = prev; prev = curr; curr = temp;
            }

            return prev[m];
        }

        /// <summary>
        /// Compute bigram Jaccard similarity between two strings.
        /// </summary>
        private static double BigramJaccard(string a, string b)
        {
            if (a.Length < 2 || b.Length < 2) return 0;

            var setA = new HashSet<string>();
            var setB = new HashSet<string>();

            for (int i = 0; i < a.Length - 1; i++)
                setA.Add(a.Substring(i, 2));
            for (int i = 0; i < b.Length - 1; i++)
                setB.Add(b.Substring(i, 2));

            int intersection = 0;
            foreach (var bigram in setA)
                if (setB.Contains(bigram))
                    intersection++;

            int union = setA.Count + setB.Count - intersection;
            return union == 0 ? 0 : (double)intersection / union;
        }
    }
}
