using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static KsDumperClient.Utility.Il2CppDumper;
using static KsDumperClient.Utility.Il2CppSdkGenerator;

namespace KsDumperClient.Utility
{
    public static class Il2CppXrefGraph
    {
        public class TypeReference
        {
            public int SourceTypeIndex;
            public int TargetTypeIndex;
            public string Kind; // "field", "method_return", "method_param", "base", "interface", "event", "property", "nested"
            public string Detail;
        }

        public class XrefResult
        {
            public List<TypeReference> References = new List<TypeReference>();
            public Dictionary<int, List<int>> TypeToUsers = new Dictionary<int, List<int>>();
            public Dictionary<int, List<int>> TypeToUsed = new Dictionary<int, List<int>>();
            public int TotalEdges;
        }

        public static XrefResult BuildXrefGraph(Il2CppMetadataSnapshot snapshot)
        {
            var result = new XrefResult();
            if (snapshot == null || snapshot.TypeDefinitions == null) return result;

            var typeDefs = snapshot.TypeDefinitions;

            for (int ti = 0; ti < typeDefs.Length; ti++)
            {
                var td = typeDefs[ti];

                // Base type reference
                if (td.ParentIndex >= 0 && td.ParentIndex < typeDefs.Length && td.ParentIndex != ti)
                    AddRef(result, ti, td.ParentIndex, "base", null);

                // Interface references
                if (snapshot.InterfaceIndices != null)
                {
                    for (int ii = td.InterfacesStart; ii < td.InterfacesStart + td.InterfaceCount; ii++)
                    {
                        if (ii < 0 || ii >= snapshot.InterfaceIndices.Length) break;
                        int ifaceIdx = snapshot.InterfaceIndices[ii];
                        if (ifaceIdx >= 0 && ifaceIdx < typeDefs.Length && ifaceIdx != ti)
                            AddRef(result, ti, ifaceIdx, "interface", null);
                    }
                }

                // Nested type references
                if (snapshot.NestedTypeIndices != null)
                {
                    int nestedStart = td.RgctxStartIndex; // nested types start varies; use available data
                    // Actually nested types use VTableStart-based offset in some versions
                    // but NestedTypeIndices is a flat array referenced by some mechanism
                }

                // Field type references
                if (snapshot.Fields != null)
                {
                    int fieldEnd = td.FieldStart + td.FieldCount;
                    for (int fi = td.FieldStart; fi < fieldEnd && fi < snapshot.Fields.Length; fi++)
                    {
                        int fieldTypeIdx = snapshot.Fields[fi].TypeIndex;
                        if (fieldTypeIdx >= 0 && fieldTypeIdx < typeDefs.Length && fieldTypeIdx != ti)
                            AddRef(result, ti, fieldTypeIdx, "field", null);
                    }
                }

                // Method return type and parameter type references
                if (snapshot.Methods != null)
                {
                    int methodEnd = td.MethodStart + td.MethodCount;
                    for (int mi = td.MethodStart; mi < methodEnd && mi < snapshot.Methods.Length; mi++)
                    {
                        var md = snapshot.Methods[mi];

                        int retIdx = md.ReturnType;
                        if (retIdx >= 0 && retIdx < typeDefs.Length && retIdx != ti)
                            AddRef(result, ti, retIdx, "method_return", null);

                        if (snapshot.Parameters != null)
                        {
                            for (int pi = md.ParameterStart; pi < md.ParameterStart + md.ParameterCount; pi++)
                            {
                                if (pi < 0 || pi >= snapshot.Parameters.Length) break;
                                int paramTypeIdx = snapshot.Parameters[pi].TypeIndex;
                                if (paramTypeIdx >= 0 && paramTypeIdx < typeDefs.Length && paramTypeIdx != ti)
                                    AddRef(result, ti, paramTypeIdx, "method_param", null);
                            }
                        }
                    }
                }

                // Event type references
                if (snapshot.Events != null)
                {
                    int eventEnd = td.EventStart + td.EventCount;
                    for (int ei = td.EventStart; ei < eventEnd && ei < snapshot.Events.Length; ei++)
                    {
                        int evtTypeIdx = snapshot.Events[ei].TypeIndex;
                        if (evtTypeIdx >= 0 && evtTypeIdx < typeDefs.Length && evtTypeIdx != ti)
                            AddRef(result, ti, evtTypeIdx, "event", null);
                    }
                }
            }

            result.TotalEdges = result.References.Count;
            return result;
        }

        private static void AddRef(XrefResult result, int source, int target, string kind, string detail)
        {
            result.References.Add(new TypeReference
            {
                SourceTypeIndex = source,
                TargetTypeIndex = target,
                Kind = kind,
                Detail = detail
            });

            if (!result.TypeToUsed.TryGetValue(source, out var usedList))
            {
                usedList = new List<int>();
                result.TypeToUsed[source] = usedList;
            }
            if (!usedList.Contains(target))
                usedList.Add(target);

            if (!result.TypeToUsers.TryGetValue(target, out var usersList))
            {
                usersList = new List<int>();
                result.TypeToUsers[target] = usersList;
            }
            if (!usersList.Contains(source))
                usersList.Add(source);
        }

        public static string QueryUsersOf(XrefResult xref, int typeIndex, Il2CppMetadataSnapshot snapshot)
        {
            var sb = new StringBuilder();
            string typeName = GetTypeName(typeIndex, snapshot);
            sb.AppendLine($"// Types that reference: {typeName} (index {typeIndex})");
            sb.AppendLine();

            if (!xref.TypeToUsers.TryGetValue(typeIndex, out var users) || users.Count == 0)
            {
                sb.AppendLine("// No references found");
                return sb.ToString();
            }

            var grouped = xref.References
                .Where(r => r.TargetTypeIndex == typeIndex)
                .GroupBy(r => r.SourceTypeIndex);

            foreach (var g in grouped)
            {
                string srcName = GetTypeName(g.Key, snapshot);
                var kinds = g.Select(r => r.Kind).Distinct().ToArray();
                sb.AppendLine($"  {srcName} [{string.Join(", ", kinds)}]");
            }

            sb.AppendLine();
            sb.AppendLine($"// Total: {users.Count} types reference {typeName}");
            return sb.ToString();
        }

        public static string QueryUsedBy(XrefResult xref, int typeIndex, Il2CppMetadataSnapshot snapshot)
        {
            var sb = new StringBuilder();
            string typeName = GetTypeName(typeIndex, snapshot);
            sb.AppendLine($"// Types referenced by: {typeName} (index {typeIndex})");
            sb.AppendLine();

            if (!xref.TypeToUsed.TryGetValue(typeIndex, out var used) || used.Count == 0)
            {
                sb.AppendLine("// No outgoing references");
                return sb.ToString();
            }

            var grouped = xref.References
                .Where(r => r.SourceTypeIndex == typeIndex)
                .GroupBy(r => r.TargetTypeIndex);

            foreach (var g in grouped)
            {
                string tgtName = GetTypeName(g.Key, snapshot);
                var kinds = g.Select(r => r.Kind).Distinct().ToArray();
                sb.AppendLine($"  {tgtName} [{string.Join(", ", kinds)}]");
            }

            sb.AppendLine();
            sb.AppendLine($"// Total: {used.Count} types referenced by {typeName}");
            return sb.ToString();
        }

        public static string GenerateFullGraph(XrefResult xref, Il2CppMetadataSnapshot snapshot, int maxEdges = 5000)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Type Cross-Reference Graph");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Total edges: {xref.TotalEdges}");
            sb.AppendLine($"// Types with incoming refs: {xref.TypeToUsers.Count}");
            sb.AppendLine($"// Types with outgoing refs: {xref.TypeToUsed.Count}");
            sb.AppendLine();

            // Top referenced types
            sb.AppendLine("// === Most Referenced Types ===");
            var topReferenced = xref.TypeToUsers
                .OrderByDescending(kvp => kvp.Value.Count)
                .Take(50);

            foreach (var kvp in topReferenced)
            {
                string name = GetTypeName(kvp.Key, snapshot);
                sb.AppendLine($"//   {name}: {kvp.Value.Count} incoming refs");
            }
            sb.AppendLine();

            // Edge list (truncated)
            sb.AppendLine("// === Edge List (source -> target [kind]) ===");
            int count = 0;
            foreach (var r in xref.References)
            {
                if (count >= maxEdges) break;
                string src = GetTypeName(r.SourceTypeIndex, snapshot);
                string tgt = GetTypeName(r.TargetTypeIndex, snapshot);
                sb.AppendLine($"{src} -> {tgt} [{r.Kind}]");
                count++;
            }

            if (xref.References.Count > maxEdges)
                sb.AppendLine($"// ... truncated ({xref.References.Count - maxEdges} more edges)");

            return sb.ToString();
        }

        private static string GetTypeName(int typeIndex, Il2CppMetadataSnapshot snapshot)
        {
            if (typeIndex < 0 || typeIndex >= snapshot.TypeDefinitions.Length)
                return $"<type:{typeIndex}>";

            var td = snapshot.TypeDefinitions[typeIndex];
            string ns = ReadStringFromTable(snapshot.RawMetadata, snapshot.Header.StringOffset, snapshot.Header.StringSize, td.NamespaceIndex);
            string name = ReadStringFromTable(snapshot.RawMetadata, snapshot.Header.StringOffset, snapshot.Header.StringSize, td.NameIndex);
            return string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
        }
    }
}
