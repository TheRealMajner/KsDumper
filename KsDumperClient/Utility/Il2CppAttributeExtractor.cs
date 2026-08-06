using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppAttributeExtractor
    {
        public class AttributeInfo
        {
            public string AttributeName;
            public int AttributeTypeIndex;
            public int CustomAttributeIndex;
        }

        public class TypeAttributes
        {
            public string TypeName;
            public uint Token;
            public List<AttributeInfo> Attributes = new List<AttributeInfo>();
        }

        public class MethodAttributes
        {
            public string MethodName;
            public string DeclaringType;
            public uint Token;
            public List<AttributeInfo> Attributes = new List<AttributeInfo>();
        }

        public class FieldAttributes
        {
            public string FieldName;
            public string DeclaringType;
            public uint Token;
            public List<AttributeInfo> Attributes = new List<AttributeInfo>();
        }

        public class AttributeExtractionResult
        {
            public List<TypeAttributes> TypesWithAttributes = new List<TypeAttributes>();
            public List<MethodAttributes> MethodsWithAttributes = new List<MethodAttributes>();
            public List<FieldAttributes> FieldsWithAttributes = new List<FieldAttributes>();
            public Dictionary<string, int> AttributeUsageCounts = new Dictionary<string, int>();
            public int TotalAttributes;
        }

        public static AttributeExtractionResult ExtractAttributes(
            Il2CppMetadataSnapshot snapshot,
            string filter = null,
            int maxEntries = 5000)
        {
            var result = new AttributeExtractionResult();

            if (snapshot == null || snapshot.RawMetadata == null || snapshot.Header == null)
                return result;

            var header = snapshot.Header;
            byte[] metadata = snapshot.RawMetadata;

            // Walk parsed type definitions
            if (snapshot.TypeDefinitions != null)
            {
                for (int i = 0; i < snapshot.TypeDefinitions.Length && result.TypesWithAttributes.Count < maxEntries; i++)
                {
                    var td = snapshot.TypeDefinitions[i];
                    if (td.CustomAttributeIndex < 0) continue;

                    string name = ReadStringFromTable(metadata, (int)header.StringOffset, (int)header.StringSize, td.NameIndex);
                    string ns = ReadStringFromTable(metadata, (int)header.StringOffset, (int)header.StringSize, td.NamespaceIndex);
                    string fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";

                    if (!string.IsNullOrEmpty(filter) &&
                        fullName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;

                    var attrs = ResolveCustomAttributes(metadata, header, td.CustomAttributeIndex, snapshot.TypeDefinitions);
                    if (attrs.Count == 0) continue;

                    var typeAttrs = new TypeAttributes
                    {
                        TypeName = fullName,
                        Token = td.Token,
                        Attributes = attrs
                    };

                    result.TotalAttributes += attrs.Count;
                    foreach (var attr in attrs)
                        CountAttribute(result.AttributeUsageCounts, attr.AttributeName);

                    result.TypesWithAttributes.Add(typeAttrs);
                }
            }

            // Walk parsed method definitions
            if (snapshot.Methods != null)
            {
                for (int i = 0; i < snapshot.Methods.Length && result.MethodsWithAttributes.Count < maxEntries; i++)
                {
                    var md = snapshot.Methods[i];
                    if (md.CustomAttributeIndex < 0) continue;

                    string methodName = ReadStringFromTable(metadata, (int)header.StringOffset, (int)header.StringSize, (int)md.NameIndex);
                    string declTypeName = GetTypeNameFromDefs(snapshot.TypeDefinitions, metadata, header, md.DeclaringType);
                    string fullMethodName = $"{declTypeName}::{methodName}";

                    if (!string.IsNullOrEmpty(filter) &&
                        fullMethodName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;

                    var attrs = ResolveCustomAttributes(metadata, header, md.CustomAttributeIndex, snapshot.TypeDefinitions);
                    if (attrs.Count == 0) continue;

                    var methodAttrs = new MethodAttributes
                    {
                        MethodName = methodName,
                        DeclaringType = declTypeName,
                        Token = md.Token,
                        Attributes = attrs
                    };

                    result.TotalAttributes += attrs.Count;
                    foreach (var attr in attrs)
                        CountAttribute(result.AttributeUsageCounts, attr.AttributeName);

                    result.MethodsWithAttributes.Add(methodAttrs);
                }
            }

            // Walk parsed field definitions (fields don't have CustomAttributeIndex directly)
            // Skip fields for now — they use token-based lookup which requires the full attribute generator table

            return result;
        }

        private static List<AttributeInfo> ResolveCustomAttributes(
            byte[] metadata, Il2CppMetadataHeader header, int customAttributeIndex,
            Il2CppTypeDefinition[] typeDefs)
        {
            var attrs = new List<AttributeInfo>();
            if (customAttributeIndex < 0) return attrs;

            int rangeTableOffset = (int)header.AttributeDataRangeOffset;
            int rangeTableSize = (int)header.AttributeDataRangeSize;

            if (rangeTableOffset == 0 || rangeTableSize == 0) return attrs;

            // Each range entry: { int32 token, int32 startRange } (v27+) or { int32 start, int32 count } (older)
            // Try both interpretations
            int entryOffset = rangeTableOffset + customAttributeIndex * 8;
            if (entryOffset + 8 > metadata.Length) return attrs;

            int start = BitConverter.ToInt32(metadata, entryOffset);
            int count = BitConverter.ToInt32(metadata, entryOffset + 4);

            if (count <= 0 || count > 100 || start < 0) return attrs;

            // Read attribute type indices from the attribute data blob
            int dataOffset = (int)header.AttributeDataOffset;
            if (dataOffset == 0) return attrs;

            // Attribute type indices stored sequentially
            for (int i = 0; i < count; i++)
            {
                int typeIdxOffset = dataOffset + (start + i) * 4;
                if (typeIdxOffset + 4 > metadata.Length) break;

                int typeIdx = BitConverter.ToInt32(metadata, typeIdxOffset);
                string attrName = GetTypeNameFromDefs(typeDefs, metadata, header, typeIdx);

                attrs.Add(new AttributeInfo
                {
                    AttributeName = attrName,
                    AttributeTypeIndex = typeIdx,
                    CustomAttributeIndex = customAttributeIndex
                });
            }

            return attrs;
        }

        private static string GetTypeNameFromDefs(
            Il2CppTypeDefinition[] typeDefs, byte[] metadata, Il2CppMetadataHeader header, int typeIndex)
        {
            if (typeDefs == null || typeIndex < 0 || typeIndex >= typeDefs.Length)
                return $"Type_{typeIndex}";

            var td = typeDefs[typeIndex];
            string name = ReadStringFromTable(metadata, (int)header.StringOffset, (int)header.StringSize, td.NameIndex);
            string ns = ReadStringFromTable(metadata, (int)header.StringOffset, (int)header.StringSize, td.NamespaceIndex);

            return string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
        }

        private static void CountAttribute(Dictionary<string, int> counts, string name)
        {
            if (!counts.ContainsKey(name))
                counts[name] = 0;
            counts[name]++;
        }

        public static string GenerateReport(AttributeExtractionResult result, string attributeFilter = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Attribute Extractor");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Types with attributes: {result.TypesWithAttributes.Count}");
            sb.AppendLine($"// Methods with attributes: {result.MethodsWithAttributes.Count}");
            sb.AppendLine($"// Total attributes: {result.TotalAttributes}");
            sb.AppendLine();

            if (result.AttributeUsageCounts.Count > 0)
            {
                sb.AppendLine("// Most used attributes:");
                foreach (var kvp in result.AttributeUsageCounts.OrderByDescending(k => k.Value).Take(30))
                    sb.AppendLine($"//   [{kvp.Key}]: {kvp.Value} usages");
                sb.AppendLine();
            }

            Func<AttributeInfo, bool> attrMatch = a =>
                string.IsNullOrEmpty(attributeFilter) ||
                a.AttributeName.IndexOf(attributeFilter, StringComparison.OrdinalIgnoreCase) >= 0;

            var filteredTypes = result.TypesWithAttributes.Where(t => t.Attributes.Any(attrMatch));
            foreach (var type in filteredTypes.OrderBy(t => t.TypeName))
            {
                sb.AppendLine($"[Type] {type.TypeName} (token: 0x{type.Token:X8})");
                foreach (var attr in type.Attributes.Where(attrMatch))
                    sb.AppendLine($"  [{attr.AttributeName}]");
                sb.AppendLine();
            }

            var filteredMethods = result.MethodsWithAttributes.Where(m => m.Attributes.Any(attrMatch));
            foreach (var method in filteredMethods.OrderBy(m => m.DeclaringType).ThenBy(m => m.MethodName).Take(500))
            {
                sb.AppendLine($"[Method] {method.DeclaringType}::{method.MethodName} (token: 0x{method.Token:X8})");
                foreach (var attr in method.Attributes.Where(attrMatch))
                    sb.AppendLine($"  [{attr.AttributeName}]");
                sb.AppendLine();
            }

            return sb.ToString();
        }
    }
}
