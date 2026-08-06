using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Xml;
using static KsDumperClient.Utility.Il2CppSdkGenerator;

namespace KsDumperClient.Utility
{
    public static class ReClassExporter
    {
        private static readonly Dictionary<string, (string rcType, int size)> TypeMap = new Dictionary<string, (string, int)>(StringComparer.OrdinalIgnoreCase)
        {
            { "System.Boolean", ("Bool", 1) }, { "bool", ("Bool", 1) },
            { "System.Byte", ("UInt8", 1) }, { "byte", ("UInt8", 1) },
            { "System.SByte", ("Int8", 1) }, { "sbyte", ("Int8", 1) },
            { "System.Int16", ("Int16", 2) }, { "short", ("Int16", 2) },
            { "System.UInt16", ("UInt16", 2) }, { "ushort", ("UInt16", 2) },
            { "System.Int32", ("Int32", 4) }, { "int", ("Int32", 4) },
            { "System.UInt32", ("UInt32", 4) }, { "uint", ("UInt32", 4) },
            { "System.Int64", ("Int64", 8) }, { "long", ("Int64", 8) },
            { "System.UInt64", ("UInt64", 8) }, { "ulong", ("UInt64", 8) },
            { "System.Single", ("Float", 4) }, { "float", ("Float", 4) },
            { "System.Double", ("Double", 8) }, { "double", ("Double", 8) },
            { "System.IntPtr", ("Hex64", 8) }, { "System.UIntPtr", ("Hex64", 8) },
        };

        public static string ExportToReClassXml(List<Il2CppClassInfo> classes, string projectName = "KsDumper")
        {
            var sb = new StringBuilder();

            sb.AppendLine("<?xml version=\"1.0\" encoding=\"utf-8\"?>");
            sb.AppendLine($"<ReClassNet Version=\"1.2\" Platform=\"x64\" Type=\"Default\">");

            // Custom data section
            sb.AppendLine("  <CustomData>");
            sb.AppendLine($"    <Data Name=\"Generator\">KsDumper IL2CPP</Data>");
            sb.AppendLine($"    <Data Name=\"GeneratedAt\">{DateTime.Now:yyyy-MM-dd HH:mm:ss}</Data>");
            sb.AppendLine($"    <Data Name=\"ClassCount\">{classes.Count}</Data>");
            sb.AppendLine("  </CustomData>");

            sb.AppendLine("  <Classes>");

            foreach (var cls in classes)
            {
                if (cls.Fields.Count == 0 && cls.Methods.Count == 0) continue;

                string fullName = string.IsNullOrEmpty(cls.Namespace) ? cls.Name : $"{cls.Namespace}.{cls.Name}";
                string safeId = GenerateGuid(fullName);

                // Calculate total struct size from field offsets
                int structSize = CalculateStructSize(cls);

                sb.AppendLine($"    <Class Uuid=\"{safeId}\" Name=\"{EscapeXml(fullName)}\" Comment=\"\" Address=\"0\">");

                int currentOffset = 0;

                // Add Il2CppObject header (klass pointer + monitor)
                if (!cls.IsValueType)
                {
                    sb.AppendLine($"      <Node Name=\"klass\" Comment=\"Il2CppClass*\" Type=\"Hex64\" />");
                    sb.AppendLine($"      <Node Name=\"monitor\" Comment=\"MonitorData*\" Type=\"Hex64\" />");
                    currentOffset = 0x10;
                }

                // Sort fields by offset
                var sortedFields = cls.Fields
                    .Where(f => !f.IsStatic && f.FieldOffset > 0)
                    .OrderBy(f => f.FieldOffset)
                    .ToList();

                foreach (var field in sortedFields)
                {
                    int fieldOffset = field.FieldOffset;

                    // Add padding if needed
                    if (fieldOffset > currentOffset)
                    {
                        int padding = fieldOffset - currentOffset;
                        sb.AppendLine($"      <Node Name=\"\" Comment=\"padding\" Type=\"Array\">");
                        sb.AppendLine($"        <Array Count=\"{padding}\" />");
                        sb.AppendLine($"        <Node Name=\"\" Comment=\"\" Type=\"UInt8\" />");
                        sb.AppendLine($"      </Node>");
                        currentOffset = fieldOffset;
                    }

                    string typeName = field.TypeName ?? "object";
                    var (rcType, rcSize) = ResolveReClassType(typeName);

                    sb.AppendLine($"      <Node Name=\"{EscapeXml(field.Name)}\" Comment=\"0x{fieldOffset:X} {EscapeXml(typeName)}\" Type=\"{rcType}\" />");
                    currentOffset += rcSize;
                }

                // Fill remaining to reach struct size
                if (structSize > currentOffset)
                {
                    int tail = structSize - currentOffset;
                    sb.AppendLine($"      <Node Name=\"\" Comment=\"tail padding\" Type=\"Array\">");
                    sb.AppendLine($"        <Array Count=\"{tail}\" />");
                    sb.AppendLine($"        <Node Name=\"\" Comment=\"\" Type=\"UInt8\" />");
                    sb.AppendLine($"      </Node>");
                }

                sb.AppendLine($"    </Class>");
            }

            sb.AppendLine("  </Classes>");
            sb.AppendLine("</ReClassNet>");

            return sb.ToString();
        }

        public static void SaveReClassProject(List<Il2CppClassInfo> classes, string outputPath, string projectName = "KsDumper")
        {
            string xml = ExportToReClassXml(classes, projectName);
            File.WriteAllText(outputPath, xml, Encoding.UTF8);
        }

        public static string ExportSingleClass(Il2CppClassInfo cls)
        {
            return ExportToReClassXml(new List<Il2CppClassInfo> { cls });
        }

        public static string GenerateStructSummary(List<Il2CppClassInfo> classes)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - ReClass.NET Export Summary");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            int totalClasses = 0;
            int totalFields = 0;

            foreach (var cls in classes.Where(c => c.Fields.Count > 0 || c.Methods.Count > 0))
            {
                string fullName = string.IsNullOrEmpty(cls.Namespace) ? cls.Name : $"{cls.Namespace}.{cls.Name}";
                int size = CalculateStructSize(cls);
                int fieldCount = cls.Fields.Count(f => !f.IsStatic);

                sb.AppendLine($"  {fullName}: {fieldCount} fields, ~0x{size:X} bytes");
                totalClasses++;
                totalFields += fieldCount;
            }

            sb.AppendLine();
            sb.AppendLine($"// Total: {totalClasses} classes, {totalFields} instance fields");
            return sb.ToString();
        }

        private static int CalculateStructSize(Il2CppClassInfo cls)
        {
            int maxEnd = cls.IsValueType ? 0 : 0x10; // Il2CppObject header

            foreach (var field in cls.Fields)
            {
                if (field.IsStatic) continue;
                string typeName = field.TypeName ?? "object";
                var (_, size) = ResolveReClassType(typeName);
                int fieldEnd = field.FieldOffset + size;
                if (fieldEnd > maxEnd) maxEnd = fieldEnd;
            }

            // Align to 8 bytes
            return (maxEnd + 7) & ~7;
        }

        private static (string rcType, int size) ResolveReClassType(string typeName)
        {
            if (string.IsNullOrEmpty(typeName)) return ("Hex64", 8);

            if (TypeMap.TryGetValue(typeName, out var mapped))
                return mapped;

            // Strip array suffix
            if (typeName.EndsWith("[]"))
                return ("Hex64", 8); // pointer to array

            // String types
            if (typeName == "System.String" || typeName == "string" || typeName == "String")
                return ("Hex64", 8); // pointer

            // Vector types
            if (typeName == "UnityEngine.Vector2") return ("Vector2", 8);
            if (typeName == "UnityEngine.Vector3") return ("Vector3", 12);
            if (typeName == "UnityEngine.Vector4" || typeName == "UnityEngine.Quaternion") return ("Vector4", 16);
            if (typeName == "UnityEngine.Color") return ("Vector4", 16);
            if (typeName == "UnityEngine.Color32") return ("UInt32", 4);
            if (typeName == "UnityEngine.Rect") return ("Vector4", 16);
            if (typeName == "UnityEngine.Bounds") return ("Hex64", 24);
            if (typeName == "UnityEngine.Matrix4x4") return ("Matrix4x4", 64);

            // Reference types (class) → pointer
            return ("Hex64", 8);
        }

        private static string GenerateGuid(string input)
        {
            // Deterministic GUID from string name for stable IDs
            byte[] hash;
            using (var md5 = System.Security.Cryptography.MD5.Create())
                hash = md5.ComputeHash(Encoding.UTF8.GetBytes(input));
            return new Guid(hash).ToString("D");
        }

        private static string EscapeXml(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&apos;");
        }
    }
}
