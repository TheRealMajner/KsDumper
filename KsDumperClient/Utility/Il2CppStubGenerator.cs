using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static KsDumperClient.Utility.Il2CppDumper;
using static KsDumperClient.Utility.Il2CppSdkGenerator;

namespace KsDumperClient.Utility
{
    public static class Il2CppStubGenerator
    {
        // ===== VTable Reconstruction =====

        public class VTableEntry
        {
            public int Slot;
            public int MethodIndex;
            public string MethodName;
            public string DeclaringTypeName;
            public bool IsOverride;
        }

        public class TypeVTable
        {
            public int TypeIndex;
            public string TypeName;
            public List<VTableEntry> Entries = new List<VTableEntry>();
        }

        public static Dictionary<int, TypeVTable> ReconstructVTables(Il2CppMetadataSnapshot snapshot)
        {
            var result = new Dictionary<int, TypeVTable>();
            if (snapshot?.TypeDefinitions == null || snapshot.Methods == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            for (int ti = 0; ti < snapshot.TypeDefinitions.Length; ti++)
            {
                var td = snapshot.TypeDefinitions[ti];
                if (td.VTableCount == 0) continue;

                string typeName = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);
                string ns = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);
                string fullName = string.IsNullOrEmpty(ns) ? typeName : $"{ns}.{typeName}";

                var vtable = new TypeVTable { TypeIndex = ti, TypeName = fullName };

                // VTableMethods are encoded method indices stored as int[]
                // Each entry in the VTable metadata is a method index (could be from this type or parent)
                // We reconstruct by mapping method slots
                for (int mi = td.MethodStart; mi < td.MethodStart + td.MethodCount && mi < snapshot.Methods.Length; mi++)
                {
                    var md = snapshot.Methods[mi];
                    if (md.Slot == 0xFFFF) continue; // not a virtual method

                    string methodName = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)md.NameIndex);
                    bool isOverride = (md.Flags & 0x0040) != 0 && // Virtual
                                     (md.Flags & 0x0100) == 0;   // Not NewSlot (= override)

                    vtable.Entries.Add(new VTableEntry
                    {
                        Slot = md.Slot,
                        MethodIndex = mi,
                        MethodName = methodName,
                        DeclaringTypeName = fullName,
                        IsOverride = isOverride
                    });
                }

                if (vtable.Entries.Count > 0)
                {
                    vtable.Entries.Sort((a, b) => a.Slot.CompareTo(b.Slot));
                    result[ti] = vtable;
                }
            }

            return result;
        }

        // ===== Full .cs Stub Generation =====

        public static void GenerateStubFiles(
            List<Il2CppClassInfo> classes,
            Il2CppMetadataSnapshot snapshot,
            Dictionary<int, TypeVTable> vtables,
            string outputDir)
        {
            Directory.CreateDirectory(outputDir);

            // Group by image (assembly)
            var byImage = classes
                .GroupBy(c => c.ImageName ?? "Unknown")
                .OrderBy(g => g.Key);

            foreach (var imageGroup in byImage)
            {
                string imageName = imageGroup.Key.Replace(".dll", "");
                string safeImageName = SanitizePath(imageName);
                string imageDir = Path.Combine(outputDir, safeImageName);
                Directory.CreateDirectory(imageDir);

                // Group by namespace
                var byNamespace = imageGroup
                    .GroupBy(c => c.Namespace ?? "")
                    .OrderBy(g => g.Key);

                foreach (var nsGroup in byNamespace)
                {
                    string nsDir = imageDir;
                    if (!string.IsNullOrEmpty(nsGroup.Key))
                    {
                        nsDir = Path.Combine(imageDir, nsGroup.Key.Replace('.', Path.DirectorySeparatorChar));
                        Directory.CreateDirectory(nsDir);
                    }

                    foreach (var cls in nsGroup)
                    {
                        string stubContent = GenerateClassStub(cls, snapshot, vtables);
                        string fileName = SanitizePath(cls.Name) + ".cs";
                        string filePath = Path.Combine(nsDir, fileName);
                        File.WriteAllText(filePath, stubContent, Encoding.UTF8);
                    }
                }
            }
        }

        public static string GenerateClassStub(
            Il2CppClassInfo cls,
            Il2CppMetadataSnapshot snapshot,
            Dictionary<int, TypeVTable> vtables)
        {
            var sb = new StringBuilder();

            // File header
            sb.AppendLine("// Auto-generated by KsDumper IL2CPP Stub Generator");
            sb.AppendLine("// Do not edit — regenerate from metadata");
            sb.AppendLine();

            // Usings
            sb.AppendLine("using System;");
            sb.AppendLine("using System.Collections.Generic;");
            sb.AppendLine("using UnityEngine;");
            sb.AppendLine();

            // Namespace
            bool hasNamespace = !string.IsNullOrEmpty(cls.Namespace);
            if (hasNamespace)
            {
                sb.AppendLine($"namespace {cls.Namespace}");
                sb.AppendLine("{");
            }

            string indent = hasNamespace ? "    " : "";

            // Type declaration
            string accessMod = GetAccessModifier(cls.Flags);
            string typeMod = GetTypeModifiers(cls);
            string typeKind = cls.IsInterface ? "interface" : (cls.IsEnum ? "enum" : (cls.IsValueType ? "struct" : "class"));

            // Generic parameters
            string genericParams = "";
            if (cls.GenericParameterNames.Count > 0)
                genericParams = "<" + string.Join(", ", cls.GenericParameterNames) + ">";

            // Base type and interfaces
            var inherits = new List<string>();
            if (!string.IsNullOrEmpty(cls.BaseTypeName) && cls.BaseTypeName != "Object" &&
                cls.BaseTypeName != "ValueType" && cls.BaseTypeName != "Enum")
                inherits.Add(cls.BaseTypeName);
            inherits.AddRange(cls.InterfaceNames);

            string inheritStr = inherits.Count > 0 ? " : " + string.Join(", ", inherits) : "";

            // Attributes
            if (cls.IsSerializable)
                sb.AppendLine($"{indent}[Serializable]");

            sb.AppendLine($"{indent}{accessMod} {typeMod}{typeKind} {EscapeIdentifier(cls.Name)}{genericParams}{inheritStr}");
            sb.AppendLine($"{indent}{{");

            string memberIndent = indent + "    ";

            // Enum values
            if (cls.IsEnum)
            {
                foreach (var field in cls.Fields)
                {
                    if (field.Name == "value__") continue;
                    if (field.FieldOffset != 0)
                        sb.AppendLine($"{memberIndent}{EscapeIdentifier(field.Name)} = {field.FieldOffset},");
                    else
                        sb.AppendLine($"{memberIndent}{EscapeIdentifier(field.Name)},");
                }
                sb.AppendLine($"{indent}}}");
                if (hasNamespace) sb.AppendLine("}");
                return sb.ToString();
            }

            // Fields
            if (cls.Fields.Count > 0)
            {
                sb.AppendLine($"{memberIndent}// Fields");
                foreach (var field in cls.Fields)
                {
                    string fAccess = GetFieldAccessModifier(field);
                    string fStatic = field.IsStatic ? "static " : "";
                    string fType = field.TypeName ?? "object";
                    string offsetComment = "";
                    if (!field.IsStatic && field.FieldOffset > 0)
                        offsetComment = $" // 0x{field.FieldOffset:X}";
                    if (field.IsSerializeField)
                        sb.AppendLine($"{memberIndent}[SerializeField]");
                    sb.AppendLine($"{memberIndent}{fAccess} {fStatic}{fType} {EscapeIdentifier(field.Name)};{offsetComment}");
                }
                sb.AppendLine();
            }

            // Properties
            if (cls.Properties.Count > 0)
            {
                sb.AppendLine($"{memberIndent}// Properties");
                foreach (var prop in cls.Properties)
                {
                    string pType = prop.TypeName ?? "object";
                    string getSet = "";
                    if (!string.IsNullOrEmpty(prop.GetterName)) getSet += " get;";
                    if (!string.IsNullOrEmpty(prop.SetterName)) getSet += " set;";
                    if (string.IsNullOrEmpty(getSet)) getSet = " get; set;";
                    sb.AppendLine($"{memberIndent}public {pType} {EscapeIdentifier(prop.Name)} {{{getSet} }}");
                }
                sb.AppendLine();
            }

            // Events
            if (cls.Events.Count > 0)
            {
                sb.AppendLine($"{memberIndent}// Events");
                foreach (var evt in cls.Events)
                {
                    string eType = evt.TypeName ?? "EventHandler";
                    sb.AppendLine($"{memberIndent}public event {eType} {EscapeIdentifier(evt.Name)};");
                }
                sb.AppendLine();
            }

            // Methods
            if (cls.Methods.Count > 0)
            {
                sb.AppendLine($"{memberIndent}// Methods");
                foreach (var method in cls.Methods)
                {
                    string mAccess = GetMethodAccessModifier(method.Flags);
                    bool isStatic = (method.Flags & 0x0010) != 0;
                    bool isVirtual = (method.Flags & 0x0040) != 0;
                    bool isAbstract = (method.Flags & 0x0400) != 0;
                    bool isNewSlot = (method.Flags & 0x0100) != 0;

                    string modifiers = "";
                    if (isStatic) modifiers += "static ";
                    else if (isAbstract) modifiers += "abstract ";
                    else if (isVirtual && isNewSlot) modifiers += "virtual ";
                    else if (isVirtual && !isNewSlot) modifiers += "override ";

                    string retType = method.ReturnTypeName ?? "void";
                    string genericMethodParams = "";
                    if (method.IsGeneric && method.GenericParameterNames != null && method.GenericParameterNames.Length > 0)
                        genericMethodParams = "<" + string.Join(", ", method.GenericParameterNames) + ">";

                    // Parameters
                    var paramParts = new List<string>();
                    for (int pi = 0; pi < method.ParameterCount; pi++)
                    {
                        string pType = (method.ParameterTypeNames != null && pi < method.ParameterTypeNames.Length)
                            ? method.ParameterTypeNames[pi] : "object";
                        string pName = (method.ParameterNames != null && pi < method.ParameterNames.Length)
                            ? method.ParameterNames[pi] : $"arg{pi}";
                        paramParts.Add($"{pType} {EscapeIdentifier(pName)}");
                    }

                    string rvaComment = method.Rva > 0 ? $" // RVA: 0x{method.Rva:X}" : "";

                    if (cls.IsInterface || isAbstract)
                    {
                        sb.AppendLine($"{memberIndent}{mAccess} {modifiers}{retType} {EscapeIdentifier(method.Name)}{genericMethodParams}({string.Join(", ", paramParts)});{rvaComment}");
                    }
                    else
                    {
                        sb.AppendLine($"{memberIndent}{mAccess} {modifiers}extern {retType} {EscapeIdentifier(method.Name)}{genericMethodParams}({string.Join(", ", paramParts)});{rvaComment}");
                    }
                }
            }

            sb.AppendLine($"{indent}}}");
            if (hasNamespace) sb.AppendLine("}");

            return sb.ToString();
        }

        // ===== VTable dump =====

        public static string GenerateVTableDump(Dictionary<int, TypeVTable> vtables)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP VTable Reconstruction");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Types with vtables: {vtables.Count}");
            sb.AppendLine();

            foreach (var kvp in vtables.OrderBy(v => v.Value.TypeName))
            {
                var vt = kvp.Value;
                sb.AppendLine($"// {vt.TypeName} ({vt.Entries.Count} virtual methods)");
                foreach (var e in vt.Entries)
                {
                    string prefix = e.IsOverride ? "override" : "virtual ";
                    sb.AppendLine($"//   slot {e.Slot,3}: {prefix} {e.MethodName}");
                }
                sb.AppendLine();
            }

            return sb.ToString();
        }

        // ===== Helpers =====

        private static string GetAccessModifier(uint flags)
        {
            uint vis = flags & 0x07;
            switch (vis)
            {
                case 0x01: return "public";
                case 0x00: return "internal";
                case 0x02: return "internal";
                default: return "public";
            }
        }

        private static string GetTypeModifiers(Il2CppClassInfo cls)
        {
            if (cls.IsInterface) return "";
            uint flags = cls.Flags;
            string mods = "";
            if ((flags & 0x0080) != 0) mods += "abstract ";
            if ((flags & 0x0100) != 0) mods += "sealed ";
            if ((flags & 0x0400) != 0 && !cls.IsValueType) mods += "static ";
            return mods;
        }

        private static string GetFieldAccessModifier(Il2CppFieldInfo field)
        {
            return "public"; // metadata doesn't carry full field access in our model; default public for stubs
        }

        private static string GetMethodAccessModifier(ushort flags)
        {
            uint access = (uint)(flags & 0x0007);
            switch (access)
            {
                case 0x0006: return "public";
                case 0x0005: return "protected internal";
                case 0x0004: return "protected";
                case 0x0003: return "internal";
                case 0x0002: return "private protected";
                case 0x0001: return "private";
                default: return "private";
            }
        }

        private static string EscapeIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_empty";
            string[] keywords = { "abstract", "as", "base", "bool", "break", "byte", "case", "catch",
                "char", "checked", "class", "const", "continue", "decimal", "default", "delegate",
                "do", "double", "else", "enum", "event", "explicit", "extern", "false", "finally",
                "fixed", "float", "for", "foreach", "goto", "if", "implicit", "in", "int", "interface",
                "internal", "is", "lock", "long", "namespace", "new", "null", "object", "operator",
                "out", "override", "params", "private", "protected", "public", "readonly", "ref",
                "return", "sbyte", "sealed", "short", "sizeof", "stackalloc", "static", "string",
                "struct", "switch", "this", "throw", "true", "try", "typeof", "uint", "ulong",
                "unchecked", "unsafe", "ushort", "using", "virtual", "void", "volatile", "while" };
            if (Array.IndexOf(keywords, name) >= 0) return "@" + name;

            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
                sb.Append(char.IsLetterOrDigit(c) || c == '_' ? c : '_');
            string result = sb.ToString();
            if (result.Length > 0 && char.IsDigit(result[0]))
                result = "_" + result;
            return result;
        }

        private static string SanitizePath(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_empty";
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                if (char.IsLetterOrDigit(c) || c == '_' || c == '-' || c == '.')
                    sb.Append(c);
                else
                    sb.Append('_');
            }
            return sb.ToString();
        }
    }
}
