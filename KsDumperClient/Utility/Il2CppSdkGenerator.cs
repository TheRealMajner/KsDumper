using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppSdkGenerator
    {
        // ---------- SDK data model ----------

        public class Il2CppMethodInfo
        {
            public string Name;
            public uint Token;
            public ushort Flags;
            public ushort Slot;
            public int ParameterCount;
            public string[] ParameterNames;
            public string ReturnTypeName;
            public string[] ParameterTypeNames;
            public uint Rva;
            public bool IsGeneric;
            public string[] GenericParameterNames;
        }

        public class Il2CppFieldInfo
        {
            public string Name;
            public int TypeIndex;
            public uint Token;
            public string TypeName;
            public int FieldOffset;
            public bool IsStatic;
            public bool IsSerializeField;
        }

        public class Il2CppPropertyInfo
        {
            public string Name;
            public uint Attrs;
            public uint Token;
            public string TypeName;
            public string GetterName;
            public string SetterName;
        }

        public class Il2CppEventInfo
        {
            public string Name;
            public string TypeName;
            public uint Token;
        }

        public class Il2CppClassInfo
        {
            public string Namespace;
            public string Name;
            public string FullName;
            public string BaseTypeName;
            public uint Flags;
            public uint Token;
            public List<Il2CppFieldInfo> Fields = new List<Il2CppFieldInfo>();
            public List<Il2CppMethodInfo> Methods = new List<Il2CppMethodInfo>();
            public List<Il2CppPropertyInfo> Properties = new List<Il2CppPropertyInfo>();
            public List<Il2CppEventInfo> Events = new List<Il2CppEventInfo>();
            public List<string> InterfaceNames = new List<string>();
            public List<string> GenericParameterNames = new List<string>();
            public string ImageName;
            public bool IsSerializable;
            public bool IsValueType => (Flags & 0x00000020) != 0; // tdValueType
            public bool IsEnum => (Flags & 0x00000020) != 0 && BaseTypeName == "Enum";
            public bool IsInterface => (Flags & 0x00000020) == 0 && (Flags & 0x00000100) != 0;
        }

        // ---------- Type name resolution ----------

        // Il2CppTypeEnum values from il2cpp-class-internals.h
        private static readonly Dictionary<int, string> PrimitiveTypeNames = new Dictionary<int, string>
        {
            { 1,  "void" },
            { 2,  "bool" },
            { 3,  "char" },
            { 4,  "sbyte" },
            { 5,  "byte" },
            { 6,  "short" },
            { 7,  "ushort" },
            { 8,  "int" },
            { 9,  "uint" },
            { 10, "long" },
            { 11, "ulong" },
            { 12, "float" },
            { 13, "double" },
            { 14, "string" },
            { 18, "IntPtr" },
            { 19, "UIntPtr" },
            { 24, "object" },
            { 25, "Array" },
        };

        private static string[] BuildTypeNameLookup(Il2CppTypeDefinition[] typeDefs, byte[] metadata, int stringOffset, int stringSize)
        {
            var names = new string[typeDefs.Length];
            for (int i = 0; i < typeDefs.Length; i++)
            {
                string ns = ReadStringFromTable(metadata, stringOffset, stringSize, typeDefs[i].NamespaceIndex);
                string name = ReadStringFromTable(metadata, stringOffset, stringSize, typeDefs[i].NameIndex);
                names[i] = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
            }
            return names;
        }

        private static Il2CppMetadataSnapshot _currentSnapshot;

        private static string ResolveTypeIndex(int typeIndex, string[] typeNameLookup)
        {
            if (typeIndex >= 0 && typeIndex < typeNameLookup.Length)
                return typeNameLookup[typeIndex];

            if (typeIndex < 0)
            {
                int specIndex = -(typeIndex + 1);
                return ResolveTypeSpec(specIndex, typeNameLookup);
            }

            if (PrimitiveTypeNames.TryGetValue(typeIndex, out string primitive))
                return primitive;

            return $"/* type:{typeIndex} */";
        }

        private static string ResolveTypeSpec(int specIndex, string[] typeNameLookup)
        {
            // IL2CPP encodes type specs as:
            //   bit[0..7]  = Il2CppTypeEnum (element type)
            //   bit[8..31] = data (type def index, generic inst index, etc.)
            // In metadata-only mode we have limited info, but we can decode
            // common patterns using the type definitions and generic parameters.

            if (_currentSnapshot == null)
                return $"/* typespec:{specIndex} */";

            // specIndex can encode: SZARRAY, PTR, GENERICINST, BYREF
            // Without the binary Il2CppType table, we reconstruct using known conventions
            // Many IL2CPP versions encode: specIndex = typeIndex for array element types
            // Try common encodings

            // Convention 1: SZARRAY - the specIndex itself is the element type index
            // Convention 2: PTR - pointer to the element type
            // Convention 3: GENERICINST - generic instantiation

            // Since we can't read Il2CppType from binary, try a heuristic:
            // If specIndex falls within TypeDef range, it's likely an array of that type
            if (specIndex < typeNameLookup.Length)
            {
                string baseName = typeNameLookup[specIndex];
                if (!string.IsNullOrEmpty(baseName) && !baseName.StartsWith("/*"))
                    return baseName + "[]";
            }

            // Check if it maps to a generic parameter
            if (_currentSnapshot.GenericParameters != null && specIndex < _currentSnapshot.GenericParameters.Length)
            {
                var gp = _currentSnapshot.GenericParameters[specIndex];
                string gpName = Il2CppDumper.ReadStringFromTable(
                    _currentSnapshot.RawMetadata,
                    _currentSnapshot.Header.StringOffset,
                    _currentSnapshot.Header.StringSize,
                    (int)gp.NameIndex);
                if (!string.IsNullOrEmpty(gpName))
                    return gpName;
            }

            return $"/* typespec:{specIndex} */";
        }

        // ---------- Build class info ----------

        public static List<Il2CppClassInfo> BuildClassInfo(Il2CppMetadataSnapshot snapshot)
        {
            _currentSnapshot = snapshot;
            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;
            var typeDefs = snapshot.TypeDefinitions;
            var methods = snapshot.Methods;
            var fields = snapshot.Fields;
            var parameters = snapshot.Parameters;
            var properties = snapshot.Properties;

            int stringOffset = header.StringOffset;
            int stringSize = header.StringSize;

            // Build type name lookup for resolving base types and field types
            string[] typeNameLookup = BuildTypeNameLookup(typeDefs, metadata, stringOffset, stringSize);

            // Build image name lookup: typeDefIndex → imageName
            var imageNameByType = new Dictionary<int, string>();
            if (snapshot.Images != null)
            {
                foreach (var img in snapshot.Images)
                {
                    string imgName = ReadStringFromTable(metadata, stringOffset, stringSize, img.NameIndex);
                    for (int t = img.TypeStart; t < img.TypeStart + (int)img.TypeCount && t < typeDefs.Length; t++)
                        imageNameByType[t] = imgName;
                }
            }

            // Build set of MonoBehaviour-derived types (for SerializeField detection)
            var monoBehaviourTypes = new HashSet<int>();
            for (int i = 0; i < typeDefs.Length; i++)
            {
                int parentIdx = typeDefs[i].ParentIndex;
                while (parentIdx >= 0 && parentIdx < typeDefs.Length)
                {
                    string pname = ReadStringFromTable(metadata, stringOffset, stringSize, typeDefs[parentIdx].NameIndex);
                    if (pname == "MonoBehaviour" || pname == "ScriptableObject")
                    {
                        monoBehaviourTypes.Add(i);
                        break;
                    }
                    parentIdx = typeDefs[parentIdx].ParentIndex;
                    if (parentIdx == typeDefs[i].ParentIndex) break; // cycle guard
                }
            }

            var classes = new List<Il2CppClassInfo>(typeDefs.Length);

            for (int i = 0; i < typeDefs.Length; i++)
            {
                var td = typeDefs[i];
                string name = ReadStringFromTable(metadata, stringOffset, stringSize, td.NameIndex);
                string ns = ReadStringFromTable(metadata, stringOffset, stringSize, td.NamespaceIndex);

                if (string.IsNullOrEmpty(name) || name == "<Module>")
                    continue;

                // Resolve base type
                string baseTypeName = "";
                if (td.ParentIndex >= 0 && td.ParentIndex < typeNameLookup.Length)
                    baseTypeName = typeNameLookup[td.ParentIndex];

                imageNameByType.TryGetValue(i, out string imageName);
                bool isSerialized = (td.Flags & 0x00002000) != 0; // tdSerializable

                var classInfo = new Il2CppClassInfo
                {
                    Namespace = ns,
                    Name = name,
                    FullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}",
                    BaseTypeName = baseTypeName,
                    Flags = td.Flags,
                    Token = td.Token,
                    ImageName = imageName,
                    IsSerializable = isSerialized
                };

                // Add methods with resolved return types and parameter types
                if (td.MethodStart >= 0)
                {
                    int end = td.MethodStart + td.MethodCount;
                    for (int m = td.MethodStart; m < end && m < methods.Length; m++)
                    {
                        var md = methods[m];
                        string methodName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)md.NameIndex);

                        // Resolve parameter names and types
                        var paramNames = new string[md.ParameterCount];
                        var paramTypes = new string[md.ParameterCount];
                        if (md.ParameterStart >= 0)
                        {
                            for (int pi = 0; pi < md.ParameterCount && (md.ParameterStart + pi) < parameters.Length; pi++)
                            {
                                paramNames[pi] = ReadStringFromTable(metadata, stringOffset, stringSize, (int)parameters[md.ParameterStart + pi].NameIndex);
                                paramTypes[pi] = ResolveTypeIndex(parameters[md.ParameterStart + pi].TypeIndex, typeNameLookup);
                            }
                        }

                        // Resolve return type
                        string returnTypeName = ResolveTypeIndex(md.ReturnType, typeNameLookup);

                        // Check for generic parameters
                        bool isGeneric = td.GenericContainerIndex >= 0 && snapshot.GenericContainers != null
                            && td.GenericContainerIndex < snapshot.GenericContainers.Length;
                        string[] genericNames = null;
                        if (isGeneric)
                        {
                            var container = snapshot.GenericContainers[td.GenericContainerIndex];
                            if (container.TypeArgCount > 0 && snapshot.GenericParameters != null)
                            {
                                genericNames = new string[container.TypeArgCount];
                                for (int gi = 0; gi < container.TypeArgCount && (container.GenericParameterStart + gi) < snapshot.GenericParameters.Length; gi++)
                                {
                                    genericNames[gi] = ReadStringFromTable(metadata, stringOffset, stringSize, (int)snapshot.GenericParameters[container.GenericParameterStart + gi].NameIndex);
                                }
                            }
                        }

                        classInfo.Methods.Add(new Il2CppMethodInfo
                        {
                            Name = methodName,
                            Token = md.Token,
                            Flags = md.Flags,
                            Slot = md.Slot,
                            ParameterCount = md.ParameterCount,
                            ParameterNames = paramNames,
                            ParameterTypeNames = paramTypes,
                            ReturnTypeName = returnTypeName,
                            IsGeneric = isGeneric && md.GenericContainerIndex >= 0,
                            GenericParameterNames = genericNames
                        });
                    }
                }

                // Add fields with resolved types
                if (td.FieldStart >= 0)
                {
                    int end = td.FieldStart + td.FieldCount;
                    for (int f = td.FieldStart; f < end && f < fields.Length; f++)
                    {
                        var fd = fields[f];
                        string fieldName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)fd.NameIndex);
                        string fieldTypeName = ResolveTypeIndex(fd.TypeIndex, typeNameLookup);

                        bool isMonoField = monoBehaviourTypes.Contains(i);

                        classInfo.Fields.Add(new Il2CppFieldInfo
                        {
                            Name = fieldName,
                            TypeIndex = fd.TypeIndex,
                            Token = fd.Token,
                            TypeName = fieldTypeName,
                            FieldOffset = -1,
                            IsStatic = false,
                            IsSerializeField = isMonoField // public non-static fields in MonoBehaviour/ScriptableObject are serialized by Unity
                        });
                    }
                }

                // Add properties with resolved types and getter/setter names
                if (td.PropertyStart >= 0 && properties != null)
                {
                    int end = td.PropertyStart + td.PropertyCount;
                    for (int p = td.PropertyStart; p < end && p < properties.Length; p++)
                    {
                        var pd = properties[p];
                        string propName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)pd.NameIndex);

                        // Try to find getter/setter method names
                        string getterName = null;
                        string setterName = null;
                        if (pd.Get >= 0 && td.MethodStart >= 0 && (td.MethodStart + pd.Get) < methods.Length)
                            getterName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)methods[td.MethodStart + pd.Get].NameIndex);
                        if (pd.Set >= 0 && td.MethodStart >= 0 && (td.MethodStart + pd.Set) < methods.Length)
                            setterName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)methods[td.MethodStart + pd.Set].NameIndex);

                        classInfo.Properties.Add(new Il2CppPropertyInfo
                        {
                            Name = propName,
                            Attrs = pd.Attrs,
                            Token = pd.Token,
                            GetterName = getterName,
                            SetterName = setterName
                        });
                    }
                }

                // Add events
                if (td.EventStart >= 0 && snapshot.Events != null)
                {
                    int end = td.EventStart + td.EventCount;
                    for (int e = td.EventStart; e < end && e < snapshot.Events.Length; e++)
                    {
                        var ev = snapshot.Events[e];
                        string eventName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)ev.NameIndex);
                        string eventTypeName = ResolveTypeIndex(ev.TypeIndex, typeNameLookup);

                        classInfo.Events.Add(new Il2CppEventInfo
                        {
                            Name = eventName,
                            TypeName = eventTypeName,
                            Token = ev.Token
                        });
                    }
                }

                // Add interfaces
                if (td.InterfacesStart >= 0 && snapshot.InterfaceIndices != null)
                {
                    int end = td.InterfacesStart + td.InterfaceCount;
                    for (int ii = td.InterfacesStart; ii < end && ii < snapshot.InterfaceIndices.Length; ii++)
                    {
                        string ifaceName = ResolveTypeIndex(snapshot.InterfaceIndices[ii], typeNameLookup);
                        if (!string.IsNullOrEmpty(ifaceName))
                            classInfo.InterfaceNames.Add(ifaceName);
                    }
                }

                // Add generic parameters (class-level)
                if (td.GenericContainerIndex >= 0 && snapshot.GenericContainers != null
                    && td.GenericContainerIndex < snapshot.GenericContainers.Length)
                {
                    var container = snapshot.GenericContainers[td.GenericContainerIndex];
                    if (container.IsMethod == 0 && container.TypeArgCount > 0 && snapshot.GenericParameters != null)
                    {
                        for (int gi = 0; gi < container.TypeArgCount && (container.GenericParameterStart + gi) < snapshot.GenericParameters.Length; gi++)
                        {
                            string gpName = ReadStringFromTable(metadata, stringOffset, stringSize, (int)snapshot.GenericParameters[container.GenericParameterStart + gi].NameIndex);
                            classInfo.GenericParameterNames.Add(gpName);
                        }
                    }
                }

                classes.Add(classInfo);
            }

            return classes;
        }

        // ---------- SDK text generation ----------

        public static string GenerateSdk(List<Il2CppClassInfo> classes)
        {
            var sb = new StringBuilder(1024 * 1024); // pre-allocate 1MB

            // Header
            sb.AppendLine("// ==============================================================");
            sb.AppendLine("// KsDumper - IL2CPP SDK Dump (Enhanced)");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Total Classes: {classes.Count}");
            sb.AppendLine($"// Total Methods: {classes.Sum(c => c.Methods.Count)}");
            sb.AppendLine($"// Total Fields: {classes.Sum(c => c.Fields.Count)}");
            sb.AppendLine($"// Total Properties: {classes.Sum(c => c.Properties.Count)}");
            sb.AppendLine($"// Total Events: {classes.Sum(c => c.Events.Count)}");

            // Image summary
            var imageGroups = classes.Where(c => !string.IsNullOrEmpty(c.ImageName))
                .GroupBy(c => c.ImageName).OrderBy(g => g.Key).ToList();
            if (imageGroups.Count > 0)
            {
                sb.AppendLine($"// Images: {imageGroups.Count}");
                foreach (var ig in imageGroups)
                    sb.AppendLine($"//   {ig.Key}: {ig.Count()} types");
            }
            sb.AppendLine("// ==============================================================");
            sb.AppendLine();

            // Group by image then namespace
            var byImage = classes
                .GroupBy(c => string.IsNullOrEmpty(c.ImageName) ? "" : c.ImageName)
                .OrderBy(g => g.Key);

            foreach (var imgGroup in byImage)
            {
                if (!string.IsNullOrEmpty(imgGroup.Key))
                {
                    sb.AppendLine($"// ============ Assembly: {imgGroup.Key} ({imgGroup.Count()} types) ============");
                    sb.AppendLine();
                }

                var grouped = imgGroup
                    .GroupBy(c => string.IsNullOrEmpty(c.Namespace) ? "<Global>" : c.Namespace)
                    .OrderBy(g => g.Key);

            foreach (var nsGroup in grouped)
            {
                sb.AppendLine($"namespace {nsGroup.Key}");
                sb.AppendLine("{");

                foreach (var cls in nsGroup.OrderBy(c => c.Name))
                {
                    string typeKind = GetTypeKind(cls);
                    string accessMod = GetAccessModifier(cls.Flags);
                    string baseClause = GetBaseClause(cls);

                    // Generic parameters on class
                    string genericParams = "";
                    if (cls.GenericParameterNames.Count > 0)
                        genericParams = "<" + string.Join(", ", cls.GenericParameterNames) + ">";

                    // Interfaces
                    string interfaceClause = "";
                    if (cls.InterfaceNames.Count > 0)
                    {
                        string separator = string.IsNullOrEmpty(baseClause) ? " : " : ", ";
                        interfaceClause = separator + string.Join(", ", cls.InterfaceNames);
                    }

                    sb.AppendLine($"    // Token: 0x{cls.Token:X8}");
                    sb.AppendLine($"    {accessMod} {typeKind} {EscapeName(cls.Name)}{genericParams}{baseClause}{interfaceClause}");
                    sb.AppendLine("    {");

                    // Fields
                    foreach (var field in cls.Fields)
                    {
                        string fieldAccess = GetFieldAccess(field.Token);
                        string fieldStatic = field.IsStatic ? "static " : "";
                        string fieldType = !string.IsNullOrEmpty(field.TypeName) ? field.TypeName : "/* type */";

                        string offsetComment;
                        if (cls.IsEnum && field.Name != "value__")
                            offsetComment = $" // = {field.FieldOffset}";
                        else if (field.FieldOffset >= 0)
                            offsetComment = $" // Offset: 0x{field.FieldOffset:X}";
                        else
                            offsetComment = "";

                        sb.AppendLine($"        // Token: 0x{field.Token:X8}");
                        if (field.IsSerializeField && !field.IsStatic)
                            sb.AppendLine("        [SerializeField]");
                        sb.AppendLine($"        {fieldAccess}{fieldStatic}{fieldType} {EscapeName(field.Name)};{offsetComment}");
                        sb.AppendLine();
                    }

                    // Properties
                    foreach (var prop in cls.Properties)
                    {
                        string propType = !string.IsNullOrEmpty(prop.TypeName) ? prop.TypeName : "/* type */";
                        string accessors = "";
                        if (!string.IsNullOrEmpty(prop.GetterName) && !string.IsNullOrEmpty(prop.SetterName))
                            accessors = "{ get; set; }";
                        else if (!string.IsNullOrEmpty(prop.GetterName))
                            accessors = "{ get; }";
                        else if (!string.IsNullOrEmpty(prop.SetterName))
                            accessors = "{ set; }";
                        else
                            accessors = "{ get; set; }";

                        sb.AppendLine($"        // Token: 0x{prop.Token:X8}");
                        if (!string.IsNullOrEmpty(prop.GetterName))
                            sb.AppendLine($"        // Getter: {prop.GetterName}");
                        if (!string.IsNullOrEmpty(prop.SetterName))
                            sb.AppendLine($"        // Setter: {prop.SetterName}");
                        sb.AppendLine($"        {propType} {EscapeName(prop.Name)} {accessors}");
                        sb.AppendLine();
                    }

                    // Events
                    foreach (var evt in cls.Events)
                    {
                        string evtType = !string.IsNullOrEmpty(evt.TypeName) ? evt.TypeName : "/* type */";
                        sb.AppendLine($"        // Token: 0x{evt.Token:X8}");
                        sb.AppendLine($"        public event {evtType} {EscapeName(evt.Name)};");
                        sb.AppendLine();
                    }

                    // Methods
                    foreach (var method in cls.Methods)
                    {
                        string methodAccess = GetMethodAccess(method.Flags);
                        string isStatic = (method.Flags & 0x0010) != 0 ? "static " : "";
                        string isVirtual = (method.Flags & 0x0040) != 0 ? "virtual " : "";
                        string isAbstract = (method.Flags & 0x0400) != 0 ? "abstract " : "";
                        string returnType = !string.IsNullOrEmpty(method.ReturnTypeName) ? method.ReturnTypeName : "void";

                        // Generic parameters on method
                        string methodGeneric = "";
                        if (method.IsGeneric && method.GenericParameterNames != null && method.GenericParameterNames.Length > 0)
                            methodGeneric = "<" + string.Join(", ", method.GenericParameterNames) + ">";

                        // Build parameter list with resolved types
                        var paramList = new StringBuilder();
                        for (int i = 0; i < method.ParameterCount; i++)
                        {
                            if (i > 0) paramList.Append(", ");
                            string pType = (method.ParameterTypeNames != null && i < method.ParameterTypeNames.Length && !string.IsNullOrEmpty(method.ParameterTypeNames[i]))
                                ? method.ParameterTypeNames[i] : "object";
                            string pName = (method.ParameterNames != null && i < method.ParameterNames.Length && !string.IsNullOrEmpty(method.ParameterNames[i]))
                                ? method.ParameterNames[i] : $"param{i}";
                            paramList.Append($"{pType} {EscapeName(pName)}");
                        }

                        sb.AppendLine($"        // Token: 0x{method.Token:X8}  Slot: {method.Slot}");
                        if (method.Rva > 0)
                            sb.AppendLine($"        // RVA: 0x{method.Rva:X8}");
                        sb.AppendLine($"        {methodAccess}{isStatic}{isVirtual}{isAbstract}{returnType} {EscapeName(method.Name)}{methodGeneric}({paramList}) {{ }}");
                        sb.AppendLine();
                    }

                    sb.AppendLine("    }");
                    sb.AppendLine();
                }

                sb.AppendLine("}");
                sb.AppendLine();
            }
            } // end byImage loop

            return sb.ToString();
        }

        public static void Save(string path, string sdkText, Il2CppMetadataSnapshot snapshot)
        {
            File.WriteAllText(path, sdkText, Encoding.UTF8);
        }

        public static string GenerateStringLiteralDump(List<Il2CppRuntimeResolver.StringLiteral> literals)
        {
            if (literals == null || literals.Count == 0)
                return "// No string literals found in metadata\n";

            var sb = new StringBuilder(literals.Count * 64);
            sb.AppendLine("// ==============================================================");
            sb.AppendLine("// KsDumper - IL2CPP String Literal Dump");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Total Strings: {literals.Count}");
            sb.AppendLine("// ==============================================================");
            sb.AppendLine();

            for (int i = 0; i < literals.Count; i++)
            {
                var lit = literals[i];
                string escaped = lit.Value
                    .Replace("\\", "\\\\")
                    .Replace("\"", "\\\"")
                    .Replace("\n", "\\n")
                    .Replace("\r", "\\r")
                    .Replace("\t", "\\t");

                if (escaped.Length > 200)
                    escaped = escaped.Substring(0, 200) + "...";

                sb.AppendLine($"[{i}] \"{escaped}\"");
            }

            return sb.ToString();
        }

        // ---------- Method attribute decoding ----------

        private static string GetTypeKind(Il2CppClassInfo cls)
        {
            if (cls.IsInterface) return "interface";
            if (cls.IsEnum) return "enum";
            if (cls.IsValueType) return "struct";
            return "class";
        }

        private static string GetAccessModifier(uint flags)
        {
            // TypeAttributes visibility mask: 0x07
            uint vis = flags & 0x07;
            switch (vis)
            {
                case 0x01: return "public";       // tdPublic
                case 0x02: return "internal";      // tdNestedPublic
                case 0x03: return "private";       // tdNestedPrivate
                case 0x04: return "protected";     // tdNestedFamily
                case 0x06: return "protected internal"; // tdNestedFamORAssem
                default: return "public";
            }
        }

        private static string GetBaseClause(Il2CppClassInfo cls)
        {
            if (string.IsNullOrEmpty(cls.BaseTypeName) || cls.IsInterface)
                return "";
            if (cls.BaseTypeName == "System.Object" || cls.BaseTypeName == "System.ValueType" || cls.BaseTypeName == "System.Enum" || cls.BaseTypeName == "System.MulticastDelegate")
                return "";
            return $" : {cls.BaseTypeName}";
        }

        private static string GetFieldAccess(uint token)
        {
            return "public "; // Field access flags not stored separately in IL2CPP metadata
        }

        private static string GetMethodAccess(ushort flags)
        {
            // MethodAttributes.MemberAccessMask = 0x0007
            uint access = (uint)(flags & 0x0007);
            switch (access)
            {
                case 0x01: return "private ";          // Private
                case 0x02: return "private ";          // FamANDAssem
                case 0x03: return "internal ";         // Assembly
                case 0x04: return "protected ";        // Family
                case 0x05: return "protected internal "; // FamORAssem
                case 0x06: return "public ";           // Public
                default: return "public ";
            }
        }

        private static string EscapeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_unnamed";
            // Escape C# keywords and invalid chars
            var keywords = new HashSet<string> { "abstract", "as", "base", "bool", "break", "byte", "case", "catch",
                "char", "checked", "class", "const", "continue", "decimal", "default", "delegate", "do", "double",
                "else", "enum", "event", "explicit", "extern", "false", "finally", "fixed", "float", "for",
                "foreach", "goto", "if", "implicit", "in", "int", "interface", "internal", "is", "lock", "long",
                "namespace", "new", "null", "object", "operator", "out", "override", "params", "private",
                "protected", "public", "readonly", "ref", "return", "sbyte", "sealed", "short", "sizeof",
                "stackalloc", "static", "string", "struct", "switch", "this", "throw", "true", "try", "typeof",
                "uint", "ulong", "unchecked", "unsafe", "ushort", "using", "virtual", "void", "volatile", "while" };

            // Replace invalid identifier characters
            var sb = new StringBuilder(name.Length);
            for (int i = 0; i < name.Length; i++)
            {
                char c = name[i];
                if (char.IsLetterOrDigit(c) || c == '_')
                    sb.Append(c);
                else
                    sb.Append('_');
            }
            string result = sb.ToString();

            if (keywords.Contains(result))
                return "@" + result;
            return result;
        }
    }
}
