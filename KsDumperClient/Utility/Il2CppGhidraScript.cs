using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    /// <summary>
    /// Generates Ghidra and IDA Python scripts from IL2CPP SDK data.
    /// Scripts create structs with field offsets, label functions at their RVA,
    /// and set function signatures.
    /// </summary>
    public static class Il2CppGhidraScript
    {
        /// <summary>
        /// Generate a Ghidra Python script that creates structs and labels functions.
        /// </summary>
        public static string GenerateGhidraScript(
            List<Il2CppSdkGenerator.Il2CppClassInfo> classes,
            Dictionary<int, ulong> methodRvas,
            ulong imageBase)
        {
            var sb = new StringBuilder(256 * 1024);

            sb.AppendLine("# ==============================================================");
            sb.AppendLine("# KsDumper IL2CPP Ghidra Script");
            sb.AppendLine($"# Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"# Classes: {classes.Count}");
            sb.AppendLine($"# Methods with RVA: {methodRvas?.Count ?? 0}");
            sb.AppendLine($"# Image Base: 0x{imageBase:X}");
            sb.AppendLine("# ==============================================================");
            sb.AppendLine();
            sb.AppendLine("from ghidra.program.model.symbol import SourceType");
            sb.AppendLine("from ghidra.program.model.data import *");
            sb.AppendLine("from ghidra.program.model.listing import DataTypeManager");
            sb.AppendLine("from ghidra.program.model.data import DataTypeConflictHandler");
            sb.AppendLine();
            sb.AppendLine("dtm = currentProgram.getDataTypeManager()");
            sb.AppendLine("listing = currentProgram.getListing()");
            sb.AppendLine("addrFactory = currentProgram.getAddressFactory()");
            sb.AppendLine("space = addrFactory.getDefaultAddressSpace()");
            sb.AppendLine();

            // Create structs for each class
            sb.AppendLine("# --- Create Structs ---");
            sb.AppendLine();

            foreach (var cls in classes.OrderBy(c => c.FullName))
            {
                string safeName = GhidraSafeName(cls.FullName);

                if (cls.Fields.Count > 0)
                {
                    sb.AppendLine($"# {cls.FullName} (Token: 0x{cls.Token:X8})");
                    sb.AppendLine($"try:");
                    sb.AppendLine($"    cat = dtm.createCategory(CategoryPath(\"/IL2CPP/{GhidraSafeName(cls.Namespace)}\"))");
                    sb.AppendLine($"    struct = StructureDataType(\"{safeName}\", 0)");

                    foreach (var field in cls.Fields)
                    {
                        if (field.FieldOffset >= 0)
                        {
                            string dataType = MapTypeToGhidra(field.TypeName);
                            int size = GetGhidraTypeSize(field.TypeName);
                            string safeFieldName = GhidraSafeName(field.Name);
                            sb.AppendLine($"    struct.insertAtOffset(0x{field.FieldOffset:X}, dtm.getDataType(\"{dataType}\"), {size}, \"{safeFieldName}\", None)");
                        }
                    }

                    sb.AppendLine($"    dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER)");
                    sb.AppendLine($"except Exception as e:");
                    sb.AppendLine($"    print(\"Error creating struct {safeName}: \" + str(e))");
                    sb.AppendLine();
                }
            }

            // Inheritance chain comments
            sb.AppendLine("# --- Inheritance Chains ---");
            sb.AppendLine();
            foreach (var cls in classes.OrderBy(c => c.FullName))
            {
                if (string.IsNullOrEmpty(cls.BaseTypeName) || cls.IsInterface) continue;
                if (cls.BaseTypeName == "System.Object" || cls.BaseTypeName == "System.ValueType"
                    || cls.BaseTypeName == "System.Enum" || cls.BaseTypeName == "System.MulticastDelegate") continue;

                string childSafe = GhidraSafeName(cls.FullName);
                string parentSafe = GhidraSafeName(cls.BaseTypeName);
                sb.AppendLine($"# INHERITS: {childSafe} : {parentSafe}");
            }
            sb.AppendLine();

            // Interface implementations
            sb.AppendLine("# --- Interface Implementations ---");
            sb.AppendLine();
            foreach (var cls in classes.OrderBy(c => c.FullName))
            {
                if (cls.InterfaceNames.Count == 0) continue;
                string safeName = GhidraSafeName(cls.FullName);
                foreach (string iface in cls.InterfaceNames)
                    sb.AppendLine($"# IMPLEMENTS: {safeName} -> {GhidraSafeName(iface)}");
            }
            sb.AppendLine();

            // VTable reconstruction
            sb.AppendLine("# --- VTable Slots ---");
            sb.AppendLine();
            foreach (var cls in classes.OrderBy(c => c.FullName))
            {
                var virtualMethods = new List<Il2CppSdkGenerator.Il2CppMethodInfo>();
                foreach (var m in cls.Methods)
                {
                    if ((m.Flags & 0x0040) != 0) // MethodAttributes.Virtual
                        virtualMethods.Add(m);
                }

                if (virtualMethods.Count == 0) continue;

                string safeName = GhidraSafeName(cls.FullName);
                sb.AppendLine($"# VTable for {safeName}:");
                foreach (var vm in virtualMethods)
                {
                    if (vm.Rva > 0)
                    {
                        ulong addr = imageBase + vm.Rva;
                        sb.AppendLine($"#   Slot {vm.Slot}: {vm.Name} -> 0x{addr:X}");
                    }
                    else
                    {
                        sb.AppendLine($"#   Slot {vm.Slot}: {vm.Name}");
                    }
                }
                sb.AppendLine();
            }

            // Label functions
            sb.AppendLine("# --- Label Functions ---");
            sb.AppendLine();

            if (methodRvas != null)
            {
                foreach (var cls in classes.OrderBy(c => c.FullName))
                {
                    foreach (var method in cls.Methods)
                    {
                        if (method.Rva > 0)
                        {
                            ulong funcAddr = imageBase + method.Rva;
                            string funcName = GhidraSafeName($"{cls.FullName}_{method.Name}");
                            string signature = BuildMethodSignature(cls, method);

                            sb.AppendLine($"try:");
                            sb.AppendLine($"    addr = space.getAddress(0x{funcAddr:X})");
                            sb.AppendLine($"    func = createFunction(addr, \"{funcName}\")");
                            sb.AppendLine($"    if func:");
                            sb.AppendLine($"        setPlateComment(addr, \"{EscapePythonString(signature)}\")");
                            sb.AppendLine($"except:");
                            sb.AppendLine($"    pass");
                            sb.AppendLine();
                        }
                    }
                }
            }

            sb.AppendLine("print(\"KsDumper IL2CPP script complete!\")");

            return sb.ToString();
        }

        /// <summary>
        /// Generate an IDA Python script equivalent.
        /// </summary>
        public static string GenerateIdaScript(
            List<Il2CppSdkGenerator.Il2CppClassInfo> classes,
            Dictionary<int, ulong> methodRvas,
            ulong imageBase)
        {
            var sb = new StringBuilder(256 * 1024);

            sb.AppendLine("# ==============================================================");
            sb.AppendLine("# KsDumper IL2CPP IDA Script");
            sb.AppendLine($"# Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"# Classes: {classes.Count}");
            sb.AppendLine($"# Methods with RVA: {methodRvas?.Count ?? 0}");
            sb.AppendLine($"# Image Base: 0x{imageBase:X}");
            sb.AppendLine("# ==============================================================");
            sb.AppendLine();
            sb.AppendLine("import idaapi");
            sb.AppendLine("import idc");
            sb.AppendLine("import idautils");
            sb.AppendLine();

            // Create structs
            sb.AppendLine("# --- Create Structs ---");
            sb.AppendLine();

            foreach (var cls in classes.OrderBy(c => c.FullName))
            {
                if (cls.Fields.Count > 0)
                {
                    string safeName = IdaSafeName(cls.FullName);

                    sb.AppendLine($"# {cls.FullName}");
                    sb.AppendLine($"sid = idc.add_struc(-1, \"{safeName}\")");
                    sb.AppendLine("if sid != -1:");

                    foreach (var field in cls.Fields)
                    {
                        if (field.FieldOffset >= 0)
                        {
                            string flag = MapTypeToIdaFlag(field.TypeName);
                            int size = GetGhidraTypeSize(field.TypeName);
                            string safeFieldName = IdaSafeName(field.Name);
                            sb.AppendLine($"    idc.add_struc_member(sid, \"{safeFieldName}\", 0x{field.FieldOffset:X}, {flag}, -1, {size})");
                        }
                    }

                    sb.AppendLine();
                }
            }

            // Inheritance and interface comments for IDA
            sb.AppendLine("# --- Type Hierarchy ---");
            sb.AppendLine();
            foreach (var cls in classes.OrderBy(c => c.FullName))
            {
                if (!string.IsNullOrEmpty(cls.BaseTypeName) && !cls.IsInterface
                    && cls.BaseTypeName != "System.Object" && cls.BaseTypeName != "System.ValueType"
                    && cls.BaseTypeName != "System.Enum" && cls.BaseTypeName != "System.MulticastDelegate")
                {
                    sb.AppendLine($"# INHERITS: {IdaSafeName(cls.FullName)} : {IdaSafeName(cls.BaseTypeName)}");
                }
                foreach (string iface in cls.InterfaceNames)
                    sb.AppendLine($"# IMPLEMENTS: {IdaSafeName(cls.FullName)} -> {IdaSafeName(iface)}");
            }
            sb.AppendLine();

            // VTable slot info
            sb.AppendLine("# --- VTable Slots ---");
            sb.AppendLine();
            foreach (var cls in classes.OrderBy(c => c.FullName))
            {
                bool hasVirtual = false;
                foreach (var m in cls.Methods)
                {
                    if ((m.Flags & 0x0040) != 0)
                    {
                        if (!hasVirtual)
                        {
                            sb.AppendLine($"# VTable for {IdaSafeName(cls.FullName)}:");
                            hasVirtual = true;
                        }
                        if (m.Rva > 0)
                            sb.AppendLine($"#   Slot {m.Slot}: {m.Name} -> 0x{imageBase + m.Rva:X}");
                        else
                            sb.AppendLine($"#   Slot {m.Slot}: {m.Name}");
                    }
                }
                if (hasVirtual) sb.AppendLine();
            }

            // Label functions
            sb.AppendLine("# --- Label Functions ---");
            sb.AppendLine();

            if (methodRvas != null)
            {
                foreach (var cls in classes.OrderBy(c => c.FullName))
                {
                    foreach (var method in cls.Methods)
                    {
                        if (method.Rva > 0)
                        {
                            ulong funcAddr = imageBase + method.Rva;
                            string funcName = IdaSafeName($"{cls.FullName}_{method.Name}");
                            sb.AppendLine($"idc.set_name(0x{funcAddr:X}, \"{funcName}\")");

                            // Add function comment with signature
                            string sig = BuildMethodSignature(cls, method);
                            sb.AppendLine($"idc.set_func_cmt(0x{funcAddr:X}, \"{EscapePythonString(sig)}\", 1)");
                        }
                    }
                }
            }

            sb.AppendLine();
            sb.AppendLine("print(\"KsDumper IL2CPP IDA script complete!\")");

            return sb.ToString();
        }

        public static void Save(string path, string scriptContent)
        {
            File.WriteAllText(path, scriptContent, Encoding.UTF8);
        }

        // ---- Helper methods ----

        private static string BuildMethodSignature(Il2CppSdkGenerator.Il2CppClassInfo cls, Il2CppSdkGenerator.Il2CppMethodInfo method)
        {
            var sb = new StringBuilder();

            string returnTypeName = method.ReturnTypeName ?? "void";
            sb.Append(returnTypeName);
            sb.Append(' ');

            if ((method.Flags & 0x0010) != 0) sb.Append("static ");
            sb.Append(cls.FullName);
            sb.Append("::");
            sb.Append(method.Name);
            sb.Append('(');

            if (method.ParameterNames != null)
            {
                for (int i = 0; i < method.ParameterCount; i++)
                {
                    if (i > 0) sb.Append(", ");
                    string pType = (method.ParameterTypeNames != null && i < method.ParameterTypeNames.Length)
                        ? method.ParameterTypeNames[i] : "object";
                    string pName = (i < method.ParameterNames.Length && !string.IsNullOrEmpty(method.ParameterNames[i]))
                        ? method.ParameterNames[i] : $"param{i}";
                    sb.Append(pType);
                    sb.Append(' ');
                    sb.Append(pName);
                }
            }

            sb.Append(')');
            return sb.ToString();
        }

        private static string MapTypeToGhidra(string typeName)
        {
            if (string.IsNullOrEmpty(typeName)) return "/undefined4";
            switch (typeName)
            {
                case "void": return "/void";
                case "bool": return "/bool";
                case "byte": return "/byte";
                case "sbyte": return "/char";
                case "short": return "/short";
                case "ushort": return "/ushort";
                case "int": return "/int";
                case "uint": return "/uint";
                case "long": return "/long";
                case "ulong": return "/ulong";
                case "float": return "/float";
                case "double": return "/double";
                case "char": return "/ushort"; // .NET char is 2 bytes
                case "string": return "/pointer";
                case "IntPtr":
                case "UIntPtr":
                case "object": return "/pointer";
                default:
                    if (typeName.EndsWith("[]")) return "/pointer";
                    return "/pointer"; // Reference types are pointers in IL2CPP
            }
        }

        private static int GetGhidraTypeSize(string typeName)
        {
            if (string.IsNullOrEmpty(typeName)) return 4;
            switch (typeName)
            {
                case "void": return 0;
                case "bool": return 1;
                case "byte":
                case "sbyte": return 1;
                case "short":
                case "ushort":
                case "char": return 2;
                case "int":
                case "uint":
                case "float": return 4;
                case "long":
                case "ulong":
                case "double": return 8;
                case "string":
                case "IntPtr":
                case "UIntPtr":
                case "object": return 8; // x64 pointer
                default:
                    if (typeName.EndsWith("[]")) return 8; // array is a reference type (pointer)
                    return 8; // reference types are pointers
            }
        }

        private static string MapTypeToIdaFlag(string typeName)
        {
            if (string.IsNullOrEmpty(typeName)) return "0x20000400"; // FF_DWORD
            switch (typeName)
            {
                case "bool":
                case "byte":
                case "sbyte": return "0x00000400"; // FF_BYTE
                case "short":
                case "ushort":
                case "char": return "0x10000400"; // FF_WORD
                case "int":
                case "uint":
                case "float": return "0x20000400"; // FF_DWORD
                case "long":
                case "ulong":
                case "double": return "0x30000400"; // FF_QWORD
                default: return "0x20000400"; // Default to DWORD
            }
        }

        private static string GhidraSafeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_unnamed";
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                if (char.IsLetterOrDigit(c) || c == '_')
                    sb.Append(c);
                else
                    sb.Append('_');
            }
            return sb.ToString();
        }

        private static string IdaSafeName(string name)
        {
            return GhidraSafeName(name);
        }

        private static string EscapePythonString(string s)
        {
            if (s == null) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n");
        }
    }
}
