using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using KsDumperClient.PE;
using static KsDumperClient.PE.NativePEStructs;
using static KsDumperClient.Utility.Il2CppSdkGenerator;

namespace KsDumperClient.Utility
{
    public static class StructureHeaderGenerator
    {
        public static string Generate(PEFile pe, ModuleSummary mod, ulong imageBase)
        {
            var sb = new StringBuilder();
            string guardName = SanitizeIdentifier(Path.GetFileNameWithoutExtension(mod.ModuleName)).ToUpperInvariant();

            sb.AppendLine($"// KsDumper - Structure Header for {mod.ModuleName}");
            sb.AppendLine($"// Base Address: 0x{imageBase:X}");
            sb.AppendLine($"// Image Size: 0x{mod.ImageSize:X}");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine($"#ifndef _{guardName}_STRUCTURES_H_");
            sb.AppendLine($"#define _{guardName}_STRUCTURES_H_");
            sb.AppendLine();
            sb.AppendLine("#include <stdint.h>");
            sb.AppendLine();

            // Module defines
            sb.AppendLine("// ---- Module Info ----");
            sb.AppendLine($"#define MODULE_BASE_ADDRESS  0x{imageBase:X}ULL");
            sb.AppendLine($"#define MODULE_IMAGE_SIZE    0x{mod.ImageSize:X}");
            sb.AppendLine($"#define MODULE_NAME          \"{EscapeString(mod.ModuleName)}\"");
            sb.AppendLine();

            // Section defines
            sb.AppendLine("// ---- Sections ----");
            foreach (var section in pe.Sections)
            {
                string name = SanitizeIdentifier(section.Header.Name?.TrimEnd('\0') ?? "unknown").ToUpperInvariant();
                sb.AppendLine($"#define SEC_{name}_RVA   0x{section.Header.VirtualAddress:X}");
                sb.AppendLine($"#define SEC_{name}_SIZE  0x{section.Header.VirtualSize:X}");
            }
            sb.AppendLine();

            // RTTI forward declarations
            var rttiClasses = PEAnalyzer.ScanRTTI(pe);
            if (rttiClasses.Count > 0)
            {
                sb.AppendLine($"// ---- RTTI Classes ({rttiClasses.Count}) ----");
                foreach (var cls in rttiClasses)
                {
                    string safeName = SanitizeClassName(cls);
                    if (!string.IsNullOrEmpty(safeName))
                        sb.AppendLine($"struct {safeName};");
                }
                sb.AppendLine();
            }

            // VTable structs
            var vtables = PEAnalyzer.FindVTables(pe, imageBase);
            if (vtables.Count > 0)
            {
                sb.AppendLine($"// ---- Virtual Method Tables ({vtables.Count}) ----");
                for (int i = 0; i < vtables.Count; i++)
                {
                    var vt = vtables[i];
                    sb.AppendLine($"// VTable at RVA 0x{vt.rva:X8} ({vt.methodCount} methods)");
                    sb.AppendLine($"struct VTable_{i} {{");
                    for (int m = 0; m < vt.methodCount; m++)
                        sb.AppendLine($"    void* method_{m};");
                    sb.AppendLine("};");
                    sb.AppendLine();
                }
            }

            // Export function typedefs
            var exports = ParseExports(pe);
            if (exports.Count > 0)
            {
                sb.AppendLine($"// ---- Exports ({exports.Count}) ----");
                foreach (var (name, rva) in exports)
                {
                    string safeName = SanitizeIdentifier(name);
                    sb.AppendLine($"typedef void (*fn_{safeName})();  // RVA: 0x{rva:X8}");
                }
                sb.AppendLine();
            }

            sb.AppendLine($"#endif // _{guardName}_STRUCTURES_H_");
            return sb.ToString();
        }

        public static string GenerateIl2CppHeader(List<Il2CppClassInfo> classes, ulong gameAssemblyBase)
        {
            var sb = new StringBuilder();

            sb.AppendLine("// KsDumper - IL2CPP Structure Header (il2cpp.h)");
            sb.AppendLine("// For use with ReClass.NET, IDA structs, or custom tooling");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// GameAssembly Base: 0x{gameAssemblyBase:X}");
            sb.AppendLine($"// Classes: {classes.Count}");
            sb.AppendLine();
            sb.AppendLine("#pragma once");
            sb.AppendLine("#include <stdint.h>");
            sb.AppendLine();

            // IL2CPP runtime structures
            sb.AppendLine("// ---- IL2CPP Runtime Structures ----");
            sb.AppendLine();
            sb.AppendLine("typedef struct Il2CppObject {");
            sb.AppendLine("    void* klass;        // +0x00 Il2CppClass*");
            sb.AppendLine("    void* monitor;      // +0x08 MonitorData*");
            sb.AppendLine("} Il2CppObject;");
            sb.AppendLine();
            sb.AppendLine("typedef struct Il2CppString {");
            sb.AppendLine("    Il2CppObject object; // +0x00");
            sb.AppendLine("    int32_t length;       // +0x10");
            sb.AppendLine("    uint16_t chars[1];    // +0x14 (variable length)");
            sb.AppendLine("} Il2CppString;");
            sb.AppendLine();
            sb.AppendLine("typedef struct Il2CppArray {");
            sb.AppendLine("    Il2CppObject object;  // +0x00");
            sb.AppendLine("    void* bounds;          // +0x10 Il2CppArrayBounds*");
            sb.AppendLine("    uint64_t max_length;   // +0x18");
            sb.AppendLine("    // items follow at +0x20");
            sb.AppendLine("} Il2CppArray;");
            sb.AppendLine();
            sb.AppendLine("typedef struct Il2CppClass {");
            sb.AppendLine("    void* image;              // +0x00 Il2CppImage*");
            sb.AppendLine("    void* gc_desc;            // +0x08");
            sb.AppendLine("    char* name;               // +0x10");
            sb.AppendLine("    char* namespaze;          // +0x18");
            sb.AppendLine("    void* byval_arg;          // +0x20 Il2CppType");
            sb.AppendLine("    void* this_arg;           // +0x28 Il2CppType");
            sb.AppendLine("    void* element_class;      // +0x30 Il2CppClass*");
            sb.AppendLine("    void* castClass;          // +0x38 Il2CppClass*");
            sb.AppendLine("    void* declaringType;      // +0x40 Il2CppClass*");
            sb.AppendLine("    void* parent;             // +0x48 Il2CppClass*");
            sb.AppendLine("    void* generic_class;      // +0x50");
            sb.AppendLine("    void* typeDefinition;     // +0x58");
            sb.AppendLine("    void* interopData;        // +0x60");
            sb.AppendLine("    void* klass;              // +0x68 Il2CppClass*");
            sb.AppendLine("    void* static_fields;      // +0x70");
            sb.AppendLine("    void* rgctx_data;         // +0x78");
            sb.AppendLine("    void* fields;             // +0x80 FieldInfo*");
            sb.AppendLine("    void* events;             // +0x88 EventInfo*");
            sb.AppendLine("    void* properties;         // +0x90 PropertyInfo*");
            sb.AppendLine("    void* methods;            // +0x98 MethodInfo**");
            sb.AppendLine("    void* nestedTypes;        // +0xA0");
            sb.AppendLine("    void* implementedInterfaces; // +0xA8");
            sb.AppendLine("    void* interfaceOffsets;   // +0xB0");
            sb.AppendLine("    void* vtable;             // +0xB8");
            sb.AppendLine("    uint32_t instance_size;   // +0xC0");
            sb.AppendLine("    uint32_t actualSize;      // +0xC4");
            sb.AppendLine("    uint16_t method_count;    // +0xC8");
            sb.AppendLine("    uint16_t field_count;     // +0xCA");
            sb.AppendLine("} Il2CppClass;");
            sb.AppendLine();
            sb.AppendLine("typedef struct FieldInfo {");
            sb.AppendLine("    char* name;               // +0x00");
            sb.AppendLine("    void* type;               // +0x08 Il2CppType*");
            sb.AppendLine("    void* parent;             // +0x10 Il2CppClass*");
            sb.AppendLine("    int32_t offset;           // +0x18");
            sb.AppendLine("    uint32_t token;           // +0x1C");
            sb.AppendLine("} FieldInfo;");
            sb.AppendLine();
            sb.AppendLine("typedef struct MethodInfo {");
            sb.AppendLine("    void* methodPointer;      // +0x00");
            sb.AppendLine("    void* invoker_method;     // +0x08");
            sb.AppendLine("    char* name;               // +0x10");
            sb.AppendLine("    void* klass;              // +0x18 Il2CppClass*");
            sb.AppendLine("    void* return_type;        // +0x20 Il2CppType*");
            sb.AppendLine("    void** parameters;        // +0x28 ParameterInfo*");
            sb.AppendLine("    uint32_t token;           // +0x30");
            sb.AppendLine("    uint16_t flags;           // +0x34");
            sb.AppendLine("    uint16_t slot;            // +0x36");
            sb.AppendLine("    uint8_t parameters_count; // +0x38");
            sb.AppendLine("} MethodInfo;");
            sb.AppendLine();

            // Generate game-specific structs from class info
            sb.AppendLine("// ---- Game-Specific Structures ----");
            sb.AppendLine();

            foreach (var cls in classes)
            {
                if (cls.Fields.Count == 0) continue;
                bool hasOffsets = cls.Fields.Any(f => f.FieldOffset > 0 && !f.IsStatic);
                if (!hasOffsets) continue;

                string structName = SanitizeIdentifier(
                    (string.IsNullOrEmpty(cls.Namespace) ? "" : cls.Namespace.Replace(".", "_") + "_") + cls.Name);

                sb.AppendLine($"// {cls.FullName}");
                if (!string.IsNullOrEmpty(cls.BaseTypeName) && cls.BaseTypeName != "Object" && cls.BaseTypeName != "ValueType")
                    sb.AppendLine($"// Base: {cls.BaseTypeName}");

                sb.AppendLine($"typedef struct {structName} {{");
                sb.AppendLine("    Il2CppObject _base;   // +0x00 Object header");

                var sortedFields = cls.Fields
                    .Where(f => f.FieldOffset > 0 && !f.IsStatic)
                    .OrderBy(f => f.FieldOffset)
                    .ToList();

                int lastEnd = 0x10; // after Il2CppObject header
                foreach (var field in sortedFields)
                {
                    if (field.FieldOffset > lastEnd)
                    {
                        int pad = field.FieldOffset - lastEnd;
                        sb.AppendLine($"    uint8_t _pad_0x{lastEnd:X}[0x{pad:X}];");
                    }

                    string cType = CSharpToCType(field.TypeName);
                    int fieldSize = CTypeSize(cType);
                    sb.AppendLine($"    {cType} {SanitizeIdentifier(field.Name)}; // +0x{field.FieldOffset:X}");
                    lastEnd = field.FieldOffset + fieldSize;
                }

                sb.AppendLine($"}} {structName};");
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private static string CSharpToCType(string typeName)
        {
            if (string.IsNullOrEmpty(typeName)) return "void*";
            switch (typeName)
            {
                case "bool": return "uint8_t";
                case "byte": return "uint8_t";
                case "sbyte": return "int8_t";
                case "short": return "int16_t";
                case "ushort": return "uint16_t";
                case "int": return "int32_t";
                case "uint": return "uint32_t";
                case "long": return "int64_t";
                case "ulong": return "uint64_t";
                case "float": return "float";
                case "double": return "double";
                case "char": return "uint16_t";
                case "string": return "Il2CppString*";
                case "IntPtr": case "UIntPtr": return "void*";
                default: return "void*"; // reference types and unknown types
            }
        }

        private static int CTypeSize(string cType)
        {
            if (cType.EndsWith("*")) return 8;
            switch (cType)
            {
                case "uint8_t": case "int8_t": return 1;
                case "uint16_t": case "int16_t": return 2;
                case "int32_t": case "uint32_t": case "float": return 4;
                case "int64_t": case "uint64_t": case "double": return 8;
                default: return 8;
            }
        }

        public static void Save(string outputPath, string content)
        {
            File.WriteAllText(outputPath, content, Encoding.UTF8);
        }

        private static System.Collections.Generic.List<(string name, uint rva)> ParseExports(PEFile pe)
        {
            var result = new System.Collections.Generic.List<(string, uint)>();
            bool is64 = pe.Type == PEFile.PEType.PE64;

            uint exportDirRVA = 0, exportDirSize = 0;
            if (pe is PE64File pe64)
            {
                exportDirRVA = pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                exportDirSize = pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
            else if (pe is PE32File pe32)
            {
                exportDirRVA = pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                exportDirSize = pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }

            if (exportDirRVA == 0 || exportDirSize == 0) return result;

            PESection section = FindSectionByRVA(pe, exportDirRVA);
            if (section?.Content == null) return result;

            uint offset = exportDirRVA - section.Header.VirtualAddress;
            byte[] data = section.Content;
            if (offset + 40 > data.Length) return result;

            uint numNames = BitConverter.ToUInt32(data, (int)offset + 24);
            uint funcAddrRVA = BitConverter.ToUInt32(data, (int)offset + 28);
            uint namePtrRVA = BitConverter.ToUInt32(data, (int)offset + 32);
            uint ordinalRVA = BitConverter.ToUInt32(data, (int)offset + 36);

            if (numNames == 0 || numNames > 100000) return result;

            PESection funcSection = FindSectionByRVA(pe, funcAddrRVA);
            PESection nameSection = FindSectionByRVA(pe, namePtrRVA);
            PESection ordSection = FindSectionByRVA(pe, ordinalRVA);

            if (funcSection?.Content == null || nameSection?.Content == null || ordSection?.Content == null)
                return result;

            uint funcOffset = funcAddrRVA - funcSection.Header.VirtualAddress;
            uint nameOffset = namePtrRVA - nameSection.Header.VirtualAddress;
            uint ordOffset = ordinalRVA - ordSection.Header.VirtualAddress;

            for (uint i = 0; i < numNames; i++)
            {
                int nameRvaPos = (int)(nameOffset + i * 4);
                if (nameRvaPos + 4 > nameSection.Content.Length) break;
                uint nameRVA = BitConverter.ToUInt32(nameSection.Content, nameRvaPos);

                PESection ns = FindSectionByRVA(pe, nameRVA);
                if (ns?.Content == null) continue;
                int nameFileOff = (int)(nameRVA - ns.Header.VirtualAddress);
                if (nameFileOff >= ns.Content.Length) continue;

                int nameEnd = nameFileOff;
                while (nameEnd < ns.Content.Length && ns.Content[nameEnd] != 0) nameEnd++;
                string name = Encoding.ASCII.GetString(ns.Content, nameFileOff, nameEnd - nameFileOff);

                int ordPos = (int)(ordOffset + i * 2);
                if (ordPos + 2 > ordSection.Content.Length) break;
                ushort ordinal = BitConverter.ToUInt16(ordSection.Content, ordPos);

                int funcPos = (int)(funcOffset + ordinal * 4);
                if (funcPos + 4 > funcSection.Content.Length) break;
                uint funcRVA = BitConverter.ToUInt32(funcSection.Content, funcPos);

                result.Add((name, funcRVA));
            }

            return result;
        }

        private static PESection FindSectionByRVA(PEFile pe, uint rva)
        {
            foreach (var s in pe.Sections)
            {
                if (rva >= s.Header.VirtualAddress &&
                    rva < s.Header.VirtualAddress + Math.Max(s.Header.VirtualSize, s.Header.SizeOfRawData))
                    return s;
            }
            return null;
        }

        private static string SanitizeIdentifier(string name)
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
            string result = sb.ToString();
            if (result.Length > 0 && char.IsDigit(result[0]))
                result = "_" + result;
            return result;
        }

        private static string SanitizeClassName(string name)
        {
            if (string.IsNullOrEmpty(name)) return null;
            // Strip template parameters
            int depth = 0;
            var sb = new StringBuilder();
            foreach (char c in name)
            {
                if (c == '<') depth++;
                else if (c == '>') depth--;
                else if (depth == 0)
                {
                    if (char.IsLetterOrDigit(c) || c == '_')
                        sb.Append(c);
                    else if (c == ':' && sb.Length > 0 && sb[sb.Length - 1] != '_')
                        sb.Append('_');
                }
            }
            string result = sb.ToString();
            if (result.Length > 0 && char.IsDigit(result[0]))
                result = "_" + result;
            return result.Length > 0 ? result : null;
        }

        private static string EscapeString(string s)
        {
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        }
    }
}
