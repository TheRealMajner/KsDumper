using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppGenericResolver
    {
        public class GenericInstantiation
        {
            public int TypeIndex;
            public string GenericTypeName;
            public string[] TypeArguments;
            public string FullInstantiatedName;
        }

        public class GenericMethodInstantiation
        {
            public int MethodIndex;
            public string MethodName;
            public string DeclaringType;
            public string[] ClassTypeArgs;
            public string[] MethodTypeArgs;
            public string FullSignature;
        }

        public class GenericResolutionResult
        {
            public List<GenericInstantiation> TypeInstantiations = new List<GenericInstantiation>();
            public List<GenericMethodInstantiation> MethodInstantiations = new List<GenericMethodInstantiation>();
            public int TotalGenericTypes;
            public int TotalGenericMethods;
            public int ResolvedTypes;
            public int ResolvedMethods;
        }

        public static GenericResolutionResult ResolveFromMetadata(Il2CppMetadataSnapshot snapshot)
        {
            var result = new GenericResolutionResult();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            // Build type name lookup
            string[] typeNames = new string[snapshot.TypeDefinitions.Length];
            for (int i = 0; i < snapshot.TypeDefinitions.Length; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                string name = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);
                string ns = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);
                typeNames[i] = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
            }

            // Find all types with generic parameters
            for (int ti = 0; ti < snapshot.TypeDefinitions.Length; ti++)
            {
                var td = snapshot.TypeDefinitions[ti];
                if (td.GenericContainerIndex < 0) continue;

                if (td.GenericContainerIndex >= snapshot.GenericContainers.Length) continue;
                var container = snapshot.GenericContainers[td.GenericContainerIndex];
                if (container.TypeArgCount <= 0) continue;

                var paramNames = new List<string>();
                for (int p = 0; p < container.TypeArgCount; p++)
                {
                    int gpIdx = container.GenericParameterStart + p;
                    if (gpIdx >= 0 && gpIdx < snapshot.GenericParameters.Length)
                    {
                        string pName = ReadStringFromTable(metadata, header.StringOffset, header.StringSize,
                            (int)snapshot.GenericParameters[gpIdx].NameIndex);
                        paramNames.Add(pName);
                    }
                    else
                    {
                        paramNames.Add($"T{p}");
                    }
                }

                result.TotalGenericTypes++;
            }

            // Find all methods with generic parameters
            for (int mi = 0; mi < snapshot.Methods.Length; mi++)
            {
                var md = snapshot.Methods[mi];
                if (md.GenericContainerIndex < 0) continue;

                if (md.GenericContainerIndex >= snapshot.GenericContainers.Length) continue;
                var container = snapshot.GenericContainers[md.GenericContainerIndex];
                if (container.IsMethod == 0 || container.TypeArgCount <= 0) continue;

                result.TotalGenericMethods++;
            }

            return result;
        }

        public static GenericResolutionResult ResolveFromRuntime(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot)
        {
            var result = ResolveFromMetadata(snapshot);
            if (result == null) return new GenericResolutionResult();

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            // Build type name lookup
            string[] typeNames = new string[snapshot.TypeDefinitions.Length];
            for (int i = 0; i < snapshot.TypeDefinitions.Length; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                string name = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);
                string ns = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);
                typeNames[i] = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
            }

            // Scan GameAssembly .data section for Il2CppGenericInst structures
            // Il2CppGenericInst: { uint32_t type_argc; Il2CppType** type_argv; }
            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return result;

            var dataSections = ParseDataSections(peHeader, gaBase);
            ulong gaEnd = gaBase + gaSize;

            foreach (var (secStart, secSize) in dataSections)
            {
                int readSize = (int)Math.Min(secSize, 0x2000000);
                byte[] data = ReadMemory(driver, pid, secStart, readSize);
                if (data == null) continue;

                // Scan for Il2CppGenericClass structures
                // Il2CppGenericClass: { int typeDefinitionIndex; Il2CppGenericContext context; Il2CppClass* cached_class; }
                // Il2CppGenericContext: { Il2CppGenericInst* class_inst; Il2CppGenericInst* method_inst; }
                for (int i = 0; i <= data.Length - 32; i += 8)
                {
                    if (result.TypeInstantiations.Count >= 5000) break;

                    int typeDefIdx = BitConverter.ToInt32(data, i);
                    if (typeDefIdx < 0 || typeDefIdx >= snapshot.TypeDefinitions.Length) continue;

                    // Check if this type has generic parameters
                    var td = snapshot.TypeDefinitions[typeDefIdx];
                    if (td.GenericContainerIndex < 0) continue;
                    if (td.GenericContainerIndex >= snapshot.GenericContainers.Length) continue;
                    var container = snapshot.GenericContainers[td.GenericContainerIndex];
                    if (container.TypeArgCount <= 0) continue;

                    // Check padding bytes (should be 0)
                    int pad = BitConverter.ToInt32(data, i + 4);
                    if (pad != 0) continue;

                    // Read class_inst pointer
                    ulong classInstPtr = BitConverter.ToUInt64(data, i + 8);
                    if (classInstPtr < gaBase || classInstPtr >= gaEnd) continue;

                    // Read Il2CppGenericInst: type_argc, type_argv
                    byte[] instData = ReadMemory(driver, pid, classInstPtr, 16);
                    if (instData == null) continue;

                    int typeArgc = BitConverter.ToInt32(instData, 0);
                    if (typeArgc != container.TypeArgCount) continue;

                    ulong typeArgvPtr = BitConverter.ToUInt64(instData, 8);
                    if (typeArgvPtr < gaBase || typeArgvPtr >= gaEnd) continue;

                    // Read type argument pointers
                    byte[] argPtrs = ReadMemory(driver, pid, typeArgvPtr, 8 * typeArgc);
                    if (argPtrs == null) continue;

                    var typeArgs = new string[typeArgc];
                    bool allValid = true;

                    for (int a = 0; a < typeArgc; a++)
                    {
                        ulong typePtr = BitConverter.ToUInt64(argPtrs, a * 8);
                        if (typePtr == 0) { allValid = false; break; }

                        // Il2CppType: { void* data; uint attrs; Il2CppTypeEnum type; ... }
                        // For CLASS/VALUETYPE: data is typeDefinitionIndex
                        byte[] typeData = ReadMemory(driver, pid, typePtr, 16);
                        if (typeData == null) { allValid = false; break; }

                        int dataVal = BitConverter.ToInt32(typeData, 0);
                        byte typeEnum = typeData[8];

                        if (typeEnum == 0x12 || typeEnum == 0x11) // CLASS or VALUETYPE
                        {
                            if (dataVal >= 0 && dataVal < typeNames.Length)
                                typeArgs[a] = typeNames[dataVal];
                            else
                                typeArgs[a] = $"type_{dataVal}";
                        }
                        else
                        {
                            typeArgs[a] = GetPrimitiveTypeName(typeEnum);
                        }
                    }

                    if (!allValid) continue;

                    string baseName = typeNames[typeDefIdx];
                    int btick = baseName.IndexOf('`');
                    if (btick > 0) baseName = baseName.Substring(0, btick);

                    var inst = new GenericInstantiation
                    {
                        TypeIndex = typeDefIdx,
                        GenericTypeName = typeNames[typeDefIdx],
                        TypeArguments = typeArgs,
                        FullInstantiatedName = $"{baseName}<{string.Join(", ", typeArgs)}>"
                    };

                    // Dedup
                    if (!result.TypeInstantiations.Any(x => x.FullInstantiatedName == inst.FullInstantiatedName))
                    {
                        result.TypeInstantiations.Add(inst);
                        result.ResolvedTypes++;
                    }
                }
            }

            return result;
        }

        public static string GenerateReport(GenericResolutionResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Generic Instantiation Report");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Generic type definitions: {result.TotalGenericTypes}");
            sb.AppendLine($"// Generic method definitions: {result.TotalGenericMethods}");
            sb.AppendLine($"// Resolved type instantiations: {result.ResolvedTypes}");
            sb.AppendLine($"// Resolved method instantiations: {result.ResolvedMethods}");
            sb.AppendLine();

            if (result.TypeInstantiations.Count > 0)
            {
                sb.AppendLine("// ===== Concrete Generic Type Instantiations =====");
                var grouped = result.TypeInstantiations
                    .GroupBy(i => i.GenericTypeName)
                    .OrderBy(g => g.Key);

                foreach (var group in grouped)
                {
                    sb.AppendLine($"// {group.Key}:");
                    foreach (var inst in group)
                    {
                        sb.AppendLine($"//   -> {inst.FullInstantiatedName}");
                    }
                    sb.AppendLine();
                }
            }

            if (result.MethodInstantiations.Count > 0)
            {
                sb.AppendLine("// ===== Concrete Generic Method Instantiations =====");
                foreach (var mi in result.MethodInstantiations.Take(500))
                {
                    sb.AppendLine($"//   {mi.FullSignature}");
                }
            }

            return sb.ToString();
        }

        private static string GetPrimitiveTypeName(byte typeEnum)
        {
            switch (typeEnum)
            {
                case 0x01: return "void";
                case 0x02: return "bool";
                case 0x03: return "char";
                case 0x04: return "sbyte";
                case 0x05: return "byte";
                case 0x06: return "short";
                case 0x07: return "ushort";
                case 0x08: return "int";
                case 0x09: return "uint";
                case 0x0A: return "long";
                case 0x0B: return "ulong";
                case 0x0C: return "float";
                case 0x0D: return "double";
                case 0x0E: return "string";
                case 0x16: return "TypedReference";
                case 0x18: return "IntPtr";
                case 0x19: return "UIntPtr";
                case 0x1C: return "object";
                default: return $"prim_0x{typeEnum:X2}";
            }
        }

        private static List<(ulong start, ulong size)> ParseDataSections(byte[] peHeader, ulong baseAddr)
        {
            var sections = new List<(ulong, ulong)>();
            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            if (peOff < 0 || peOff + 24 > peHeader.Length) return sections;

            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                if (sName == ".data" || sName == ".rdata" || sName == ".bss")
                    sections.Add((baseAddr + vAddr, vSize));
            }
            return sections;
        }

        private static byte[] ReadMemory(IMemoryReader driver, int pid, ulong address, int size)
        {
            byte[] buf = new byte[size];
            GCHandle handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                if (!driver.CopyVirtualMemory(pid, (IntPtr)(long)address, handle.AddrOfPinnedObject(), size))
                    return null;
                return buf;
            }
            finally { handle.Free(); }
        }
    }
}
