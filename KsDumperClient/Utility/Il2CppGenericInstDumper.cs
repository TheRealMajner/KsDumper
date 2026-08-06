using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppGenericInstDumper
    {
        public class GenericTypeArg
        {
            public ulong TypePointer;
            public string TypeName;
            public byte TypeKind;
        }

        public class GenericInstInfo
        {
            public ulong Address;
            public int ArgCount;
            public List<GenericTypeArg> TypeArgs = new List<GenericTypeArg>();
            public string FormattedArgs;
        }

        public class GenericClassInfo
        {
            public string BaseTypeName;
            public ulong KlassPointer;
            public List<GenericInstInfo> Instantiations = new List<GenericInstInfo>();
        }

        public class GenericDumpResult
        {
            public List<GenericClassInfo> GenericClasses = new List<GenericClassInfo>();
            public int TotalInstantiations;
            public int TotalUniqueBaseTypes;
            public Dictionary<string, int> TypeArgFrequency = new Dictionary<string, int>();
        }

        // Il2CppGenericInst layout:
        // +0x00: uint32 type_argc
        // +0x08: Il2CppType** type_argv (pointer to array of Il2CppType*)

        // Il2CppGenericClass layout:
        // +0x00: Il2CppClass* containerClass (the open generic)
        // +0x08: Il2CppGenericContext context
        //   +0x08: Il2CppGenericInst* class_inst
        //   +0x10: Il2CppGenericInst* method_inst

        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;
        private const int kClass_GenericClass = 0xC8;

        public static GenericDumpResult DumpGenericInstantiations(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            string filter = null,
            int maxClasses = 5000)
        {
            var result = new GenericDumpResult();

            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return result;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            var seenKlass = new HashSet<ulong>();
            var genericMap = new Dictionary<string, GenericClassInfo>();

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                if (sName != ".data" && sName != ".rdata") continue;

                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                ulong secStart = gaBase + vAddr;
                int readSize = (int)Math.Min(vSize, 0x4000000);

                byte[] data = ReadMemory(driver, pid, secStart, readSize);
                if (data == null) continue;

                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    if (result.TotalInstantiations >= maxClasses) break;

                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;
                    if (seenKlass.Contains(candidate)) continue;
                    seenKlass.Add(candidate);

                    TryExtractGeneric(driver, pid, candidate, filter, genericMap, result);
                }
            }

            result.GenericClasses = genericMap.Values.ToList();
            result.TotalUniqueBaseTypes = genericMap.Count;

            return result;
        }

        private static void TryExtractGeneric(
            IMemoryReader driver, int pid, ulong klassAddr,
            string filter,
            Dictionary<string, GenericClassInfo> genericMap,
            GenericDumpResult result)
        {
            byte[] klassData = ReadMemory(driver, pid, klassAddr, 0xD0);
            if (klassData == null) return;

            ulong namePtr = BitConverter.ToUInt64(klassData, kClass_Name);
            if (namePtr < 0x10000 || namePtr > 0x7FFFFFFFFFFF) return;

            string name = ReadCString(driver, pid, namePtr, 128);
            if (string.IsNullOrEmpty(name)) return;

            // Check for generic marker
            if (!name.Contains("`")) return;

            foreach (char c in name)
                if (c < 0x20 || c > 0x7E)
                    if (c != '<' && c != '>' && c != '`')
                        return;

            ulong nsPtr = BitConverter.ToUInt64(klassData, kClass_Namespace);
            string ns = nsPtr != 0 ? ReadCString(driver, pid, nsPtr, 128) : "";
            string fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";

            if (!string.IsNullOrEmpty(filter) &&
                fullName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                return;

            // Read genericClass pointer
            ulong genericClassPtr = BitConverter.ToUInt64(klassData, kClass_GenericClass);
            if (genericClassPtr == 0 || genericClassPtr < 0x10000) return;

            byte[] gcData = ReadMemory(driver, pid, genericClassPtr, 0x20);
            if (gcData == null) return;

            // Read class_inst (at offset 0x08 within GenericClass)
            ulong classInstPtr = BitConverter.ToUInt64(gcData, 0x08);

            GenericInstInfo instInfo = null;
            if (classInstPtr != 0 && classInstPtr >= 0x10000)
            {
                instInfo = ReadGenericInst(driver, pid, classInstPtr);
            }

            if (instInfo == null) return;

            result.TotalInstantiations++;

            foreach (var arg in instInfo.TypeArgs)
            {
                if (!result.TypeArgFrequency.ContainsKey(arg.TypeName))
                    result.TypeArgFrequency[arg.TypeName] = 0;
                result.TypeArgFrequency[arg.TypeName]++;
            }

            // Strip the `N suffix for grouping
            string baseName = fullName;
            int tickIdx = baseName.IndexOf('`');
            if (tickIdx > 0)
                baseName = baseName.Substring(0, tickIdx);

            if (!genericMap.ContainsKey(baseName))
            {
                genericMap[baseName] = new GenericClassInfo
                {
                    BaseTypeName = baseName,
                    KlassPointer = klassAddr
                };
            }

            genericMap[baseName].Instantiations.Add(instInfo);
        }

        private static GenericInstInfo ReadGenericInst(IMemoryReader driver, int pid, ulong instAddr)
        {
            byte[] instData = ReadMemory(driver, pid, instAddr, 0x10);
            if (instData == null) return null;

            int argc = BitConverter.ToInt32(instData, 0);
            if (argc <= 0 || argc > 20) return null;

            ulong argvPtr = BitConverter.ToUInt64(instData, 0x08);
            if (argvPtr == 0 || argvPtr < 0x10000) return null;

            byte[] argPtrs = ReadMemory(driver, pid, argvPtr, argc * 8);
            if (argPtrs == null) return null;

            var info = new GenericInstInfo
            {
                Address = instAddr,
                ArgCount = argc
            };

            var argNames = new List<string>();

            for (int a = 0; a < argc; a++)
            {
                ulong typePtr = BitConverter.ToUInt64(argPtrs, a * 8);
                if (typePtr == 0) continue;

                byte[] typeData = ReadMemory(driver, pid, typePtr, 16);
                if (typeData == null) continue;

                byte typeKind = typeData[0];
                string typeName = GetIl2CppTypeName(driver, pid, typePtr, typeKind, typeData);

                var arg = new GenericTypeArg
                {
                    TypePointer = typePtr,
                    TypeName = typeName,
                    TypeKind = typeKind
                };
                info.TypeArgs.Add(arg);
                argNames.Add(typeName);
            }

            info.FormattedArgs = string.Join(", ", argNames);
            return info;
        }

        private static string GetIl2CppTypeName(IMemoryReader driver, int pid, ulong typePtr, byte typeKind, byte[] typeData)
        {
            switch (typeKind)
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
                case 0x1C: return "object";
                case 0x12: // VALUETYPE
                case 0x11: // CLASS
                {
                    // data field at offset +8 is Il2CppTypeDefinitionIndex (or klass ptr)
                    ulong dataVal = BitConverter.ToUInt64(typeData, 8);
                    if (dataVal >= 0x10000 && dataVal < 0x7FFFFFFFFFFF)
                    {
                        ulong classNamePtr = ReadPtr(driver, pid, dataVal + kClass_Name);
                        if (classNamePtr != 0)
                        {
                            string className = ReadCString(driver, pid, classNamePtr, 128);
                            if (!string.IsNullOrEmpty(className)) return className;
                        }
                    }
                    return typeKind == 0x12 ? "struct?" : "class?";
                }
                case 0x0F: // PTR
                    return "ptr";
                case 0x14: // ARRAY
                    return "array";
                case 0x1D: // SZARRAY
                    return "[]";
                default:
                    return $"type_0x{typeKind:X2}";
            }
        }

        public static string GenerateReport(GenericDumpResult result, string search = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Generic Instantiation Dumper");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Unique base types: {result.TotalUniqueBaseTypes}");
            sb.AppendLine($"// Total instantiations: {result.TotalInstantiations}");
            sb.AppendLine();

            if (result.TypeArgFrequency.Count > 0)
            {
                sb.AppendLine("// Most common type arguments:");
                foreach (var kv in result.TypeArgFrequency.OrderByDescending(x => x.Value).Take(20))
                    sb.AppendLine($"//   {kv.Key}: {kv.Value} uses");
                sb.AppendLine();
            }

            var classes = result.GenericClasses.AsEnumerable();
            if (!string.IsNullOrEmpty(search))
                classes = classes.Where(c => c.BaseTypeName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    c.Instantiations.Any(inst => inst.FormattedArgs.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0));

            foreach (var cls in classes.OrderBy(c => c.BaseTypeName))
            {
                sb.AppendLine($"{cls.BaseTypeName} ({cls.Instantiations.Count} instantiations)");
                foreach (var inst in cls.Instantiations.OrderBy(i => i.FormattedArgs))
                {
                    sb.AppendLine($"  {cls.BaseTypeName}<{inst.FormattedArgs}>");
                }
                sb.AppendLine();
            }

            return sb.ToString();
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

        private static ulong ReadPtr(IMemoryReader driver, int pid, ulong address)
        {
            byte[] buf = ReadMemory(driver, pid, address, 8);
            if (buf == null) return 0;
            return BitConverter.ToUInt64(buf, 0);
        }

        private static string ReadCString(IMemoryReader driver, int pid, ulong address, int maxLen)
        {
            byte[] buf = ReadMemory(driver, pid, address, maxLen);
            if (buf == null) return null;
            int len = Array.IndexOf(buf, (byte)0);
            if (len < 0) len = maxLen;
            if (len == 0) return "";
            try { return Encoding.UTF8.GetString(buf, 0, len); }
            catch { return null; }
        }
    }
}
