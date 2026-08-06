using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class MonoRuntimeResolver
    {
        public class MonoClassInfo
        {
            public ulong Address;
            public string Namespace;
            public string Name;
            public string FullName;
            public int FieldCount;
            public int MethodCount;
            public ulong VTableAddress;
            public int VTableSize;
            public uint Token;
            public List<MonoFieldInfo> Fields = new List<MonoFieldInfo>();
            public List<MonoMethodInfo> Methods = new List<MonoMethodInfo>();
        }

        public class MonoFieldInfo
        {
            public ulong Address;
            public string Name;
            public int Offset;
            public ulong TypeAddress;
            public string TypeName;
        }

        public class MonoMethodInfo
        {
            public ulong Address;
            public string Name;
            public ulong NativeCode;
            public uint Token;
            public ushort Flags;
            public bool IsStatic;
            public bool IsVirtual;
        }

        public class MonoImageInfo
        {
            public ulong Address;
            public string Name;
            public string FileName;
            public int ClassCount;
            public List<MonoClassInfo> Classes = new List<MonoClassInfo>();
        }

        public class MonoAssemblyInfo
        {
            public ulong Address;
            public string Name;
            public MonoImageInfo Image;
        }

        public class MonoDomainInfo
        {
            public ulong Address;
            public string FriendlyName;
            public List<MonoAssemblyInfo> Assemblies = new List<MonoAssemblyInfo>();
        }

        public class RuntimeResolution
        {
            public MonoDomainInfo Domain;
            public int TotalAssemblies;
            public int TotalClasses;
            public int TotalMethods;
            public int ResolvedNativeAddresses;
        }

        // Mono internal struct offsets (x64, Mono 6.x / Unity 2019+)
        private const int kDomain_FriendlyName = 0xC8;     // MonoDomain -> friendly_name (char*)
        private const int kDomain_Assemblies = 0xC0;        // MonoDomain -> domain_assemblies (GSList*)

        private const int kAssembly_AName = 0x10;           // MonoAssembly -> aname (MonoAssemblyName, name at +0x00)
        private const int kAssembly_Image = 0x60;           // MonoAssembly -> image (MonoImage*)

        private const int kImage_Name = 0x18;               // MonoImage -> name (const char*)
        private const int kImage_FileName = 0x10;           // MonoImage -> assembly_name
        private const int kImage_ClassCache = 0x3D0;        // MonoImage -> class_cache (MonoInternalHashTable)
        private const int kImage_TypeDef = 0x4A0;           // MonoImage -> class_def (MonoClass** table)
        private const int kImage_TypeDefCount = 0x18;       // TypeDef table row count from metadata tables

        private const int kClass_Name = 0x48;               // MonoClass -> name (const char*)
        private const int kClass_Namespace = 0x50;          // MonoClass -> name_space (const char*)
        private const int kClass_Fields = 0xA0;             // MonoClass -> fields (MonoClassField*)
        private const int kClass_Methods = 0xA8;            // MonoClass -> methods (MonoMethod**)
        private const int kClass_FieldCount = 0xF0;         // MonoClass -> field.count (uint16)
        private const int kClass_MethodCount = 0xF2;        // MonoClass -> method.count (uint16)
        private const int kClass_VTable = 0x40;             // MonoClass -> vtable
        private const int kClass_VTableSize = 0x5C;         // MonoClass -> vtable_size (int)
        private const int kClass_Token = 0x28;              // MonoClass -> type_token

        private const int kMethod_Name = 0x18;              // MonoMethod -> name (const char*)
        private const int kMethod_Klass = 0x10;             // MonoMethod -> klass (MonoClass*)
        private const int kMethod_Flags = 0x20;             // MonoMethod -> flags (uint16)
        private const int kMethod_Token = 0x28;             // MonoMethod -> token (uint32)

        private const int kField_Name = 0x08;               // MonoClassField -> name (const char*)
        private const int kField_Type = 0x00;               // MonoClassField -> type (MonoType*)
        private const int kField_Offset = 0x18;             // MonoClassField -> offset (int)

        private const int kGSList_Data = 0x00;              // GSList -> data
        private const int kGSList_Next = 0x08;              // GSList -> next

        public static RuntimeResolution ResolveFromMonoModule(
            IMemoryReader driver, int pid,
            ulong monoBase, uint monoSize,
            int maxClasses = 5000)
        {
            var result = new RuntimeResolution();

            // Find mono_root_domain via export
            ulong rootDomain = FindRootDomain(driver, pid, monoBase, monoSize);
            if (rootDomain == 0) return result;

            result.Domain = WalkDomain(driver, pid, rootDomain, maxClasses);
            if (result.Domain != null)
            {
                result.TotalAssemblies = result.Domain.Assemblies.Count;
                foreach (var asm in result.Domain.Assemblies)
                {
                    if (asm.Image == null) continue;
                    result.TotalClasses += asm.Image.Classes.Count;
                    foreach (var cls in asm.Image.Classes)
                    {
                        result.TotalMethods += cls.Methods.Count;
                        result.ResolvedNativeAddresses += cls.Methods.Count(m => m.NativeCode != 0);
                    }
                }
            }

            return result;
        }

        private static ulong FindRootDomain(IMemoryReader driver, int pid, ulong monoBase, uint monoSize)
        {
            // Try to find mono_get_root_domain export and call it
            // Alternatively, scan for the domain pointer in mono's .data section
            var exports = driver.GetExportMap(pid);
            if (exports != null)
            {
                foreach (var kvp in exports)
                {
                    if (kvp.Value.funcName == "mono_get_root_domain")
                    {
                        // This is a function, not a variable - we need to find the data it references
                        // Scan the function body for a LEA to a RIP-relative address
                        ulong funcAddr = kvp.Key;
                        byte[] funcBody = ReadMemory(driver, pid, funcAddr, 32);
                        if (funcBody == null) break;

                        // Look for pattern: 48 8B 05 xx xx xx xx (MOV RAX, [rip+disp32])
                        for (int i = 0; i <= funcBody.Length - 7; i++)
                        {
                            if (funcBody[i] == 0x48 && funcBody[i + 1] == 0x8B && funcBody[i + 2] == 0x05)
                            {
                                int disp = BitConverter.ToInt32(funcBody, i + 3);
                                ulong ptrAddr = funcAddr + (ulong)(i + 7) + (ulong)disp;
                                ulong domain = ReadPtr(driver, pid, ptrAddr);
                                if (domain > 0x10000 && domain < 0x7FFFFFFFFFFF)
                                    return domain;
                            }
                        }
                        break;
                    }
                }
            }

            // Fallback: scan mono .data section for domain-like pointers
            byte[] peHeader = ReadMemory(driver, pid, monoBase, 0x1000);
            if (peHeader == null) return 0;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                if (sName != ".data") continue;

                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                ulong dataStart = monoBase + vAddr;
                int dataSize = (int)Math.Min(vSize, 0x200000);

                byte[] data = ReadMemory(driver, pid, dataStart, dataSize);
                if (data == null) continue;

                // Scan for valid domain pointer candidates
                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;

                    // Validate: domain should have a friendly name pointer
                    ulong namePtr = ReadPtr(driver, pid, candidate + kDomain_FriendlyName);
                    if (namePtr == 0) continue;

                    string name = ReadCString(driver, pid, namePtr, 64);
                    if (string.IsNullOrEmpty(name)) continue;

                    // Valid domain candidates usually have recognizable names
                    if (name.Contains(".exe") || name.Contains("Unity") || name.Contains("Mono") || name.Length > 2)
                    {
                        // Verify assemblies list exists
                        ulong asmList = ReadPtr(driver, pid, candidate + kDomain_Assemblies);
                        if (asmList != 0)
                            return candidate;
                    }
                }
            }

            return 0;
        }

        private static MonoDomainInfo WalkDomain(IMemoryReader driver, int pid, ulong domainAddr, int maxClasses)
        {
            var domain = new MonoDomainInfo { Address = domainAddr };

            ulong namePtr = ReadPtr(driver, pid, domainAddr + kDomain_FriendlyName);
            domain.FriendlyName = namePtr != 0 ? ReadCString(driver, pid, namePtr, 128) : "<unknown>";

            // Walk GSList of assemblies
            ulong asmNode = ReadPtr(driver, pid, domainAddr + kDomain_Assemblies);
            int totalClasses = 0;
            int asmCount = 0;

            while (asmNode != 0 && asmCount < 200)
            {
                ulong asmPtr = ReadPtr(driver, pid, asmNode + kGSList_Data);
                if (asmPtr != 0)
                {
                    var asm = ReadAssembly(driver, pid, asmPtr, maxClasses - totalClasses);
                    if (asm != null)
                    {
                        domain.Assemblies.Add(asm);
                        if (asm.Image != null)
                            totalClasses += asm.Image.Classes.Count;
                    }
                }

                asmNode = ReadPtr(driver, pid, asmNode + kGSList_Next);
                asmCount++;

                if (totalClasses >= maxClasses) break;
            }

            return domain;
        }

        private static MonoAssemblyInfo ReadAssembly(IMemoryReader driver, int pid, ulong asmAddr, int maxClasses)
        {
            var asm = new MonoAssemblyInfo { Address = asmAddr };

            // Read assembly name from MonoAssemblyName at asmAddr + kAssembly_AName
            ulong aNamePtr = ReadPtr(driver, pid, asmAddr + kAssembly_AName);
            asm.Name = aNamePtr != 0 ? ReadCString(driver, pid, aNamePtr, 128) : "<unknown>";

            // Read image
            ulong imagePtr = ReadPtr(driver, pid, asmAddr + kAssembly_Image);
            if (imagePtr != 0)
            {
                asm.Image = ReadImage(driver, pid, imagePtr, maxClasses);
            }

            return asm;
        }

        private static MonoImageInfo ReadImage(IMemoryReader driver, int pid, ulong imageAddr, int maxClasses)
        {
            var image = new MonoImageInfo { Address = imageAddr };

            ulong namePtr = ReadPtr(driver, pid, imageAddr + kImage_Name);
            image.Name = namePtr != 0 ? ReadCString(driver, pid, namePtr, 128) : "<unknown>";

            ulong fileNamePtr = ReadPtr(driver, pid, imageAddr + kImage_FileName);
            image.FileName = fileNamePtr != 0 ? ReadCString(driver, pid, fileNamePtr, 256) : "";

            // Try to walk the class cache hash table
            // MonoInternalHashTable: { GHashFunc hash_func; MonoInternalHashEntry** table; int size; int num_entries; ... }
            // We'll try reading the class_def table which is simpler
            ulong classTablePtr = ReadPtr(driver, pid, imageAddr + kImage_TypeDef);
            if (classTablePtr == 0) return image;

            // Read up to maxClasses class pointers from the table
            int readCount = Math.Min(maxClasses, 10000);
            byte[] tableData = ReadMemory(driver, pid, classTablePtr, readCount * 8);
            if (tableData == null) return image;

            for (int i = 0; i < readCount; i++)
            {
                ulong classPtr = BitConverter.ToUInt64(tableData, i * 8);
                if (classPtr == 0) continue;
                if (classPtr < 0x10000 || classPtr > 0x7FFFFFFFFFFF) continue;

                var cls = ReadClass(driver, pid, classPtr);
                if (cls != null && !string.IsNullOrEmpty(cls.Name))
                {
                    image.Classes.Add(cls);
                    image.ClassCount++;
                }

                if (image.Classes.Count >= maxClasses) break;
            }

            return image;
        }

        private static MonoClassInfo ReadClass(IMemoryReader driver, int pid, ulong classAddr)
        {
            var cls = new MonoClassInfo { Address = classAddr };

            ulong namePtr = ReadPtr(driver, pid, classAddr + kClass_Name);
            cls.Name = namePtr != 0 ? ReadCString(driver, pid, namePtr, 128) : null;
            if (string.IsNullOrEmpty(cls.Name)) return null;

            ulong nsPtr = ReadPtr(driver, pid, classAddr + kClass_Namespace);
            cls.Namespace = nsPtr != 0 ? ReadCString(driver, pid, nsPtr, 128) : "";

            cls.FullName = string.IsNullOrEmpty(cls.Namespace) ? cls.Name : $"{cls.Namespace}.{cls.Name}";

            // Read counts
            byte[] countData = ReadMemory(driver, pid, classAddr + kClass_FieldCount, 4);
            if (countData != null)
            {
                cls.FieldCount = BitConverter.ToUInt16(countData, 0);
                cls.MethodCount = BitConverter.ToUInt16(countData, 2);
            }

            // Read token
            byte[] tokenData = ReadMemory(driver, pid, classAddr + kClass_Token, 4);
            if (tokenData != null)
                cls.Token = BitConverter.ToUInt32(tokenData, 0);

            // Read vtable info
            byte[] vtSizeData = ReadMemory(driver, pid, classAddr + kClass_VTableSize, 4);
            if (vtSizeData != null)
                cls.VTableSize = BitConverter.ToInt32(vtSizeData, 0);

            cls.VTableAddress = ReadPtr(driver, pid, classAddr + kClass_VTable);

            // Read methods (limit to avoid huge reads)
            if (cls.MethodCount > 0 && cls.MethodCount < 500)
            {
                ulong methodsPtr = ReadPtr(driver, pid, classAddr + kClass_Methods);
                if (methodsPtr != 0)
                {
                    byte[] methodPtrs = ReadMemory(driver, pid, methodsPtr, cls.MethodCount * 8);
                    if (methodPtrs != null)
                    {
                        for (int m = 0; m < cls.MethodCount; m++)
                        {
                            ulong mPtr = BitConverter.ToUInt64(methodPtrs, m * 8);
                            if (mPtr == 0) continue;

                            var method = ReadMethod(driver, pid, mPtr);
                            if (method != null)
                                cls.Methods.Add(method);
                        }
                    }
                }
            }

            // Read fields (limit)
            if (cls.FieldCount > 0 && cls.FieldCount < 500)
            {
                ulong fieldsPtr = ReadPtr(driver, pid, classAddr + kClass_Fields);
                if (fieldsPtr != 0)
                {
                    int fieldStructSize = 0x20; // MonoClassField is ~32 bytes
                    byte[] fieldData = ReadMemory(driver, pid, fieldsPtr, cls.FieldCount * fieldStructSize);
                    if (fieldData != null)
                    {
                        for (int f = 0; f < cls.FieldCount; f++)
                        {
                            int fOff = f * fieldStructSize;
                            ulong fNamePtr = BitConverter.ToUInt64(fieldData, fOff + kField_Name);

                            string fName = fNamePtr != 0 ? ReadCString(driver, pid, fNamePtr, 64) : null;
                            if (string.IsNullOrEmpty(fName)) continue;

                            int fOffset = BitConverter.ToInt32(fieldData, fOff + kField_Offset);

                            cls.Fields.Add(new MonoFieldInfo
                            {
                                Address = fieldsPtr + (ulong)(f * fieldStructSize),
                                Name = fName,
                                Offset = fOffset
                            });
                        }
                    }
                }
            }

            return cls;
        }

        private static MonoMethodInfo ReadMethod(IMemoryReader driver, int pid, ulong methodAddr)
        {
            var method = new MonoMethodInfo { Address = methodAddr };

            ulong namePtr = ReadPtr(driver, pid, methodAddr + kMethod_Name);
            method.Name = namePtr != 0 ? ReadCString(driver, pid, namePtr, 128) : null;
            if (string.IsNullOrEmpty(method.Name)) return null;

            byte[] flagsData = ReadMemory(driver, pid, methodAddr + kMethod_Flags, 2);
            if (flagsData != null)
            {
                method.Flags = BitConverter.ToUInt16(flagsData, 0);
                method.IsStatic = (method.Flags & 0x10) != 0;    // METHOD_ATTRIBUTE_STATIC
                method.IsVirtual = (method.Flags & 0x40) != 0;   // METHOD_ATTRIBUTE_VIRTUAL
            }

            byte[] tokenData = ReadMemory(driver, pid, methodAddr + kMethod_Token, 4);
            if (tokenData != null)
                method.Token = BitConverter.ToUInt32(tokenData, 0);

            // Try to get the JIT-compiled native code address
            // mono_jit_info_table_find or direct from MonoJitInfo
            // The compiled_code pointer is typically at method + specific offset
            // This varies heavily by Mono version, try reading from vtable entries instead
            method.NativeCode = 0;

            return method;
        }

        public static string GenerateReport(RuntimeResolution result, string search = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Mono Runtime Resolution Report");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");

            if (result.Domain != null)
            {
                sb.AppendLine($"// Domain: {result.Domain.FriendlyName}");
                sb.AppendLine($"// Assemblies: {result.TotalAssemblies}");
                sb.AppendLine($"// Classes: {result.TotalClasses}");
                sb.AppendLine($"// Methods: {result.TotalMethods}");
                sb.AppendLine($"// Resolved native addresses: {result.ResolvedNativeAddresses}");
            }
            sb.AppendLine();

            if (result.Domain == null) return sb.ToString();

            foreach (var asm in result.Domain.Assemblies)
            {
                if (asm.Image == null || asm.Image.Classes.Count == 0) continue;

                var classes = asm.Image.Classes.AsEnumerable();
                if (!string.IsNullOrEmpty(search))
                {
                    classes = classes.Where(c =>
                        c.FullName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0);
                }

                var filteredClasses = classes.ToList();
                if (filteredClasses.Count == 0) continue;

                sb.AppendLine($"// === Assembly: {asm.Name} ({filteredClasses.Count} classes) ===");

                foreach (var cls in filteredClasses.OrderBy(c => c.FullName))
                {
                    sb.AppendLine($"class {cls.FullName} // 0x{cls.Address:X} token:0x{cls.Token:X8}");

                    foreach (var field in cls.Fields)
                    {
                        sb.AppendLine($"  field {field.Name} // offset: 0x{field.Offset:X}");
                    }

                    foreach (var method in cls.Methods)
                    {
                        string modifiers = "";
                        if (method.IsStatic) modifiers += "static ";
                        if (method.IsVirtual) modifiers += "virtual ";

                        string native = method.NativeCode != 0 ? $" -> 0x{method.NativeCode:X}" : "";
                        sb.AppendLine($"  {modifiers}method {method.Name} // 0x{method.Address:X} token:0x{method.Token:X8}{native}");
                    }

                    sb.AppendLine();
                }
            }

            return sb.ToString();
        }

        public static Dictionary<string, ulong> GetMethodAddressMap(RuntimeResolution result, string filter = null)
        {
            var map = new Dictionary<string, ulong>();
            if (result.Domain == null) return map;

            foreach (var asm in result.Domain.Assemblies)
            {
                if (asm.Image == null) continue;
                foreach (var cls in asm.Image.Classes)
                {
                    foreach (var method in cls.Methods)
                    {
                        string fullName = $"{cls.FullName}.{method.Name}";
                        if (!string.IsNullOrEmpty(filter) &&
                            fullName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                            continue;

                        if (!map.ContainsKey(fullName))
                            map[fullName] = method.Address;
                    }
                }
            }

            return map;
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
