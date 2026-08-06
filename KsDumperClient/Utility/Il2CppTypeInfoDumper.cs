using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppTypeInfoDumper
    {
        public class RuntimeTypeInfo
        {
            public int TypeIndex;
            public string FullName;
            public ulong KlassPointer;
            public uint InstanceSize;
            public uint ActualSize;
            public uint NativeSize;
            public uint StaticFieldSize;
            public ulong StaticFieldData;
            public int VTableSlotCount;
            public ulong VTablePointer;
            public uint Flags;
            public uint Token;
            public int FieldCount;
            public int MethodCount;
            public int InterfaceCount;
            public ulong ParentKlass;
            public string ParentName;
            public bool IsValueType;
            public bool IsEnum;
            public bool IsInterface;
            public bool IsAbstract;
            public bool IsGeneric;
            public int Bitfield;
            public List<RuntimeFieldLayout> Fields = new List<RuntimeFieldLayout>();
            public List<RuntimeInterfaceEntry> Interfaces = new List<RuntimeInterfaceEntry>();
        }

        public class RuntimeFieldLayout
        {
            public string Name;
            public int Offset;
            public int Size;
            public ulong TypePointer;
            public string TypeName;
            public bool IsStatic;
            public ulong StaticValueAddress;
        }

        public class RuntimeInterfaceEntry
        {
            public ulong KlassPointer;
            public string Name;
            public int InterfaceOffset;
        }

        public class TypeInfoDump
        {
            public List<RuntimeTypeInfo> Types = new List<RuntimeTypeInfo>();
            public int TotalScanned;
            public int TotalResolved;
            public int TotalWithStaticData;
        }

        // Il2CppClass offsets (x64, Unity 2019-2022)
        private const int kClass_Image = 0x00;
        private const int kClass_GC_Desc = 0x08;
        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;
        private const int kClass_ByValArg = 0x20;
        private const int kClass_ThisArg = 0x28;
        private const int kClass_DeclaringType = 0x30;
        private const int kClass_Parent = 0x38;
        private const int kClass_GenericClass = 0x40;
        private const int kClass_TypeMetadataHandle = 0x48;
        private const int kClass_InteropData = 0x50;
        private const int kClass_Klass = 0x58;
        private const int kClass_Fields = 0x60;
        private const int kClass_Events = 0x68;
        private const int kClass_Properties = 0x70;
        private const int kClass_Methods = 0x78;
        private const int kClass_NestedTypes = 0x80;
        private const int kClass_ImplementedInterfaces = 0x88;
        private const int kClass_InterfaceOffsets = 0x90;
        private const int kClass_StaticFields = 0x98;
        private const int kClass_RGCTX_Data = 0xA0;
        private const int kClass_TypeHierarchy = 0xA8;
        private const int kClass_Unity_UserData = 0xB0;
        private const int kClass_InitializationExceptionGCH = 0xB8;
        private const int kClass_CctorStarted = 0xBC;
        private const int kClass_CctorFinished = 0xC0;
        private const int kClass_CctorThread = 0xC8;
        private const int kClass_GenericContainerHandle = 0xD0;
        private const int kClass_InstanceSize = 0xD8;
        private const int kClass_ActualSize = 0xDC;
        private const int kClass_ElementSize = 0xE0;
        private const int kClass_NativeSize = 0xE4;
        private const int kClass_StaticFieldsSize = 0xE8;
        private const int kClass_ThreadStaticFieldsSize = 0xEC;
        private const int kClass_ThreadStaticFieldsOffset = 0xF0;
        private const int kClass_Flags = 0xF4;
        private const int kClass_Token = 0xF8;
        private const int kClass_MethodCount = 0xFC;
        private const int kClass_PropertyCount = 0xFE;
        private const int kClass_FieldCount = 0x100;
        private const int kClass_EventCount = 0x102;
        private const int kClass_NestedTypeCount = 0x104;
        private const int kClass_VTableCount = 0x106;
        private const int kClass_InterfacesCount = 0x108;
        private const int kClass_InterfaceOffsetsCount = 0x10A;
        private const int kClass_Bitfield = 0x10C;

        private const int kClassField_Size = 0x20;
        private const int kField_Type = 0x00;
        private const int kField_Name = 0x08;
        private const int kField_Parent = 0x10;
        private const int kField_Offset = 0x18;

        public static TypeInfoDump DumpTypeInfo(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot,
            string filter = null,
            int maxTypes = 5000)
        {
            var result = new TypeInfoDump();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            // Build type name lookup from metadata
            string[] typeNames = new string[snapshot.TypeDefinitions.Length];
            for (int i = 0; i < snapshot.TypeDefinitions.Length; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                string name = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);
                string ns = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);
                typeNames[i] = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
            }

            // Scan for Il2CppClass* pointers in GA .data section
            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return result;

            var dataSections = ParseDataSections(peHeader, gaBase);
            ulong gaEnd = gaBase + gaSize;
            var seenKlass = new HashSet<ulong>();

            foreach (var (secStart, secSize) in dataSections)
            {
                int readSize = (int)Math.Min(secSize, 0x4000000);
                byte[] data = ReadMemory(driver, pid, secStart, readSize);
                if (data == null) continue;

                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    if (result.Types.Count >= maxTypes) break;

                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;
                    if (seenKlass.Contains(candidate)) continue;

                    var typeInfo = TryReadTypeInfo(driver, pid, candidate, typeNames, gaBase, gaEnd);
                    if (typeInfo == null) continue;

                    seenKlass.Add(candidate);
                    result.TotalScanned++;

                    if (!string.IsNullOrEmpty(filter) &&
                        typeInfo.FullName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;

                    result.Types.Add(typeInfo);
                    result.TotalResolved++;
                    if (typeInfo.StaticFieldData != 0)
                        result.TotalWithStaticData++;
                }
            }

            return result;
        }

        private static RuntimeTypeInfo TryReadTypeInfo(
            IMemoryReader driver, int pid, ulong klassAddr,
            string[] typeNames, ulong gaBase, ulong gaEnd)
        {
            byte[] klassData = ReadMemory(driver, pid, klassAddr, 0x110);
            if (klassData == null) return null;

            // Validate: name and namespace should be valid string pointers
            ulong namePtr = BitConverter.ToUInt64(klassData, kClass_Name);
            ulong nsPtr = BitConverter.ToUInt64(klassData, kClass_Namespace);
            if (namePtr < 0x10000 || namePtr > 0x7FFFFFFFFFFF) return null;

            string name = ReadCString(driver, pid, namePtr, 128);
            if (string.IsNullOrEmpty(name) || name.Length < 1) return null;

            // Filter out garbage by checking for reasonable characters
            foreach (char c in name)
            {
                if (c < 0x20 || c > 0x7E)
                    if (c != '<' && c != '>' && c != '`')
                        return null;
            }

            string ns = nsPtr != 0 ? ReadCString(driver, pid, nsPtr, 128) : "";

            uint instanceSize = BitConverter.ToUInt32(klassData, kClass_InstanceSize);
            uint actualSize = BitConverter.ToUInt32(klassData, kClass_ActualSize);
            uint nativeSize = BitConverter.ToUInt32(klassData, kClass_NativeSize);
            uint staticFieldSize = BitConverter.ToUInt32(klassData, kClass_StaticFieldsSize);
            uint flags = BitConverter.ToUInt32(klassData, kClass_Flags);
            uint token = BitConverter.ToUInt32(klassData, kClass_Token);
            ushort methodCount = BitConverter.ToUInt16(klassData, kClass_MethodCount);
            ushort fieldCount = BitConverter.ToUInt16(klassData, kClass_FieldCount);
            ushort vtableCount = BitConverter.ToUInt16(klassData, kClass_VTableCount);
            ushort interfaceCount = BitConverter.ToUInt16(klassData, kClass_InterfacesCount);
            int bitfield = BitConverter.ToInt32(klassData, kClass_Bitfield);

            // Sanity checks
            if (instanceSize > 0x100000 || methodCount > 10000 || fieldCount > 5000)
                return null;

            ulong parentKlass = BitConverter.ToUInt64(klassData, kClass_Parent);
            string parentName = "";
            if (parentKlass != 0 && parentKlass != klassAddr)
            {
                ulong pNamePtr = ReadPtr(driver, pid, parentKlass + kClass_Name);
                if (pNamePtr != 0)
                    parentName = ReadCString(driver, pid, pNamePtr, 64) ?? "";
            }

            ulong staticFieldData = BitConverter.ToUInt64(klassData, kClass_StaticFields);

            var info = new RuntimeTypeInfo
            {
                FullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}",
                KlassPointer = klassAddr,
                InstanceSize = instanceSize,
                ActualSize = actualSize,
                NativeSize = nativeSize,
                StaticFieldSize = staticFieldSize,
                StaticFieldData = staticFieldData,
                VTableSlotCount = vtableCount,
                Flags = flags,
                Token = token,
                FieldCount = fieldCount,
                MethodCount = methodCount,
                InterfaceCount = interfaceCount,
                ParentKlass = parentKlass,
                ParentName = parentName,
                IsValueType = (bitfield & 0x01) != 0,
                IsEnum = (bitfield & 0x02) != 0,
                IsInterface = (flags & 0x20) != 0,
                IsAbstract = (flags & 0x80) != 0,
                IsGeneric = BitConverter.ToUInt64(klassData, kClass_GenericClass) != 0,
                Bitfield = bitfield
            };

            // Read field layouts
            ulong fieldsPtr = BitConverter.ToUInt64(klassData, kClass_Fields);
            if (fieldsPtr != 0 && fieldCount > 0 && fieldCount < 500)
            {
                byte[] fieldData = ReadMemory(driver, pid, fieldsPtr, fieldCount * kClassField_Size);
                if (fieldData != null)
                {
                    for (int f = 0; f < fieldCount; f++)
                    {
                        int fOff = f * kClassField_Size;
                        ulong fNamePtr = BitConverter.ToUInt64(fieldData, fOff + kField_Name);
                        string fName = fNamePtr != 0 ? ReadCString(driver, pid, fNamePtr, 64) : null;
                        if (string.IsNullOrEmpty(fName)) continue;

                        int offset = BitConverter.ToInt32(fieldData, fOff + kField_Offset);
                        bool isStatic = (offset & unchecked((int)0x80000000)) != 0;
                        if (isStatic) offset &= 0x7FFFFFFF;

                        ulong staticAddr = 0;
                        if (isStatic && staticFieldData != 0)
                            staticAddr = staticFieldData + (ulong)offset;

                        info.Fields.Add(new RuntimeFieldLayout
                        {
                            Name = fName,
                            Offset = offset,
                            IsStatic = isStatic,
                            StaticValueAddress = staticAddr
                        });
                    }
                }
            }

            return info;
        }

        public static string GenerateReport(TypeInfoDump dump, bool showFields = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Runtime TypeInfo Dump");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Types scanned: {dump.TotalScanned}");
            sb.AppendLine($"// Types resolved: {dump.TotalResolved}");
            sb.AppendLine($"// Types with static data: {dump.TotalWithStaticData}");
            sb.AppendLine();

            foreach (var type in dump.Types.OrderBy(t => t.FullName))
            {
                string modifiers = "";
                if (type.IsInterface) modifiers += "interface ";
                else if (type.IsAbstract) modifiers += "abstract class ";
                else if (type.IsValueType) modifiers += "struct ";
                else if (type.IsEnum) modifiers += "enum ";
                else modifiers += "class ";

                string parent = !string.IsNullOrEmpty(type.ParentName) && type.ParentName != "Object"
                    ? $" : {type.ParentName}" : "";

                sb.AppendLine($"{modifiers}{type.FullName}{parent}");
                sb.AppendLine($"  // klass: 0x{type.KlassPointer:X16} token: 0x{type.Token:X8}");
                sb.AppendLine($"  // instance_size: 0x{type.InstanceSize:X} actual_size: 0x{type.ActualSize:X} native_size: 0x{type.NativeSize:X}");

                if (type.StaticFieldSize > 0)
                    sb.AppendLine($"  // static_fields: 0x{type.StaticFieldData:X16} ({type.StaticFieldSize} bytes)");

                sb.AppendLine($"  // fields: {type.FieldCount} methods: {type.MethodCount} vtable: {type.VTableSlotCount} interfaces: {type.InterfaceCount}");

                if (showFields && type.Fields.Count > 0)
                {
                    foreach (var field in type.Fields.OrderBy(f => f.IsStatic).ThenBy(f => f.Offset))
                    {
                        string staticStr = field.IsStatic ? "static " : "";
                        string addrStr = field.IsStatic && field.StaticValueAddress != 0
                            ? $" @ 0x{field.StaticValueAddress:X}" : "";
                        sb.AppendLine($"  {staticStr}{field.Name} // offset: 0x{field.Offset:X}{addrStr}");
                    }
                }

                sb.AppendLine();
            }

            return sb.ToString();
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
