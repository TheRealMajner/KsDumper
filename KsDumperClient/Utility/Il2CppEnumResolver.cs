using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppEnumResolver
    {
        public class EnumValue
        {
            public string Name;
            public long Value;
            public string HexValue;
        }

        public class EnumInfo
        {
            public string TypeName;
            public string UnderlyingType;
            public bool IsFlags;
            public ulong KlassPointer;
            public List<EnumValue> Values = new List<EnumValue>();
        }

        public class EnumDumpResult
        {
            public List<EnumInfo> Enums = new List<EnumInfo>();
            public int TotalEnums;
            public int TotalValues;
        }

        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;
        private const int kClass_Fields = 0x60;
        private const int kClass_FieldCount = 0x100;
        private const int kClass_Flags = 0xF4;
        private const int kClass_Parent = 0x38;
        private const int kClass_StaticFields = 0x98;
        private const int kClass_Bitfield = 0x10C;

        // Il2CppType enum values
        private const int IL2CPP_TYPE_ENUM = 0x55;

        // TypeAttributes.Sealed = 0x100, for enum check
        private const uint TYPE_ATTRIBUTE_SEALED = 0x100;
        private const uint TYPE_ATTRIBUTE_SERIALIZABLE = 0x2000;

        public static EnumDumpResult DumpEnums(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot,
            string filter = null,
            int maxEnums = 5000)
        {
            var result = new EnumDumpResult();

            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return result;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            var seenKlass = new HashSet<ulong>();

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
                    if (result.Enums.Count >= maxEnums) break;

                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;
                    if (seenKlass.Contains(candidate)) continue;
                    seenKlass.Add(candidate);

                    var enumInfo = TryReadEnum(driver, pid, candidate, filter);
                    if (enumInfo == null) continue;

                    result.Enums.Add(enumInfo);
                    result.TotalEnums++;
                    result.TotalValues += enumInfo.Values.Count;
                }
            }

            return result;
        }

        private static EnumInfo TryReadEnum(IMemoryReader driver, int pid, ulong klassAddr, string filter)
        {
            byte[] klassData = ReadMemory(driver, pid, klassAddr, 0x110);
            if (klassData == null) return null;

            // Check if this is an enum by checking parent class
            ulong parentPtr = BitConverter.ToUInt64(klassData, kClass_Parent);
            if (parentPtr == 0) return null;

            // Read parent class name
            ulong parentNamePtr = ReadPtr(driver, pid, parentPtr + kClass_Name);
            if (parentNamePtr == 0) return null;
            string parentName = ReadCString(driver, pid, parentNamePtr, 64);
            if (parentName != "Enum") return null;

            // Read class name
            ulong namePtr = BitConverter.ToUInt64(klassData, kClass_Name);
            if (namePtr < 0x10000 || namePtr > 0x7FFFFFFFFFFF) return null;
            string name = ReadCString(driver, pid, namePtr, 128);
            if (string.IsNullOrEmpty(name)) return null;

            foreach (char c in name)
                if (c < 0x20 || c > 0x7E)
                    if (c != '<' && c != '>' && c != '`')
                        return null;

            ulong nsPtr = BitConverter.ToUInt64(klassData, kClass_Namespace);
            string ns = nsPtr != 0 ? ReadCString(driver, pid, nsPtr, 128) : "";
            string fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";

            if (!string.IsNullOrEmpty(filter) &&
                fullName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                return null;

            uint flags = BitConverter.ToUInt32(klassData, kClass_Flags);
            ushort fieldCount = BitConverter.ToUInt16(klassData, kClass_FieldCount);

            if (fieldCount == 0 || fieldCount > 1000) return null;

            var enumInfo = new EnumInfo
            {
                TypeName = fullName,
                KlassPointer = klassAddr,
                IsFlags = false // Will try to detect from [Flags] attribute presence
            };

            // Read fields to get enum values
            ulong fieldsPtr = BitConverter.ToUInt64(klassData, kClass_Fields);
            if (fieldsPtr == 0 || fieldsPtr < 0x10000) return null;

            // Field struct: 0x20 bytes each
            // Offset 0x00: Il2CppType* type
            // Offset 0x08: const char* name
            // Offset 0x18: int32 offset
            byte[] fieldData = ReadMemory(driver, pid, fieldsPtr, fieldCount * 0x20);
            if (fieldData == null) return null;

            // Read static fields data
            ulong staticFieldsPtr = BitConverter.ToUInt64(klassData, kClass_StaticFields);

            for (int f = 0; f < fieldCount; f++)
            {
                int fOff = f * 0x20;
                ulong typePtr = BitConverter.ToUInt64(fieldData, fOff);
                ulong fieldNamePtr = BitConverter.ToUInt64(fieldData, fOff + 8);
                int fieldOffset = BitConverter.ToInt32(fieldData, fOff + 0x18);

                if (fieldNamePtr == 0 || fieldNamePtr < 0x10000) continue;
                string fieldName = ReadCString(driver, pid, fieldNamePtr, 128);
                if (string.IsNullOrEmpty(fieldName)) continue;

                // Skip "value__" (the underlying value field)
                if (fieldName == "value__")
                {
                    // Determine underlying type from this field's type
                    if (typePtr != 0)
                    {
                        byte[] typeData = ReadMemory(driver, pid, typePtr, 16);
                        if (typeData != null)
                        {
                            byte typeKind = typeData[0]; // Il2CppType.type
                            enumInfo.UnderlyingType = GetUnderlyingTypeName(typeKind);
                        }
                    }
                    continue;
                }

                // Read the constant value from static fields
                long value = 0;
                if (staticFieldsPtr != 0 && fieldOffset >= 0 && fieldOffset < 0x10000)
                {
                    byte[] valBuf = ReadMemory(driver, pid, staticFieldsPtr + (ulong)fieldOffset, 8);
                    if (valBuf != null)
                    {
                        value = BitConverter.ToInt64(valBuf, 0);
                    }
                }

                enumInfo.Values.Add(new EnumValue
                {
                    Name = fieldName,
                    Value = value,
                    HexValue = $"0x{value:X}"
                });
            }

            if (enumInfo.Values.Count == 0) return null;

            // Heuristic: check if values are powers of 2 (likely [Flags])
            if (enumInfo.Values.Count >= 3)
            {
                int powerOf2Count = enumInfo.Values.Count(v => v.Value > 0 && (v.Value & (v.Value - 1)) == 0);
                if ((float)powerOf2Count / enumInfo.Values.Count > 0.6f)
                    enumInfo.IsFlags = true;
            }

            if (string.IsNullOrEmpty(enumInfo.UnderlyingType))
                enumInfo.UnderlyingType = "int";

            return enumInfo;
        }

        private static string GetUnderlyingTypeName(byte typeKind)
        {
            switch (typeKind)
            {
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
                default: return "int";
            }
        }

        public static string GenerateReport(EnumDumpResult result, string search = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Enum Value Resolver");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Enums found: {result.TotalEnums}");
            sb.AppendLine($"// Total values: {result.TotalValues}");
            sb.AppendLine();

            var enums = result.Enums.AsEnumerable();
            if (!string.IsNullOrEmpty(search))
            {
                enums = enums.Where(e =>
                    e.TypeName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    e.Values.Any(v => v.Name.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0));
            }

            foreach (var e in enums.OrderBy(e => e.TypeName))
            {
                string flags = e.IsFlags ? " [Flags]" : "";
                sb.AppendLine($"enum {e.TypeName} : {e.UnderlyingType}{flags}");
                sb.AppendLine("{");
                foreach (var v in e.Values.OrderBy(v => v.Value))
                {
                    sb.AppendLine($"    {v.Name} = {v.Value}, // {v.HexValue}");
                }
                sb.AppendLine("}");
                sb.AppendLine();
            }

            return sb.ToString();
        }

        public static string GenerateCSharpEnums(EnumDumpResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// Auto-generated enum definitions from IL2CPP runtime");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            foreach (var e in result.Enums.OrderBy(e => e.TypeName))
            {
                if (e.IsFlags)
                    sb.AppendLine("[Flags]");
                sb.AppendLine($"public enum {e.TypeName.Split('.').Last()} : {e.UnderlyingType}");
                sb.AppendLine("{");
                foreach (var v in e.Values.OrderBy(v => v.Value))
                {
                    sb.AppendLine($"    {v.Name} = {v.Value},");
                }
                sb.AppendLine("}");
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
