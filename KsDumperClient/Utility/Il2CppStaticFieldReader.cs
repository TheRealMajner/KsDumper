using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppStaticFieldReader
    {
        public class StaticFieldValue
        {
            public string FieldName;
            public string TypeName;
            public byte TypeKind;
            public int Offset;
            public byte[] RawBytes;
            public string FormattedValue;
            public ulong PointerValue;
            public bool IsPointer;
        }

        public class StaticClassInfo
        {
            public string ClassName;
            public ulong KlassPointer;
            public ulong StaticFieldsPointer;
            public List<StaticFieldValue> Fields = new List<StaticFieldValue>();
        }

        public class StaticFieldDumpResult
        {
            public List<StaticClassInfo> Classes = new List<StaticClassInfo>();
            public int TotalClasses;
            public int TotalFields;
        }

        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;
        private const int kClass_Fields = 0x60;
        private const int kClass_FieldCount = 0x100;
        private const int kClass_StaticFields = 0x98;
        private const int kClass_Parent = 0x38;

        public static StaticFieldDumpResult ReadStaticFields(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            string filter = null,
            string fieldFilter = null,
            int maxClasses = 2000)
        {
            var result = new StaticFieldDumpResult();

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
                    if (result.Classes.Count >= maxClasses) break;

                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;
                    if (seenKlass.Contains(candidate)) continue;
                    seenKlass.Add(candidate);

                    var classInfo = TryReadStaticClass(driver, pid, candidate, filter, fieldFilter);
                    if (classInfo != null)
                    {
                        result.Classes.Add(classInfo);
                        result.TotalClasses++;
                        result.TotalFields += classInfo.Fields.Count;
                    }
                }
            }

            return result;
        }

        private static StaticClassInfo TryReadStaticClass(
            IMemoryReader driver, int pid, ulong klassAddr,
            string classFilter, string fieldFilter)
        {
            byte[] klassData = ReadMemory(driver, pid, klassAddr, 0x110);
            if (klassData == null) return null;

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

            if (!string.IsNullOrEmpty(classFilter) &&
                fullName.IndexOf(classFilter, StringComparison.OrdinalIgnoreCase) < 0)
                return null;

            ulong staticFieldsPtr = BitConverter.ToUInt64(klassData, kClass_StaticFields);
            if (staticFieldsPtr == 0 || staticFieldsPtr < 0x10000) return null;

            ushort fieldCount = BitConverter.ToUInt16(klassData, kClass_FieldCount);
            if (fieldCount == 0 || fieldCount > 1000) return null;

            ulong fieldsPtr = BitConverter.ToUInt64(klassData, kClass_Fields);
            if (fieldsPtr == 0 || fieldsPtr < 0x10000) return null;

            byte[] fieldData = ReadMemory(driver, pid, fieldsPtr, fieldCount * 0x20);
            if (fieldData == null) return null;

            // Read static fields data (up to 4KB)
            byte[] staticData = ReadMemory(driver, pid, staticFieldsPtr, 0x1000);
            if (staticData == null) return null;

            var classInfo = new StaticClassInfo
            {
                ClassName = fullName,
                KlassPointer = klassAddr,
                StaticFieldsPointer = staticFieldsPtr
            };

            for (int f = 0; f < fieldCount; f++)
            {
                int fOff = f * 0x20;
                ulong typePtr = BitConverter.ToUInt64(fieldData, fOff);
                ulong fieldNamePtr = BitConverter.ToUInt64(fieldData, fOff + 8);
                int fieldOffset = BitConverter.ToInt32(fieldData, fOff + 0x18);

                if (fieldNamePtr == 0 || fieldNamePtr < 0x10000) continue;
                string fieldName = ReadCString(driver, pid, fieldNamePtr, 128);
                if (string.IsNullOrEmpty(fieldName)) continue;

                // Check if this is a static field (offset >= 0 within static fields block)
                if (fieldOffset < 0 || fieldOffset >= staticData.Length) continue;

                if (!string.IsNullOrEmpty(fieldFilter) &&
                    fieldName.IndexOf(fieldFilter, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;

                byte typeKind = 0;
                if (typePtr != 0 && typePtr >= 0x10000)
                {
                    byte[] typeData = ReadMemory(driver, pid, typePtr, 8);
                    if (typeData != null)
                        typeKind = typeData[0];
                }

                var fieldValue = new StaticFieldValue
                {
                    FieldName = fieldName,
                    TypeKind = typeKind,
                    Offset = fieldOffset,
                    TypeName = GetTypeName(typeKind)
                };

                int valueSize = GetValueSize(typeKind);
                if (fieldOffset + valueSize <= staticData.Length)
                {
                    fieldValue.RawBytes = new byte[valueSize];
                    Buffer.BlockCopy(staticData, fieldOffset, fieldValue.RawBytes, 0, valueSize);
                    fieldValue.FormattedValue = FormatValue(fieldValue.RawBytes, typeKind);

                    if (typeKind == 0x12 || typeKind == 0x11 || typeKind == 0x1C || typeKind == 0x0E)
                    {
                        if (valueSize >= 8)
                        {
                            fieldValue.PointerValue = BitConverter.ToUInt64(fieldValue.RawBytes, 0);
                            fieldValue.IsPointer = fieldValue.PointerValue >= 0x10000 && fieldValue.PointerValue < 0x7FFFFFFFFFFF;

                            if (fieldValue.IsPointer && typeKind == 0x0E) // string
                            {
                                string strVal = TryReadManagedString(driver, pid, fieldValue.PointerValue);
                                if (strVal != null)
                                    fieldValue.FormattedValue = $"\"{strVal}\"";
                            }
                        }
                    }
                }

                classInfo.Fields.Add(fieldValue);
            }

            if (classInfo.Fields.Count == 0) return null;
            return classInfo;
        }

        private static string TryReadManagedString(IMemoryReader driver, int pid, ulong addr)
        {
            byte[] header = ReadMemory(driver, pid, addr, 0x40);
            if (header == null) return null;

            int len = BitConverter.ToInt32(header, 0x10);
            if (len <= 0 || len > 500) return null;

            int charStart = 0x14;
            if (charStart + len * 2 <= header.Length)
            {
                return Encoding.Unicode.GetString(header, charStart, len * 2);
            }

            byte[] chars = ReadMemory(driver, pid, addr + (ulong)charStart, len * 2);
            if (chars == null) return null;
            return Encoding.Unicode.GetString(chars, 0, len * 2);
        }

        private static string GetTypeName(byte typeKind)
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
                case 0x11: return "class";
                case 0x12: return "struct";
                case 0x1C: return "object";
                case 0x1D: return "array";
                default: return $"type_0x{typeKind:X2}";
            }
        }

        private static int GetValueSize(byte typeKind)
        {
            switch (typeKind)
            {
                case 0x02: return 1; // bool
                case 0x03: return 2; // char
                case 0x04: return 1; // sbyte
                case 0x05: return 1; // byte
                case 0x06: return 2; // short
                case 0x07: return 2; // ushort
                case 0x08: return 4; // int
                case 0x09: return 4; // uint
                case 0x0A: return 8; // long
                case 0x0B: return 8; // ulong
                case 0x0C: return 4; // float
                case 0x0D: return 8; // double
                default: return 8;   // pointer/reference
            }
        }

        private static string FormatValue(byte[] raw, byte typeKind)
        {
            switch (typeKind)
            {
                case 0x02: return raw[0] != 0 ? "true" : "false";
                case 0x03: return $"'{(char)BitConverter.ToUInt16(raw, 0)}'";
                case 0x04: return ((sbyte)raw[0]).ToString();
                case 0x05: return raw[0].ToString();
                case 0x06: return BitConverter.ToInt16(raw, 0).ToString();
                case 0x07: return BitConverter.ToUInt16(raw, 0).ToString();
                case 0x08: return BitConverter.ToInt32(raw, 0).ToString();
                case 0x09: return BitConverter.ToUInt32(raw, 0).ToString();
                case 0x0A: return BitConverter.ToInt64(raw, 0).ToString();
                case 0x0B: return BitConverter.ToUInt64(raw, 0).ToString();
                case 0x0C: return BitConverter.ToSingle(raw, 0).ToString("G6");
                case 0x0D: return BitConverter.ToDouble(raw, 0).ToString("G6");
                default:
                {
                    if (raw.Length >= 8)
                    {
                        ulong ptr = BitConverter.ToUInt64(raw, 0);
                        if (ptr == 0) return "null";
                        return $"0x{ptr:X}";
                    }
                    return BitConverter.ToString(raw).Replace("-", " ");
                }
            }
        }

        public static string GenerateReport(StaticFieldDumpResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Static Field Value Reader");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Classes with static fields: {result.TotalClasses}");
            sb.AppendLine($"// Total static fields: {result.TotalFields}");
            sb.AppendLine();

            foreach (var cls in result.Classes.OrderBy(c => c.ClassName))
            {
                sb.AppendLine($"{cls.ClassName} (staticFields: 0x{cls.StaticFieldsPointer:X})");

                foreach (var field in cls.Fields.OrderBy(f => f.Offset))
                {
                    string ptr = field.IsPointer ? $" -> 0x{field.PointerValue:X}" : "";
                    sb.AppendLine($"  +0x{field.Offset:X3} {field.TypeName} {field.FieldName} = {field.FormattedValue}{ptr}");
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
