using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class Il2CppInstanceScanner
    {
        public class InstanceInfo
        {
            public ulong Address;
            public ulong KlassPointer;
            public string ClassName;
            public uint InstanceSize;
            public Dictionary<string, FieldValue> Fields = new Dictionary<string, FieldValue>();
        }

        public class FieldValue
        {
            public string Name;
            public int Offset;
            public string TypeName;
            public object Value;
            public string DisplayValue;
        }

        public class ScanResult
        {
            public string TargetClass;
            public ulong TargetKlass;
            public int InstancesFound;
            public List<InstanceInfo> Instances = new List<InstanceInfo>();
            public long ScanTimeMs;
        }

        // Il2CppObject layout: klass pointer at +0x00, monitor at +0x08, fields start at +0x10
        private const int kObject_Klass = 0x00;
        private const int kObject_Monitor = 0x08;
        private const int kObject_FieldsStart = 0x10;

        // Il2CppClass layout
        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;
        private const int kClass_InstanceSize = 0xD8;
        private const int kClass_Fields = 0x60;
        private const int kClass_FieldCount = 0x100;

        private const int kField_Name = 0x08;
        private const int kField_Offset = 0x18;
        private const int kField_Size = 0x20;

        public static ScanResult ScanForInstances(
            IMemoryReader driver, int pid,
            ulong targetKlass,
            int maxInstances = 500,
            bool readFields = true)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var result = new ScanResult { TargetKlass = targetKlass };

            // Read class info
            byte[] klassData = ReadMemory(driver, pid, targetKlass, 0x110);
            if (klassData == null) return result;

            ulong namePtr = BitConverter.ToUInt64(klassData, kClass_Name);
            result.TargetClass = namePtr != 0 ? ReadCString(driver, pid, namePtr, 128) : "<unknown>";

            uint instanceSize = BitConverter.ToUInt32(klassData, kClass_InstanceSize);
            if (instanceSize == 0 || instanceSize > 0x10000) return result;

            // Read field definitions for the class
            var fieldDefs = new List<(string name, int offset)>();
            if (readFields)
            {
                ushort fieldCount = BitConverter.ToUInt16(klassData, kClass_FieldCount);
                ulong fieldsPtr = BitConverter.ToUInt64(klassData, kClass_Fields);
                if (fieldsPtr != 0 && fieldCount > 0 && fieldCount < 500)
                {
                    byte[] fieldData = ReadMemory(driver, pid, fieldsPtr, fieldCount * kField_Size);
                    if (fieldData != null)
                    {
                        for (int f = 0; f < fieldCount; f++)
                        {
                            ulong fNamePtr = BitConverter.ToUInt64(fieldData, f * kField_Size + kField_Name);
                            string fName = fNamePtr != 0 ? ReadCString(driver, pid, fNamePtr, 64) : null;
                            int fOffset = BitConverter.ToInt32(fieldData, f * kField_Size + kField_Offset);
                            if (!string.IsNullOrEmpty(fName) && fOffset >= 0 && fOffset < (int)instanceSize)
                                fieldDefs.Add((fName, fOffset));
                        }
                    }
                }
            }

            // Scan heap regions (PAGE_READWRITE, MEM_COMMIT)
            var regions = driver.EnumRegions(pid);
            if (regions == null) return result;

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (result.Instances.Count >= maxInstances) break;

                // Only scan committed, writable, private pages
                if (state != 0x1000) continue; // MEM_COMMIT
                if ((protect & 0x04) == 0 && (protect & 0x08) == 0) continue; // PAGE_READWRITE or PAGE_WRITECOPY
                if (regionSize < instanceSize || regionSize > 0x10000000) continue;

                int readSize = (int)Math.Min(regionSize, 0x1000000);
                byte[] data = ReadMemory(driver, pid, baseAddr, readSize);
                if (data == null) continue;

                // Scan for objects whose klass pointer matches targetKlass
                for (int i = 0; i <= data.Length - (int)instanceSize; i += 8)
                {
                    if (result.Instances.Count >= maxInstances) break;

                    ulong klassPtr = BitConverter.ToUInt64(data, i);
                    if (klassPtr != targetKlass) continue;

                    // Validate monitor field (should be 0 or a valid pointer)
                    if (i + 8 < data.Length)
                    {
                        ulong monitor = BitConverter.ToUInt64(data, i + 8);
                        if (monitor != 0 && (monitor < 0x10000 || monitor > 0x7FFFFFFFFFFF))
                            continue;
                    }

                    ulong objAddr = baseAddr + (ulong)i;
                    var instance = new InstanceInfo
                    {
                        Address = objAddr,
                        KlassPointer = targetKlass,
                        ClassName = result.TargetClass,
                        InstanceSize = instanceSize
                    };

                    // Read field values
                    if (readFields && fieldDefs.Count > 0)
                    {
                        int dataRemaining = data.Length - i;
                        foreach (var (name, offset) in fieldDefs)
                        {
                            if (offset + 8 > dataRemaining) break;

                            var fv = new FieldValue
                            {
                                Name = name,
                                Offset = offset
                            };

                            // Try to read as different types and pick the most useful representation
                            if (offset + 8 <= dataRemaining)
                            {
                                long i64 = BitConverter.ToInt64(data, i + offset);
                                int i32 = BitConverter.ToInt32(data, i + offset);
                                float f32 = BitConverter.ToSingle(data, i + offset);

                                // Heuristic: if it looks like a pointer, show as hex
                                if (i64 > 0x10000 && i64 < 0x7FFFFFFFFFFF)
                                {
                                    fv.Value = (ulong)i64;
                                    fv.DisplayValue = $"0x{i64:X}";

                                    // Try to read as string if it looks like a string pointer
                                    string asString = ReadCString(driver, pid, (ulong)i64, 64);
                                    if (!string.IsNullOrEmpty(asString) && asString.Length > 1 && IsReadableString(asString))
                                        fv.DisplayValue = $"0x{i64:X} (\"{asString}\")";
                                }
                                else if (Math.Abs(f32) > 0.0001f && Math.Abs(f32) < 1e10f && !float.IsNaN(f32) && !float.IsInfinity(f32))
                                {
                                    fv.Value = f32;
                                    fv.DisplayValue = $"{f32:F3} (0x{i32:X8})";
                                }
                                else
                                {
                                    fv.Value = i32;
                                    fv.DisplayValue = $"{i32} (0x{i32:X8})";
                                }
                            }

                            instance.Fields[name] = fv;
                        }
                    }

                    result.Instances.Add(instance);
                }
            }

            result.InstancesFound = result.Instances.Count;
            sw.Stop();
            result.ScanTimeMs = sw.ElapsedMilliseconds;
            return result;
        }

        public static ScanResult ScanByClassName(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            string className,
            int maxInstances = 500)
        {
            // First find the Il2CppClass* for the target class name
            ulong targetKlass = FindKlassByName(driver, pid, gaBase, gaSize, className);
            if (targetKlass == 0)
                return new ScanResult { TargetClass = className };

            return ScanForInstances(driver, pid, targetKlass, maxInstances);
        }

        private static ulong FindKlassByName(IMemoryReader driver, int pid, ulong gaBase, uint gaSize, string className)
        {
            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
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
                if (sName != ".data" && sName != ".rdata") continue;

                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                ulong secStart = gaBase + vAddr;
                int readSize = (int)Math.Min(vSize, 0x4000000);

                byte[] data = ReadMemory(driver, pid, secStart, readSize);
                if (data == null) continue;

                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;

                    // Check if this pointer leads to an Il2CppClass with matching name
                    ulong namePtr = ReadPtr(driver, pid, candidate + kClass_Name);
                    if (namePtr == 0) continue;

                    string name = ReadCString(driver, pid, namePtr, 128);
                    if (name == null) continue;

                    if (name.Equals(className, StringComparison.OrdinalIgnoreCase) ||
                        name.EndsWith("." + className, StringComparison.OrdinalIgnoreCase))
                    {
                        // Validate further: instance size should be reasonable
                        byte[] sizeData = ReadMemory(driver, pid, candidate + kClass_InstanceSize, 4);
                        if (sizeData == null) continue;
                        uint iSize = BitConverter.ToUInt32(sizeData, 0);
                        if (iSize > 0 && iSize < 0x10000)
                            return candidate;
                    }
                }
            }

            return 0;
        }

        public static string GenerateReport(ScanResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Instance Scanner");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Target class: {result.TargetClass}");
            sb.AppendLine($"// Target klass: 0x{result.TargetKlass:X16}");
            sb.AppendLine($"// Instances found: {result.InstancesFound}");
            sb.AppendLine($"// Scan time: {result.ScanTimeMs}ms");
            sb.AppendLine();

            int idx = 0;
            foreach (var inst in result.Instances)
            {
                sb.AppendLine($"Instance #{idx++} @ 0x{inst.Address:X16} (size: 0x{inst.InstanceSize:X})");

                foreach (var field in inst.Fields.Values.OrderBy(f => f.Offset))
                {
                    sb.AppendLine($"  +0x{field.Offset:X4} {field.Name,-30} = {field.DisplayValue}");
                }
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private static bool IsReadableString(string s)
        {
            foreach (char c in s)
                if (c < 0x20 || c > 0x7E) return false;
            return true;
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
