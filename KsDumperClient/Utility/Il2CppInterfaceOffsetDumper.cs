using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppInterfaceOffsetDumper
    {
        public class InterfaceOffsetEntry
        {
            public ulong InterfaceKlass;
            public string InterfaceName;
            public int VTableOffset;
        }

        public class TypeInterfaceInfo
        {
            public string TypeName;
            public ulong KlassPointer;
            public int InterfaceOffsetsCount;
            public List<InterfaceOffsetEntry> InterfaceOffsets = new List<InterfaceOffsetEntry>();
            public List<string> ImplementedInterfaces = new List<string>();
        }

        public class InterfaceDumpResult
        {
            public List<TypeInterfaceInfo> Types = new List<TypeInterfaceInfo>();
            public int TotalTypes;
            public int TotalInterfaces;
            public Dictionary<string, int> InterfaceImplementors = new Dictionary<string, int>();
        }

        // Il2CppClass offsets (x64)
        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;
        private const int kClass_ImplementedInterfaces = 0x88;
        private const int kClass_InterfaceOffsets = 0x90;
        private const int kClass_InterfacesCount = 0x108;
        private const int kClass_InterfaceOffsetsCount = 0x10A;
        private const int kClass_InstanceSize = 0xD8;

        // Il2CppRuntimeInterfaceOffsetPair: { Il2CppClass* interfaceType; int32 offset; }
        private const int kInterfaceOffsetPair_Size = 16; // 8 bytes ptr + 4 bytes offset + 4 pad

        public static InterfaceDumpResult DumpInterfaceOffsets(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot,
            string filter = null,
            int maxTypes = 3000)
        {
            var result = new InterfaceDumpResult();

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
                    if (result.Types.Count >= maxTypes) break;

                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;
                    if (seenKlass.Contains(candidate)) continue;
                    seenKlass.Add(candidate);

                    var typeInfo = TryReadInterfaceInfo(driver, pid, candidate, filter);
                    if (typeInfo == null) continue;

                    result.Types.Add(typeInfo);
                    result.TotalTypes++;
                    result.TotalInterfaces += typeInfo.InterfaceOffsets.Count;

                    foreach (var iface in typeInfo.InterfaceOffsets)
                    {
                        if (!result.InterfaceImplementors.ContainsKey(iface.InterfaceName))
                            result.InterfaceImplementors[iface.InterfaceName] = 0;
                        result.InterfaceImplementors[iface.InterfaceName]++;
                    }
                }
            }

            return result;
        }

        private static TypeInterfaceInfo TryReadInterfaceInfo(
            IMemoryReader driver, int pid, ulong klassAddr, string filter)
        {
            byte[] klassData = ReadMemory(driver, pid, klassAddr, 0x110);
            if (klassData == null) return null;

            // Validate name pointer
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

            ushort interfaceOffsetsCount = BitConverter.ToUInt16(klassData, kClass_InterfaceOffsetsCount);
            ushort interfacesCount = BitConverter.ToUInt16(klassData, kClass_InterfacesCount);

            if (interfaceOffsetsCount == 0 && interfacesCount == 0) return null;
            if (interfaceOffsetsCount > 500) return null;

            if (!string.IsNullOrEmpty(filter) &&
                fullName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                return null;

            var info = new TypeInterfaceInfo
            {
                TypeName = fullName,
                KlassPointer = klassAddr,
                InterfaceOffsetsCount = interfaceOffsetsCount
            };

            // Read interface offset pairs
            ulong offsetsPtr = BitConverter.ToUInt64(klassData, kClass_InterfaceOffsets);
            if (offsetsPtr != 0 && interfaceOffsetsCount > 0)
            {
                byte[] offsetData = ReadMemory(driver, pid, offsetsPtr, interfaceOffsetsCount * kInterfaceOffsetPair_Size);
                if (offsetData != null)
                {
                    for (int i = 0; i < interfaceOffsetsCount; i++)
                    {
                        int pairOff = i * kInterfaceOffsetPair_Size;
                        ulong ifaceKlass = BitConverter.ToUInt64(offsetData, pairOff);
                        int vtableOffset = BitConverter.ToInt32(offsetData, pairOff + 8);

                        string ifaceName = "?";
                        if (ifaceKlass != 0)
                        {
                            ulong ifaceNamePtr = ReadPtr(driver, pid, ifaceKlass + kClass_Name);
                            if (ifaceNamePtr != 0)
                            {
                                ifaceName = ReadCString(driver, pid, ifaceNamePtr, 128) ?? "?";
                                ulong ifaceNsPtr = ReadPtr(driver, pid, ifaceKlass + kClass_Namespace);
                                string ifaceNs = ifaceNsPtr != 0 ? ReadCString(driver, pid, ifaceNsPtr, 128) : "";
                                if (!string.IsNullOrEmpty(ifaceNs))
                                    ifaceName = $"{ifaceNs}.{ifaceName}";
                            }
                        }

                        info.InterfaceOffsets.Add(new InterfaceOffsetEntry
                        {
                            InterfaceKlass = ifaceKlass,
                            InterfaceName = ifaceName,
                            VTableOffset = vtableOffset
                        });
                    }
                }
            }

            return info;
        }

        public static string GenerateReport(InterfaceDumpResult result, string interfaceFilter = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Interface Offset Dump");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Types with interfaces: {result.TotalTypes}");
            sb.AppendLine($"// Total interface mappings: {result.TotalInterfaces}");
            sb.AppendLine($"// Unique interfaces: {result.InterfaceImplementors.Count}");
            sb.AppendLine();

            if (result.InterfaceImplementors.Count > 0)
            {
                sb.AppendLine("// Most implemented interfaces:");
                foreach (var kvp in result.InterfaceImplementors.OrderByDescending(k => k.Value).Take(20))
                    sb.AppendLine($"//   {kvp.Key}: {kvp.Value} implementors");
                sb.AppendLine();
            }

            var types = result.Types.AsEnumerable();
            if (!string.IsNullOrEmpty(interfaceFilter))
                types = types.Where(t => t.InterfaceOffsets.Any(io =>
                    io.InterfaceName.IndexOf(interfaceFilter, StringComparison.OrdinalIgnoreCase) >= 0));

            foreach (var type in types.OrderBy(t => t.TypeName))
            {
                sb.AppendLine($"{type.TypeName} (klass: 0x{type.KlassPointer:X})");
                foreach (var iface in type.InterfaceOffsets)
                {
                    sb.AppendLine($"  implements {iface.InterfaceName} -> vtable[{iface.VTableOffset}]");
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
