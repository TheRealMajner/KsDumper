using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppVtableHookDetector
    {
        public class VtableEntry
        {
            public int SlotIndex;
            public ulong MethodPointer;
            public string MethodName;
            public bool IsHooked;
            public string HookTarget;
            public string HookModule;
        }

        public class HookedClass
        {
            public string ClassName;
            public ulong KlassPointer;
            public int VtableSize;
            public List<VtableEntry> Entries = new List<VtableEntry>();
            public int HookedCount;
        }

        public class HookDetectionResult
        {
            public List<HookedClass> Classes = new List<HookedClass>();
            public int TotalClassesScanned;
            public int TotalVtableEntries;
            public int TotalHooksDetected;
            public List<string> SuspiciousModules = new List<string>();
        }

        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;
        private const int kClass_VTable = 0x110;
        private const int kClass_VTableCount = 0x106;

        public static HookDetectionResult DetectHooks(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            string filter = null,
            int maxClasses = 2000)
        {
            var result = new HookDetectionResult();

            if (!driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                return result;

            var moduleRanges = new List<(string name, ulong start, ulong end)>();
            foreach (var mod in modules)
                moduleRanges.Add((mod.ModuleName, mod.BaseAddress, mod.BaseAddress + mod.ImageSize));

            ulong gaEnd = gaBase + gaSize;

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

                    var hookedClass = CheckClassVtable(driver, pid, candidate, gaBase, gaEnd, moduleRanges, filter);
                    if (hookedClass == null) continue;

                    result.TotalClassesScanned++;
                    result.TotalVtableEntries += hookedClass.Entries.Count;

                    if (hookedClass.HookedCount > 0)
                    {
                        result.Classes.Add(hookedClass);
                        result.TotalHooksDetected += hookedClass.HookedCount;

                        foreach (var entry in hookedClass.Entries.Where(e => e.IsHooked))
                        {
                            if (!string.IsNullOrEmpty(entry.HookModule) &&
                                !result.SuspiciousModules.Contains(entry.HookModule))
                                result.SuspiciousModules.Add(entry.HookModule);
                        }
                    }
                }
            }

            return result;
        }

        private static HookedClass CheckClassVtable(
            IMemoryReader driver, int pid, ulong klassAddr,
            ulong gaBase, ulong gaEnd,
            List<(string name, ulong start, ulong end)> moduleRanges,
            string filter)
        {
            byte[] klassData = ReadMemory(driver, pid, klassAddr, 0x120);
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

            if (!string.IsNullOrEmpty(filter) &&
                fullName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                return null;

            ushort vtableCount = BitConverter.ToUInt16(klassData, kClass_VTableCount);
            if (vtableCount == 0 || vtableCount > 1000) return null;

            // VTable is inline at the end of Il2CppClass struct (variable size)
            // vtable entries start at kClass_VTable, each is a pointer (Il2CppMethodInfo*)
            byte[] vtableData = ReadMemory(driver, pid, klassAddr + kClass_VTable, vtableCount * 8);
            if (vtableData == null) return null;

            var hookedClass = new HookedClass
            {
                ClassName = fullName,
                KlassPointer = klassAddr,
                VtableSize = vtableCount
            };

            for (int slot = 0; slot < vtableCount; slot++)
            {
                ulong methodInfoPtr = BitConverter.ToUInt64(vtableData, slot * 8);
                if (methodInfoPtr == 0) continue;

                // Read MethodInfo->methodPointer (first field, offset 0)
                byte[] miData = ReadMemory(driver, pid, methodInfoPtr, 0x30);
                if (miData == null) continue;

                ulong methodPtr = BitConverter.ToUInt64(miData, 0);
                if (methodPtr == 0) continue;

                // Read method name from MethodInfo->name (offset 0x10)
                ulong methodNamePtr = BitConverter.ToUInt64(miData, 0x10);
                string methodName = methodNamePtr != 0 ? ReadCString(driver, pid, methodNamePtr, 128) : $"slot_{slot}";

                var entry = new VtableEntry
                {
                    SlotIndex = slot,
                    MethodPointer = methodPtr,
                    MethodName = methodName ?? $"slot_{slot}"
                };

                // Check if method pointer is inside GameAssembly.dll
                if (methodPtr < gaBase || methodPtr >= gaEnd)
                {
                    entry.IsHooked = true;
                    hookedClass.HookedCount++;

                    // Find which module it points to
                    foreach (var (modName, modStart, modEnd) in moduleRanges)
                    {
                        if (methodPtr >= modStart && methodPtr < modEnd)
                        {
                            entry.HookModule = modName;
                            entry.HookTarget = $"{modName}+0x{methodPtr - modStart:X}";
                            break;
                        }
                    }

                    if (string.IsNullOrEmpty(entry.HookTarget))
                        entry.HookTarget = $"0x{methodPtr:X16} (unknown module)";
                }

                hookedClass.Entries.Add(entry);
            }

            if (hookedClass.HookedCount == 0 && !string.IsNullOrEmpty(filter))
                return hookedClass;

            return hookedClass.HookedCount > 0 || !string.IsNullOrEmpty(filter) ? hookedClass : null;
        }

        public static string GenerateReport(HookDetectionResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP VTable Hook Detector");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Classes scanned: {result.TotalClassesScanned}");
            sb.AppendLine($"// VTable entries checked: {result.TotalVtableEntries}");
            sb.AppendLine($"// Hooks detected: {result.TotalHooksDetected}");
            sb.AppendLine();

            if (result.SuspiciousModules.Count > 0)
            {
                sb.AppendLine("// Suspicious modules (hook targets):");
                foreach (var mod in result.SuspiciousModules)
                    sb.AppendLine($"//   {mod}");
                sb.AppendLine();
            }

            foreach (var cls in result.Classes.OrderByDescending(c => c.HookedCount))
            {
                sb.AppendLine($"{cls.ClassName} (klass: 0x{cls.KlassPointer:X}, vtable: {cls.VtableSize} slots, hooked: {cls.HookedCount})");

                foreach (var entry in cls.Entries.Where(e => e.IsHooked))
                {
                    sb.AppendLine($"  [HOOKED] slot[{entry.SlotIndex}] {entry.MethodName} -> {entry.HookTarget}");
                }

                sb.AppendLine();
            }

            if (result.TotalHooksDetected == 0)
                sb.AppendLine("No vtable hooks detected.");

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
