using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class Il2CppDelegateResolver
    {
        public class DelegateInfo
        {
            public ulong Address;
            public ulong KlassPointer;
            public string DelegateTypeName;
            public ulong TargetObject;
            public ulong MethodPointer;
            public string TargetMethodName;
            public ulong ExtraArg;
            public ulong InvocationList;
            public int InvocationCount;
            public List<DelegateInfo> MulticastEntries = new List<DelegateInfo>();
        }

        public class DelegateResolveResult
        {
            public List<DelegateInfo> Delegates = new List<DelegateInfo>();
            public int TotalFound;
            public int MulticastCount;
            public int ResolvedMethodCount;
        }

        // Il2CppDelegate layout (inherits Il2CppObject)
        // +0x00: Il2CppClass* klass
        // +0x08: MonitorData* monitor
        // +0x10: Il2CppObject* target
        // +0x18: Il2CppMethodPointer method_ptr
        // +0x20: IntPtr invoke_impl
        // +0x28: Il2CppObject* m_target
        // +0x30: IntPtr method
        // +0x38: IntPtr delegate_trampoline
        // +0x40: intptr_t extraArg
        // Multicast:
        // +0x48: Il2CppObject* delegates (array)
        // +0x50: int delegates_count

        private const int kDelegate_Target = 0x10;
        private const int kDelegate_MethodPtr = 0x18;
        private const int kDelegate_InvokeImpl = 0x20;
        private const int kDelegate_MTarget = 0x28;
        private const int kDelegate_Method = 0x30;
        private const int kDelegate_Trampoline = 0x38;
        private const int kDelegate_ExtraArg = 0x40;
        private const int kDelegate_InvocationList = 0x48;
        private const int kDelegate_InvocationCount = 0x50;

        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;
        private const int kClass_Parent = 0x38;
        private const int kClass_InstanceSize = 0xD8;

        public static DelegateResolveResult ScanDelegates(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot,
            string filter = null,
            int maxDelegates = 1000)
        {
            var result = new DelegateResolveResult();

            // Build method address -> name map for resolution
            var methodMap = BuildMethodAddressMap(driver, pid, gaBase, gaSize, snapshot);

            // Find all Il2CppClass pointers that represent delegate types
            // (classes whose parent chain includes System.Delegate or System.MulticastDelegate)
            var delegateKlasses = FindDelegateClasses(driver, pid, gaBase, gaSize);

            if (delegateKlasses.Count == 0) return result;

            // Scan heap for delegate instances
            var regions = driver.EnumRegions(pid);
            if (regions == null) return result;

            var seen = new HashSet<ulong>();

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (result.Delegates.Count >= maxDelegates) break;
                if (state != 0x1000) continue; // MEM_COMMIT
                if ((protect & 0x04) == 0 && (protect & 0x08) == 0) continue;
                if (regionSize < 0x58 || regionSize > 0x10000000) continue;

                int readSize = (int)Math.Min(regionSize, 0x1000000);
                byte[] data = ReadMemory(driver, pid, baseAddr, readSize);
                if (data == null) continue;

                for (int i = 0; i <= data.Length - 0x58; i += 8)
                {
                    if (result.Delegates.Count >= maxDelegates) break;

                    ulong klassPtr = BitConverter.ToUInt64(data, i);
                    if (!delegateKlasses.ContainsKey(klassPtr)) continue;

                    ulong objAddr = baseAddr + (ulong)i;
                    if (seen.Contains(objAddr)) continue;
                    seen.Add(objAddr);

                    ulong methodPtr = BitConverter.ToUInt64(data, i + kDelegate_MethodPtr);
                    if (methodPtr == 0) continue;

                    // Validate method pointer is in code range
                    if (methodPtr < gaBase || methodPtr >= gaBase + gaSize) continue;

                    var del = new DelegateInfo
                    {
                        Address = objAddr,
                        KlassPointer = klassPtr,
                        DelegateTypeName = delegateKlasses[klassPtr],
                        TargetObject = BitConverter.ToUInt64(data, i + kDelegate_Target),
                        MethodPointer = methodPtr,
                        ExtraArg = BitConverter.ToUInt64(data, i + kDelegate_ExtraArg)
                    };

                    // Resolve method name
                    if (methodMap.TryGetValue(methodPtr, out string methodName))
                    {
                        del.TargetMethodName = methodName;
                        result.ResolvedMethodCount++;
                    }
                    else
                    {
                        del.TargetMethodName = $"sub_{methodPtr:X}";
                    }

                    // Check for multicast delegate
                    ulong invocationList = BitConverter.ToUInt64(data, i + kDelegate_InvocationList);
                    if (invocationList != 0 && invocationList > 0x10000 && invocationList < 0x7FFFFFFFFFFF)
                    {
                        del.InvocationList = invocationList;
                        del.InvocationCount = BitConverter.ToInt32(data, i + kDelegate_InvocationCount);

                        if (del.InvocationCount > 1 && del.InvocationCount < 100)
                        {
                            result.MulticastCount++;
                            ReadMulticastEntries(driver, pid, del, delegateKlasses, methodMap, gaBase, gaSize);
                        }
                    }

                    if (!string.IsNullOrEmpty(filter))
                    {
                        bool matches = (del.DelegateTypeName != null && del.DelegateTypeName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0) ||
                                       (del.TargetMethodName != null && del.TargetMethodName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) >= 0);
                        if (!matches) continue;
                    }

                    result.Delegates.Add(del);
                    result.TotalFound++;
                }
            }

            return result;
        }

        private static void ReadMulticastEntries(
            IMemoryReader driver, int pid,
            DelegateInfo parent,
            Dictionary<ulong, string> delegateKlasses,
            Dictionary<ulong, string> methodMap,
            ulong gaBase, ulong gaSize)
        {
            // Invocation list is an Il2CppArray of delegate objects
            // Il2CppArray: klass(8) + monitor(8) + bounds(8) + max_length(8) + elements...
            byte[] arrHeader = ReadMemory(driver, pid, parent.InvocationList, 0x20);
            if (arrHeader == null) return;

            int length = BitConverter.ToInt32(arrHeader, 0x18);
            if (length <= 0 || length > 100) return;

            byte[] elements = ReadMemory(driver, pid, parent.InvocationList + 0x20, length * 8);
            if (elements == null) return;

            for (int i = 0; i < length; i++)
            {
                ulong elementPtr = BitConverter.ToUInt64(elements, i * 8);
                if (elementPtr == 0) continue;

                byte[] delData = ReadMemory(driver, pid, elementPtr, 0x58);
                if (delData == null) continue;

                ulong methodPtr = BitConverter.ToUInt64(delData, kDelegate_MethodPtr);
                if (methodPtr == 0 || methodPtr < gaBase || methodPtr >= gaBase + gaSize) continue;

                ulong klassPtr = BitConverter.ToUInt64(delData, 0);
                var entry = new DelegateInfo
                {
                    Address = elementPtr,
                    KlassPointer = klassPtr,
                    DelegateTypeName = delegateKlasses.ContainsKey(klassPtr) ? delegateKlasses[klassPtr] : "?",
                    MethodPointer = methodPtr,
                    TargetObject = BitConverter.ToUInt64(delData, kDelegate_Target)
                };

                if (methodMap.TryGetValue(methodPtr, out string name))
                    entry.TargetMethodName = name;
                else
                    entry.TargetMethodName = $"sub_{methodPtr:X}";

                parent.MulticastEntries.Add(entry);
            }
        }

        private static Dictionary<ulong, string> FindDelegateClasses(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize)
        {
            var result = new Dictionary<ulong, string>();
            var visited = new HashSet<ulong>();

            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return result;

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
                    if (result.Count > 5000) break;

                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;
                    if (visited.Contains(candidate)) continue;
                    visited.Add(candidate);

                    // Check if this is a delegate class by walking parent chain
                    if (IsDelegateClass(driver, pid, candidate))
                    {
                        ulong namePtr = ReadPtr(driver, pid, candidate + kClass_Name);
                        string name = namePtr != 0 ? ReadCString(driver, pid, namePtr, 128) : null;
                        if (name != null && name != "Delegate" && name != "MulticastDelegate")
                        {
                            ulong nsPtr = ReadPtr(driver, pid, candidate + kClass_Namespace);
                            string ns = nsPtr != 0 ? ReadCString(driver, pid, nsPtr, 128) : "";
                            string fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
                            result[candidate] = fullName;
                        }
                    }
                }
            }

            return result;
        }

        private static bool IsDelegateClass(IMemoryReader driver, int pid, ulong klassAddr)
        {
            int depth = 0;
            ulong current = klassAddr;

            while (current != 0 && depth < 10)
            {
                ulong namePtr = ReadPtr(driver, pid, current + kClass_Name);
                if (namePtr == 0) return false;

                string name = ReadCString(driver, pid, namePtr, 32);
                if (name == null) return false;

                if (name == "MulticastDelegate" || name == "Delegate")
                    return true;

                ulong parent = ReadPtr(driver, pid, current + kClass_Parent);
                if (parent == current || parent == 0) return false;

                current = parent;
                depth++;
            }

            return false;
        }

        private static Dictionary<ulong, string> BuildMethodAddressMap(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot)
        {
            var map = new Dictionary<ulong, string>();

            // Use export map as primary source of address->name mappings
            var exports = driver.GetExportMap(pid);
            if (exports != null)
            {
                foreach (var kvp in exports)
                {
                    ulong addr = kvp.Key;
                    if (addr >= gaBase && addr < gaBase + gaSize && !map.ContainsKey(addr))
                        map[addr] = $"{kvp.Value.dllName}!{kvp.Value.funcName}";
                }
            }

            return map;
        }

        public static string GenerateReport(DelegateResolveResult result, string search = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - IL2CPP Delegate/Event Resolver");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Delegates found: {result.TotalFound}");
            sb.AppendLine($"// Multicast delegates: {result.MulticastCount}");
            sb.AppendLine($"// Methods resolved: {result.ResolvedMethodCount}");
            sb.AppendLine();

            var delegates = result.Delegates.AsEnumerable();
            if (!string.IsNullOrEmpty(search))
            {
                delegates = delegates.Where(d =>
                    (d.DelegateTypeName != null && d.DelegateTypeName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (d.TargetMethodName != null && d.TargetMethodName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0));
            }

            foreach (var del in delegates)
            {
                sb.AppendLine($"  {del.DelegateTypeName} @ 0x{del.Address:X}");
                sb.AppendLine($"    method_ptr: 0x{del.MethodPointer:X} -> {del.TargetMethodName}");

                if (del.TargetObject != 0)
                    sb.AppendLine($"    target: 0x{del.TargetObject:X}");

                if (del.MulticastEntries.Count > 0)
                {
                    sb.AppendLine($"    multicast ({del.InvocationCount} handlers):");
                    foreach (var entry in del.MulticastEntries)
                    {
                        sb.AppendLine($"      [{entry.TargetMethodName}] @ 0x{entry.MethodPointer:X}");
                    }
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
