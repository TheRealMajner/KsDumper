using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class PointerScanEngine
    {
        public class PointerChain
        {
            public ulong BaseAddress;
            public string BaseModule;
            public ulong BaseOffset;
            public List<long> Offsets = new List<long>();
            public ulong FinalAddress;
            public int Depth;
        }

        public class PointerScanResult
        {
            public ulong TargetAddress;
            public List<PointerChain> Chains = new List<PointerChain>();
            public int TotalPointersScanned;
            public int RegionsScanned;
            public long BytesScanned;
        }

        public static PointerScanResult Scan(
            IMemoryReader driver, int pid,
            ulong targetAddress,
            int maxDepth = 4,
            int maxOffset = 0x1000,
            int maxResults = 200)
        {
            var result = new PointerScanResult { TargetAddress = targetAddress };

            // Get module list for base address identification
            if (!driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                return result;
            if (modules == null || modules.Length == 0) return result;

            var moduleMap = new Dictionary<string, (ulong baseAddr, uint size)>();
            foreach (var mod in modules)
                moduleMap[mod.ModuleName] = (mod.BaseAddress, mod.ImageSize);

            // Build pointer map: scan all readable regions for pointers
            var pointerMap = new Dictionary<ulong, List<ulong>>(); // target -> list of addresses that point to it
            var regions = driver.EnumRegions(pid);
            if (regions == null) return result;

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (state != 0x1000) continue;
                if ((protect & 0x02) == 0 && (protect & 0x04) == 0 &&
                    (protect & 0x08) == 0 && (protect & 0x40) == 0) continue;
                if (regionSize < 8 || regionSize > 0x4000000) continue;

                int readSize = (int)Math.Min(regionSize, 0x2000000);
                byte[] data = ReadMemory(driver, pid, baseAddr, readSize);
                if (data == null) continue;

                result.RegionsScanned++;
                result.BytesScanned += readSize;

                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    ulong ptrVal = BitConverter.ToUInt64(data, i);
                    if (ptrVal < 0x10000 || ptrVal > 0x7FFFFFFFFFFF) continue;

                    ulong srcAddr = baseAddr + (ulong)i;
                    if (!pointerMap.ContainsKey(ptrVal))
                        pointerMap[ptrVal] = new List<ulong>();

                    if (pointerMap[ptrVal].Count < 100)
                        pointerMap[ptrVal].Add(srcAddr);

                    result.TotalPointersScanned++;
                }
            }

            // BFS from target address backwards through pointer map
            var queue = new Queue<(ulong addr, List<long> offsets, int depth)>();

            // Level 0: find pointers to targetAddress +/- maxOffset
            for (long off = 0; off < maxOffset; off += 8)
            {
                ulong candidate = targetAddress - (ulong)off;
                if (pointerMap.ContainsKey(candidate))
                {
                    foreach (var src in pointerMap[candidate])
                    {
                        var offsets = new List<long> { off };
                        var chain = TryResolveToModule(src, offsets, moduleMap);
                        if (chain != null && result.Chains.Count < maxResults)
                        {
                            chain.FinalAddress = targetAddress;
                            result.Chains.Add(chain);
                        }
                        else if (offsets.Count < maxDepth)
                        {
                            queue.Enqueue((src, offsets, 1));
                        }
                    }
                }
            }

            // BFS deeper levels
            while (queue.Count > 0 && result.Chains.Count < maxResults)
            {
                var (addr, currentOffsets, depth) = queue.Dequeue();
                if (depth >= maxDepth) continue;

                for (long off = 0; off < maxOffset; off += 8)
                {
                    ulong candidate = addr - (ulong)off;
                    if (!pointerMap.ContainsKey(candidate)) continue;

                    foreach (var src in pointerMap[candidate])
                    {
                        if (result.Chains.Count >= maxResults) break;

                        var newOffsets = new List<long>(currentOffsets) { off };
                        var chain = TryResolveToModule(src, newOffsets, moduleMap);
                        if (chain != null)
                        {
                            chain.FinalAddress = targetAddress;
                            result.Chains.Add(chain);
                        }
                        else if (depth + 1 < maxDepth && queue.Count < 50000)
                        {
                            queue.Enqueue((src, newOffsets, depth + 1));
                        }
                    }
                }
            }

            // Sort by depth (shorter chains first), then by base module
            result.Chains = result.Chains.OrderBy(c => c.Depth).ThenBy(c => c.BaseModule).ToList();

            return result;
        }

        private static PointerChain TryResolveToModule(
            ulong address, List<long> offsets,
            Dictionary<string, (ulong baseAddr, uint size)> moduleMap)
        {
            foreach (var kvp in moduleMap)
            {
                if (address >= kvp.Value.baseAddr && address < kvp.Value.baseAddr + kvp.Value.size)
                {
                    return new PointerChain
                    {
                        BaseAddress = kvp.Value.baseAddr,
                        BaseModule = kvp.Key,
                        BaseOffset = address - kvp.Value.baseAddr,
                        Offsets = new List<long>(offsets),
                        Depth = offsets.Count
                    };
                }
            }
            return null;
        }

        public static string GenerateReport(PointerScanResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Pointer Scan Engine");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Target: 0x{result.TargetAddress:X16}");
            sb.AppendLine($"// Chains found: {result.Chains.Count}");
            sb.AppendLine($"// Pointers scanned: {result.TotalPointersScanned:N0}");
            sb.AppendLine($"// Regions: {result.RegionsScanned}");
            sb.AppendLine($"// Bytes: {result.BytesScanned:N0}");
            sb.AppendLine();

            foreach (var chain in result.Chains.Take(100))
            {
                var sb2 = new StringBuilder();
                sb2.Append($"  [{chain.BaseModule}+0x{chain.BaseOffset:X}]");
                foreach (var off in chain.Offsets)
                {
                    if (off >= 0)
                        sb2.Append($" +0x{off:X}");
                    else
                        sb2.Append($" -0x{-off:X}");
                }
                sb2.Append($"  (depth: {chain.Depth})");
                sb.AppendLine(sb2.ToString());
            }

            // Generate CE pointer notation
            if (result.Chains.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("// Cheat Engine pointer notation (first 10):");
                foreach (var chain in result.Chains.Take(10))
                {
                    var offsets = new List<long>(chain.Offsets);
                    offsets.Reverse();
                    string ceNotation = $"\"{chain.BaseModule}\"+{chain.BaseOffset:X}";
                    foreach (var off in offsets)
                        ceNotation = $"[{ceNotation}]+{off:X}";
                    sb.AppendLine($"  {ceNotation}");
                }
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
    }
}
