using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class MemorySnapshotDiff
    {
        public class MemorySnapshot
        {
            public int Pid;
            public DateTime Timestamp;
            public List<SnapshotRegion> Regions = new List<SnapshotRegion>();
            public long TotalBytes;
        }

        public class SnapshotRegion
        {
            public ulong BaseAddress;
            public int Size;
            public byte[] Data;
        }

        public class DiffResult
        {
            public DateTime SnapshotA;
            public DateTime SnapshotB;
            public int TotalRegionsCompared;
            public long TotalBytesCompared;
            public List<ChangedRegion> Changes = new List<ChangedRegion>();
            public int TotalChangedBytes;
        }

        public class ChangedRegion
        {
            public ulong Address;
            public int Offset;
            public byte OldValue;
            public byte NewValue;
        }

        public class ValueScanResult
        {
            public List<ulong> Addresses = new List<ulong>();
            public string ValueType;
            public string SearchValue;
        }

        public static MemorySnapshot TakeSnapshot(
            IMemoryReader driver, int pid,
            ulong startAddress = 0, ulong endAddress = 0,
            int maxRegionSize = 0x1000000)
        {
            var snapshot = new MemorySnapshot
            {
                Pid = pid,
                Timestamp = DateTime.Now
            };

            var regions = driver.EnumRegions(pid);
            if (regions == null) return snapshot;

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (state != 0x1000) continue; // MEM_COMMIT
                if ((protect & 0x04) == 0 && (protect & 0x08) == 0 &&
                    (protect & 0x02) == 0 && (protect & 0x40) == 0) continue;
                if (regionSize < 4 || regionSize > (ulong)maxRegionSize) continue;

                if (startAddress != 0 && baseAddr < startAddress) continue;
                if (endAddress != 0 && baseAddr >= endAddress) continue;

                int readSize = (int)Math.Min(regionSize, (ulong)maxRegionSize);
                byte[] data = ReadMemory(driver, pid, baseAddr, readSize);
                if (data == null) continue;

                snapshot.Regions.Add(new SnapshotRegion
                {
                    BaseAddress = baseAddr,
                    Size = readSize,
                    Data = data
                });
                snapshot.TotalBytes += readSize;
            }

            return snapshot;
        }

        public static MemorySnapshot TakeSnapshotOfModule(
            IMemoryReader driver, int pid, ulong moduleBase, uint moduleSize)
        {
            return TakeSnapshot(driver, pid, moduleBase, moduleBase + moduleSize);
        }

        public static DiffResult CompareSnapshots(MemorySnapshot a, MemorySnapshot b, int maxChanges = 10000)
        {
            var result = new DiffResult
            {
                SnapshotA = a.Timestamp,
                SnapshotB = b.Timestamp
            };

            var bRegions = new Dictionary<ulong, SnapshotRegion>();
            foreach (var r in b.Regions)
                bRegions[r.BaseAddress] = r;

            foreach (var regionA in a.Regions)
            {
                if (!bRegions.TryGetValue(regionA.BaseAddress, out var regionB)) continue;

                result.TotalRegionsCompared++;
                int compareLen = Math.Min(regionA.Size, regionB.Size);
                result.TotalBytesCompared += compareLen;

                for (int i = 0; i < compareLen; i++)
                {
                    if (result.Changes.Count >= maxChanges) break;

                    if (regionA.Data[i] != regionB.Data[i])
                    {
                        result.Changes.Add(new ChangedRegion
                        {
                            Address = regionA.BaseAddress + (ulong)i,
                            Offset = i,
                            OldValue = regionA.Data[i],
                            NewValue = regionB.Data[i]
                        });
                        result.TotalChangedBytes++;
                    }
                }
            }

            return result;
        }

        public static DiffResult CompareForValue(
            MemorySnapshot a, MemorySnapshot b,
            string compareType, int maxResults = 5000)
        {
            var result = new DiffResult
            {
                SnapshotA = a.Timestamp,
                SnapshotB = b.Timestamp
            };

            var bRegions = new Dictionary<ulong, SnapshotRegion>();
            foreach (var r in b.Regions)
                bRegions[r.BaseAddress] = r;

            foreach (var regionA in a.Regions)
            {
                if (!bRegions.TryGetValue(regionA.BaseAddress, out var regionB)) continue;

                result.TotalRegionsCompared++;
                int compareLen = Math.Min(regionA.Size, regionB.Size);
                result.TotalBytesCompared += compareLen;

                for (int i = 0; i <= compareLen - 4; i += 4)
                {
                    if (result.Changes.Count >= maxResults) break;

                    int valA = BitConverter.ToInt32(regionA.Data, i);
                    int valB = BitConverter.ToInt32(regionB.Data, i);

                    bool match = false;
                    switch (compareType.ToLowerInvariant())
                    {
                        case "increased": match = valB > valA && valA != 0; break;
                        case "decreased": match = valB < valA && valA != 0; break;
                        case "changed": match = valB != valA; break;
                        case "unchanged": match = valB == valA && valA != 0; break;
                    }

                    if (match)
                    {
                        result.Changes.Add(new ChangedRegion
                        {
                            Address = regionA.BaseAddress + (ulong)i,
                            Offset = i,
                            OldValue = (byte)(valA & 0xFF),
                            NewValue = (byte)(valB & 0xFF)
                        });
                    }
                }
            }

            return result;
        }

        public static ValueScanResult ScanForValue(
            MemorySnapshot snapshot, string valueType, string value, int maxResults = 5000)
        {
            var result = new ValueScanResult { ValueType = valueType, SearchValue = value };

            foreach (var region in snapshot.Regions)
            {
                if (result.Addresses.Count >= maxResults) break;

                switch (valueType.ToLowerInvariant())
                {
                    case "int32":
                        if (!int.TryParse(value, out int i32)) break;
                        for (int i = 0; i <= region.Size - 4; i += 4)
                        {
                            if (result.Addresses.Count >= maxResults) break;
                            if (BitConverter.ToInt32(region.Data, i) == i32)
                                result.Addresses.Add(region.BaseAddress + (ulong)i);
                        }
                        break;

                    case "float":
                        if (!float.TryParse(value, System.Globalization.NumberStyles.Float,
                            System.Globalization.CultureInfo.InvariantCulture, out float f32)) break;
                        for (int i = 0; i <= region.Size - 4; i += 4)
                        {
                            if (result.Addresses.Count >= maxResults) break;
                            float v = BitConverter.ToSingle(region.Data, i);
                            if (Math.Abs(v - f32) < 0.001f)
                                result.Addresses.Add(region.BaseAddress + (ulong)i);
                        }
                        break;

                    case "int64":
                        if (!long.TryParse(value, out long i64)) break;
                        for (int i = 0; i <= region.Size - 8; i += 4)
                        {
                            if (result.Addresses.Count >= maxResults) break;
                            if (BitConverter.ToInt64(region.Data, i) == i64)
                                result.Addresses.Add(region.BaseAddress + (ulong)i);
                        }
                        break;

                    case "double":
                        if (!double.TryParse(value, System.Globalization.NumberStyles.Float,
                            System.Globalization.CultureInfo.InvariantCulture, out double d64)) break;
                        for (int i = 0; i <= region.Size - 8; i += 4)
                        {
                            if (result.Addresses.Count >= maxResults) break;
                            double v = BitConverter.ToDouble(region.Data, i);
                            if (Math.Abs(v - d64) < 0.0001)
                                result.Addresses.Add(region.BaseAddress + (ulong)i);
                        }
                        break;
                }
            }

            return result;
        }

        public static string GenerateDiffReport(DiffResult diff)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Memory Snapshot Diff");
            sb.AppendLine($"// Snapshot A: {diff.SnapshotA:yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"// Snapshot B: {diff.SnapshotB:yyyy-MM-dd HH:mm:ss.fff}");
            sb.AppendLine($"// Regions compared: {diff.TotalRegionsCompared}");
            sb.AppendLine($"// Bytes compared: {diff.TotalBytesCompared:N0}");
            sb.AppendLine($"// Changed bytes: {diff.TotalChangedBytes}");
            sb.AppendLine($"// Change entries: {diff.Changes.Count}");
            sb.AppendLine();

            // Group consecutive changes
            var grouped = GroupConsecutiveChanges(diff.Changes);
            foreach (var group in grouped.Take(500))
            {
                if (group.Count == 1)
                {
                    var c = group[0];
                    sb.AppendLine($"  0x{c.Address:X16}: 0x{c.OldValue:X2} -> 0x{c.NewValue:X2}");
                }
                else
                {
                    sb.AppendLine($"  0x{group[0].Address:X16} - 0x{group[group.Count - 1].Address:X16} ({group.Count} bytes changed)");
                }
            }

            return sb.ToString();
        }

        public static string GenerateValueScanReport(ValueScanResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Memory Value Scan");
            sb.AppendLine($"// Type: {result.ValueType}");
            sb.AppendLine($"// Value: {result.SearchValue}");
            sb.AppendLine($"// Matches: {result.Addresses.Count}");
            sb.AppendLine();

            foreach (var addr in result.Addresses.Take(1000))
                sb.AppendLine($"  0x{addr:X16}");

            return sb.ToString();
        }

        private static List<List<ChangedRegion>> GroupConsecutiveChanges(List<ChangedRegion> changes)
        {
            var groups = new List<List<ChangedRegion>>();
            if (changes.Count == 0) return groups;

            var current = new List<ChangedRegion> { changes[0] };
            for (int i = 1; i < changes.Count; i++)
            {
                if (changes[i].Address == changes[i - 1].Address + 1)
                {
                    current.Add(changes[i]);
                }
                else
                {
                    groups.Add(current);
                    current = new List<ChangedRegion> { changes[i] };
                }
            }
            groups.Add(current);
            return groups;
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
