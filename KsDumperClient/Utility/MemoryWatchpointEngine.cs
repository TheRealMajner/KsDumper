using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class MemoryWatchpointEngine
    {
        public class WatchpointHit
        {
            public ulong WatchAddress;
            public ulong InstructionAddress;
            public string InstructionBytes;
            public string AccessType; // "read", "write", "execute"
            public ulong OldValue;
            public ulong NewValue;
            public DateTime Timestamp;
            public int ThreadId;
        }

        public class WatchpointResult
        {
            public ulong WatchAddress;
            public int Size;
            public string AccessType;
            public List<WatchpointHit> Hits = new List<WatchpointHit>();
            public int Duration;
            public int PollCount;
        }

        public class ValueChangeEntry
        {
            public ulong Address;
            public ulong OldValue;
            public ulong NewValue;
            public DateTime Timestamp;
            public TimeSpan TimeSinceStart;
        }

        public class ValueWatchResult
        {
            public ulong Address;
            public string ValueType;
            public int DurationMs;
            public int SampleCount;
            public List<ValueChangeEntry> Changes = new List<ValueChangeEntry>();
            public ulong InitialValue;
            public ulong FinalValue;
            public ulong MinValue;
            public ulong MaxValue;
        }

        public static ValueWatchResult WatchValue(
            IMemoryReader driver, int pid,
            ulong address, string valueType = "int32",
            int durationMs = 5000, int intervalMs = 50)
        {
            var result = new ValueWatchResult
            {
                Address = address,
                ValueType = valueType,
                DurationMs = durationMs
            };

            int valueSize = GetValueSize(valueType);
            ulong lastValue = ReadValue(driver, pid, address, valueSize);
            result.InitialValue = lastValue;
            result.MinValue = lastValue;
            result.MaxValue = lastValue;

            DateTime start = DateTime.Now;
            DateTime end = start.AddMilliseconds(durationMs);

            while (DateTime.Now < end)
            {
                Thread.Sleep(intervalMs);
                result.SampleCount++;

                ulong currentValue = ReadValue(driver, pid, address, valueSize);

                if (currentValue != lastValue)
                {
                    result.Changes.Add(new ValueChangeEntry
                    {
                        Address = address,
                        OldValue = lastValue,
                        NewValue = currentValue,
                        Timestamp = DateTime.Now,
                        TimeSinceStart = DateTime.Now - start
                    });

                    if (currentValue < result.MinValue) result.MinValue = currentValue;
                    if (currentValue > result.MaxValue) result.MaxValue = currentValue;

                    lastValue = currentValue;
                }

                if (result.Changes.Count >= 10000) break;
            }

            result.FinalValue = lastValue;

            return result;
        }

        public static ValueWatchResult WatchMultipleValues(
            IMemoryReader driver, int pid,
            ulong[] addresses, string valueType = "int32",
            int durationMs = 5000, int intervalMs = 100)
        {
            var result = new ValueWatchResult
            {
                ValueType = valueType,
                DurationMs = durationMs
            };

            int valueSize = GetValueSize(valueType);
            var lastValues = new Dictionary<ulong, ulong>();
            foreach (var addr in addresses)
                lastValues[addr] = ReadValue(driver, pid, addr, valueSize);

            if (addresses.Length > 0)
            {
                result.Address = addresses[0];
                result.InitialValue = lastValues[addresses[0]];
            }

            DateTime start = DateTime.Now;
            DateTime end = start.AddMilliseconds(durationMs);

            while (DateTime.Now < end)
            {
                Thread.Sleep(intervalMs);
                result.SampleCount++;

                foreach (var addr in addresses)
                {
                    ulong currentValue = ReadValue(driver, pid, addr, valueSize);
                    if (currentValue != lastValues[addr])
                    {
                        result.Changes.Add(new ValueChangeEntry
                        {
                            Address = addr,
                            OldValue = lastValues[addr],
                            NewValue = currentValue,
                            Timestamp = DateTime.Now,
                            TimeSinceStart = DateTime.Now - start
                        });

                        lastValues[addr] = currentValue;
                    }
                }

                if (result.Changes.Count >= 10000) break;
            }

            if (addresses.Length > 0)
                result.FinalValue = lastValues[addresses[0]];

            return result;
        }

        public static WatchpointResult SetHardwareWatchpoint(
            IMemoryReader driver, int pid,
            ulong address, int size = 4, string accessType = "write",
            int durationMs = 5000, int intervalMs = 20)
        {
            var result = new WatchpointResult
            {
                WatchAddress = address,
                Size = size,
                AccessType = accessType,
                Duration = durationMs
            };

            // Software watchpoint: poll the value and detect changes
            byte[] lastData = ReadMemory(driver, pid, address, size);
            if (lastData == null) return result;

            DateTime start = DateTime.Now;
            DateTime end = start.AddMilliseconds(durationMs);

            while (DateTime.Now < end)
            {
                Thread.Sleep(intervalMs);
                result.PollCount++;

                byte[] currentData = ReadMemory(driver, pid, address, size);
                if (currentData == null) continue;

                bool changed = false;
                for (int i = 0; i < size; i++)
                {
                    if (currentData[i] != lastData[i])
                    {
                        changed = true;
                        break;
                    }
                }

                if (changed)
                {
                    ulong oldVal = 0, newVal = 0;
                    if (size >= 8)
                    {
                        oldVal = BitConverter.ToUInt64(lastData, 0);
                        newVal = BitConverter.ToUInt64(currentData, 0);
                    }
                    else if (size >= 4)
                    {
                        oldVal = BitConverter.ToUInt32(lastData, 0);
                        newVal = BitConverter.ToUInt32(currentData, 0);
                    }
                    else if (size >= 2)
                    {
                        oldVal = BitConverter.ToUInt16(lastData, 0);
                        newVal = BitConverter.ToUInt16(currentData, 0);
                    }
                    else
                    {
                        oldVal = lastData[0];
                        newVal = currentData[0];
                    }

                    result.Hits.Add(new WatchpointHit
                    {
                        WatchAddress = address,
                        AccessType = "write",
                        OldValue = oldVal,
                        NewValue = newVal,
                        Timestamp = DateTime.Now,
                    });

                    Buffer.BlockCopy(currentData, 0, lastData, 0, size);
                }

                if (result.Hits.Count >= 5000) break;
            }

            return result;
        }

        public static string GenerateReport(ValueWatchResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Memory Value Watch");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Address: 0x{result.Address:X16}");
            sb.AppendLine($"// Type: {result.ValueType}");
            sb.AppendLine($"// Duration: {result.DurationMs}ms");
            sb.AppendLine($"// Samples: {result.SampleCount}");
            sb.AppendLine($"// Changes: {result.Changes.Count}");
            sb.AppendLine($"// Initial: {FormatValue(result.InitialValue, result.ValueType)}");
            sb.AppendLine($"// Final: {FormatValue(result.FinalValue, result.ValueType)}");
            sb.AppendLine($"// Min: {FormatValue(result.MinValue, result.ValueType)}");
            sb.AppendLine($"// Max: {FormatValue(result.MaxValue, result.ValueType)}");
            sb.AppendLine();

            foreach (var change in result.Changes.Take(500))
            {
                string addr = change.Address != result.Address ? $" 0x{change.Address:X}" : "";
                sb.AppendLine($"  [{change.TimeSinceStart.TotalMilliseconds:F0}ms]{addr} {FormatValue(change.OldValue, result.ValueType)} -> {FormatValue(change.NewValue, result.ValueType)}");
            }

            return sb.ToString();
        }

        public static string GenerateWatchpointReport(WatchpointResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Memory Watchpoint");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Watch: 0x{result.WatchAddress:X16} ({result.Size} bytes)");
            sb.AppendLine($"// Access type: {result.AccessType}");
            sb.AppendLine($"// Duration: {result.Duration}ms");
            sb.AppendLine($"// Poll count: {result.PollCount}");
            sb.AppendLine($"// Hits: {result.Hits.Count}");
            sb.AppendLine();

            foreach (var hit in result.Hits.Take(500))
            {
                sb.AppendLine($"  [{hit.Timestamp:HH:mm:ss.fff}] {hit.AccessType}: 0x{hit.OldValue:X} -> 0x{hit.NewValue:X}");
            }

            return sb.ToString();
        }

        private static string FormatValue(ulong value, string valueType)
        {
            switch ((valueType ?? "").ToLowerInvariant())
            {
                case "float":
                    return BitConverter.ToSingle(BitConverter.GetBytes((uint)value), 0).ToString("G6");
                case "double":
                    return BitConverter.ToDouble(BitConverter.GetBytes(value), 0).ToString("G6");
                default:
                    return $"{(long)value} (0x{value:X})";
            }
        }

        private static int GetValueSize(string valueType)
        {
            switch ((valueType ?? "").ToLowerInvariant())
            {
                case "byte": return 1;
                case "int16": case "short": return 2;
                case "int32": case "int": case "float": return 4;
                case "int64": case "long": case "double": return 8;
                default: return 4;
            }
        }

        private static ulong ReadValue(IMemoryReader driver, int pid, ulong address, int size)
        {
            byte[] buf = ReadMemory(driver, pid, address, size);
            if (buf == null) return 0;

            switch (size)
            {
                case 1: return buf[0];
                case 2: return BitConverter.ToUInt16(buf, 0);
                case 4: return BitConverter.ToUInt32(buf, 0);
                case 8: return BitConverter.ToUInt64(buf, 0);
                default: return 0;
            }
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
