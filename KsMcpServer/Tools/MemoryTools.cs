using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using ModelContextProtocol.Server;
using KsDumperClient;
using KsDumperClient.Driver;

namespace KsMcpServer.Tools
{
    [McpServerToolType]
    public class MemoryTools
    {
        private readonly IMemoryReader _driver;

        public MemoryTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Reads memory from a process at the specified address and returns hex dump + ASCII interpretation. Address should be hex string like '0x7FF6A0000000'.")]
        public string ReadMemory(int pid, string address, int size = 256)
        {
            ulong addr = ParseAddress(address);
            if (addr == 0) return "Invalid address format. Use hex like '0x7FF6A0000000'.";

            if (size > 65536) size = 65536; // Cap at 64KB

            byte[] buffer = new byte[size];
            IntPtr bufPtr = Marshal.AllocHGlobal(size);
            try
            {
                if (!_driver.CopyVirtualMemory(pid, (IntPtr)addr, bufPtr, size))
                    return $"Failed to read {size} bytes at 0x{addr:X16} from PID {pid}.";

                Marshal.Copy(bufPtr, buffer, 0, size);
                return FormatHexDump(buffer, addr);
            }
            finally
            {
                Marshal.FreeHGlobal(bufPtr);
            }
        }

        [McpServerTool, Description("Reads a 64-bit pointer chain from process memory. Provide base address and list of offsets. Returns the final resolved address.")]
        public string ReadPointerChain(int pid, string baseAddress, int[] offsets)
        {
            ulong addr = ParseAddress(baseAddress);
            if (addr == 0) return "Invalid base address.";

            byte[] buf = new byte[8];
            IntPtr bufPtr = Marshal.AllocHGlobal(8);
            try
            {
                // Read base pointer
                if (!_driver.CopyVirtualMemory(pid, (IntPtr)addr, bufPtr, 8))
                    return $"Failed to read base pointer at 0x{addr:X16}.";

                Marshal.Copy(bufPtr, buf, 0, 8);
                ulong current = BitConverter.ToUInt64(buf, 0);

                var sb = new StringBuilder();
                sb.AppendLine($"Base: 0x{addr:X16} -> 0x{current:X16}");

                for (int i = 0; i < offsets.Length; i++)
                {
                    ulong nextAddr = current + (ulong)offsets[i];
                    if (!_driver.CopyVirtualMemory(pid, (IntPtr)nextAddr, bufPtr, 8))
                    {
                        sb.AppendLine($"  [+0x{offsets[i]:X}] 0x{nextAddr:X16} -> FAILED");
                        return sb.ToString();
                    }
                    Marshal.Copy(bufPtr, buf, 0, 8);
                    current = BitConverter.ToUInt64(buf, 0);
                    sb.AppendLine($"  [+0x{offsets[i]:X}] 0x{nextAddr:X16} -> 0x{current:X16}");
                }

                sb.AppendLine($"Final address: 0x{current:X16}");
                return sb.ToString();
            }
            finally
            {
                Marshal.FreeHGlobal(bufPtr);
            }
        }

        [McpServerTool, Description("Writes bytes to process memory at the specified address. Bytes should be hex string like '48 89 5C 24'.")]
        public string WriteMemory(int pid, string address, string hexBytes)
        {
            ulong addr = ParseAddress(address);
            if (addr == 0) return "Invalid address.";

            byte[] data = ParseHexBytes(hexBytes);
            if (data == null || data.Length == 0) return "Invalid hex bytes. Use format like '48 89 5C 24'.";

            IntPtr bufPtr = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, bufPtr, data.Length);
                if (!_driver.WriteVirtualMemory(pid, (IntPtr)addr, bufPtr, data.Length))
                    return $"Failed to write {data.Length} bytes at 0x{addr:X16}.";

                return $"Successfully wrote {data.Length} bytes at 0x{addr:X16}.";
            }
            finally
            {
                Marshal.FreeHGlobal(bufPtr);
            }
        }

        [McpServerTool, Description("Enumerates memory regions of a process. Returns base address, size, protection, and state for each region.")]
        public string EnumMemoryRegions(int pid, string filter = "")
        {
            var regions = _driver.EnumRegions(pid);
            if (regions == null || regions.Count == 0)
                return $"No memory regions found for PID {pid}.";

            var sb = new StringBuilder();
            sb.AppendLine($"{"Base Address",-20} {"Size",-14} {"Protect",-10} {"State",-10} {"Type"}");
            sb.AppendLine(new string('-', 70));

            int count = 0;
            foreach (var r in regions)
            {
                string protect = GetProtectionString(r.protect);
                string state = GetStateString(r.state);

                if (!string.IsNullOrEmpty(filter) &&
                    !protect.Contains(filter, StringComparison.OrdinalIgnoreCase) &&
                    !state.Contains(filter, StringComparison.OrdinalIgnoreCase))
                    continue;

                sb.AppendLine($"0x{r.baseAddress:X16} 0x{r.regionSize:X10} {protect,-10} {state,-10} 0x{r.type:X}");
                count++;
                if (count >= 500) // Cap output
                {
                    sb.AppendLine($"... ({regions.Count - count} more regions)");
                    break;
                }
            }

            sb.AppendLine($"Total: {regions.Count} regions");
            return sb.ToString();
        }

        private string FormatHexDump(byte[] data, ulong baseAddr)
        {
            var sb = new StringBuilder();
            for (int i = 0; i < data.Length; i += 16)
            {
                sb.Append($"0x{baseAddr + (ulong)i:X16}  ");

                // Hex
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < data.Length)
                        sb.Append($"{data[i + j]:X2} ");
                    else
                        sb.Append("   ");
                    if (j == 7) sb.Append(' ');
                }

                sb.Append(' ');

                // ASCII
                for (int j = 0; j < 16 && i + j < data.Length; j++)
                {
                    char c = (char)data[i + j];
                    sb.Append(c >= 32 && c < 127 ? c : '.');
                }

                sb.AppendLine();
            }
            return sb.ToString();
        }

        internal static ulong ParseAddress(string address)
        {
            if (string.IsNullOrEmpty(address)) return 0;
            address = address.Trim().Replace("0x", "").Replace("0X", "");
            if (ulong.TryParse(address, System.Globalization.NumberStyles.HexNumber, null, out ulong result))
                return result;
            return 0;
        }

        internal static byte[] ParseHexBytes(string hex)
        {
            if (string.IsNullOrEmpty(hex)) return null;
            hex = hex.Replace(" ", "").Replace("-", "").Replace("0x", "").Replace("0X", "");
            if (hex.Length % 2 != 0) return null;

            byte[] result = new byte[hex.Length / 2];
            for (int i = 0; i < result.Length; i++)
            {
                if (!byte.TryParse(hex.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber, null, out result[i]))
                    return null;
            }
            return result;
        }

        private string GetProtectionString(uint protect)
        {
            var parts = new List<string>();
            if ((protect & 0x01) != 0) parts.Add("NOACCESS");
            if ((protect & 0x02) != 0) parts.Add("R");
            if ((protect & 0x04) != 0) parts.Add("RW");
            if ((protect & 0x08) != 0) parts.Add("WC");
            if ((protect & 0x10) != 0) parts.Add("RX");
            if ((protect & 0x20) != 0) parts.Add("RWX");
            if ((protect & 0x40) != 0) parts.Add("RWX");
            if ((protect & 0x100) != 0) parts.Add("GUARD");
            return parts.Count > 0 ? string.Join("|", parts) : "0x" + protect.ToString("X");
        }

        private string GetStateString(uint state)
        {
            if ((state & 0x1000) != 0) return "COMMIT";
            if ((state & 0x2000) != 0) return "RESERVE";
            if ((state & 0x10000) != 0) return "FREE";
            return "0x" + state.ToString("X");
        }
    }
}
