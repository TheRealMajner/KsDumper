using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using ModelContextProtocol.Server;
using KsDumperClient.Driver;

namespace KsMcpServer.Tools
{
    [McpServerToolType]
    public class DebugTools
    {
        private readonly IMemoryReader _driver;

        public DebugTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Attaches the kernel debugger to a process. Required before using DebugWaitEvent/DebugContinue.")]
        public string DebugAttach(int pid)
        {
            try
            {
                bool ok = _driver.DebugAttach(pid);
                return ok
                    ? $"Debugger attached to PID {pid}."
                    : $"Failed to attach debugger to PID {pid}.";
            }
            catch (Exception ex)
            {
                return $"DebugAttach failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Waits for a debug event from an attached process. Returns event code, thread ID, exception address, and exception code.")]
        public string DebugWaitEvent(int timeoutMs = 5000)
        {
            try
            {
                var (eventCode, threadId, eventAddress, exceptionCode) = _driver.DebugWaitEvent(timeoutMs);

                if (eventCode == 0)
                    return $"No debug event within {timeoutMs}ms timeout.";

                var sb = new StringBuilder();
                sb.AppendLine("Debug Event received:");
                sb.AppendLine($"  Event code: {eventCode} ({GetEventName(eventCode)})");
                sb.AppendLine($"  Thread ID: {threadId}");
                sb.AppendLine($"  Address: 0x{eventAddress:X16}");
                sb.AppendLine($"  Exception code: 0x{exceptionCode:X8} ({GetExceptionName(exceptionCode)})");
                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"DebugWaitEvent failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Continues execution after a debug event. continueStatus: 0x10002 = DBG_CONTINUE, 0x80010001 = EXCEPTION_NOT_HANDLED.")]
        public string DebugContinue(int threadId, int continueStatus = 0x10002)
        {
            try
            {
                bool ok = _driver.DebugContinue(threadId, continueStatus);
                return ok
                    ? $"Debug continued for thread {threadId} with status 0x{continueStatus:X}."
                    : $"Failed to continue debug for thread {threadId}.";
            }
            catch (Exception ex)
            {
                return $"DebugContinue failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Sets the CPU context (registers) of a specific thread. Provide register name=value pairs like 'RIP=0x7FF6A0001000 RAX=0'.")]
        public string SetThreadContext(int pid, int threadId, string registers)
        {
            try
            {
                byte[] ctx = _driver.GetThreadContext(pid, threadId, 0x0010003F);
                if (ctx == null || ctx.Length < 1232)
                    return $"Failed to get current context for TID {threadId}.";

                foreach (var pair in registers.Split(new[] { ' ', ',' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    var parts = pair.Split('=');
                    if (parts.Length != 2) continue;

                    string reg = parts[0].Trim().ToUpperInvariant();
                    ulong val = MemoryTools.ParseAddress(parts[1].Trim());

                    int offset = GetRegisterOffset(reg);
                    if (offset < 0)
                        return $"Unknown register: {reg}";

                    byte[] valBytes = BitConverter.GetBytes(val);
                    Array.Copy(valBytes, 0, ctx, offset, 8);
                }

                bool ok = _driver.SetThreadContext(pid, threadId, ctx);
                return ok
                    ? $"Thread {threadId} context updated."
                    : $"Failed to set thread context for TID {threadId}.";
            }
            catch (Exception ex)
            {
                return $"SetThreadContext failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Reads a specific value type from process memory. Types: byte, short, int, long, float, double, pointer.")]
        public string ReadValue(int pid, string address, string type = "long")
        {
            ulong addr = MemoryTools.ParseAddress(address);
            if (addr == 0) return "Invalid address.";

            int size = GetTypeSize(type);
            if (size <= 0) return $"Unknown type '{type}'. Use: byte, short, int, long, float, double, pointer.";

            byte[] buffer = new byte[size];
            IntPtr bufPtr = Marshal.AllocHGlobal(size);
            try
            {
                if (!_driver.CopyVirtualMemory(pid, (IntPtr)addr, bufPtr, size))
                    return $"Failed to read {size} bytes at 0x{addr:X16}.";

                Marshal.Copy(bufPtr, buffer, 0, size);

                string result = type.ToLowerInvariant() switch
                {
                    "byte" => $"{buffer[0]} (0x{buffer[0]:X2})",
                    "short" => $"{BitConverter.ToInt16(buffer, 0)} (0x{BitConverter.ToUInt16(buffer, 0):X4})",
                    "int" => $"{BitConverter.ToInt32(buffer, 0)} (0x{BitConverter.ToUInt32(buffer, 0):X8})",
                    "long" => $"{BitConverter.ToInt64(buffer, 0)} (0x{BitConverter.ToUInt64(buffer, 0):X16})",
                    "float" => $"{BitConverter.ToSingle(buffer, 0):G9}",
                    "double" => $"{BitConverter.ToDouble(buffer, 0):G17}",
                    "pointer" or "ptr" => $"0x{BitConverter.ToUInt64(buffer, 0):X16}",
                    _ => BitConverter.ToString(buffer)
                };

                return $"[0x{addr:X16}] ({type}) = {result}";
            }
            finally
            {
                Marshal.FreeHGlobal(bufPtr);
            }
        }

        [McpServerTool, Description("Writes a typed value to process memory. Types: byte, short, int, long, float, double. Value is decimal unless prefixed with 0x.")]
        public string WriteValue(int pid, string address, string type, string value)
        {
            ulong addr = MemoryTools.ParseAddress(address);
            if (addr == 0) return "Invalid address.";

            byte[] data;
            try
            {
                data = type.ToLowerInvariant() switch
                {
                    "byte" => new[] { byte.Parse(value) },
                    "short" => BitConverter.GetBytes(short.Parse(value)),
                    "int" => BitConverter.GetBytes(int.Parse(value)),
                    "long" => BitConverter.GetBytes(long.Parse(value.Replace("0x", ""), value.StartsWith("0x") ? System.Globalization.NumberStyles.HexNumber : System.Globalization.NumberStyles.Integer, null)),
                    "float" => BitConverter.GetBytes(float.Parse(value)),
                    "double" => BitConverter.GetBytes(double.Parse(value)),
                    _ => null
                };
            }
            catch (Exception ex)
            {
                return $"Failed to parse '{value}' as {type}: {ex.Message}";
            }

            if (data == null) return $"Unknown type '{type}'.";

            IntPtr bufPtr = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, bufPtr, data.Length);
                if (!_driver.WriteVirtualMemory(pid, (IntPtr)addr, bufPtr, data.Length))
                    return $"Failed to write at 0x{addr:X16}.";
                return $"Wrote {type} value {value} at 0x{addr:X16}.";
            }
            finally
            {
                Marshal.FreeHGlobal(bufPtr);
            }
        }

        [McpServerTool, Description("Reads a null-terminated string from process memory (ASCII or Unicode).")]
        public string ReadString(int pid, string address, bool unicode = false, int maxLength = 512)
        {
            ulong addr = MemoryTools.ParseAddress(address);
            if (addr == 0) return "Invalid address.";

            int readSize = unicode ? maxLength * 2 : maxLength;
            byte[] buffer = new byte[readSize];
            IntPtr bufPtr = Marshal.AllocHGlobal(readSize);
            try
            {
                if (!_driver.CopyVirtualMemory(pid, (IntPtr)addr, bufPtr, readSize))
                    return $"Failed to read at 0x{addr:X16}.";

                Marshal.Copy(bufPtr, buffer, 0, readSize);

                string result;
                if (unicode)
                {
                    int end = 0;
                    while (end + 1 < buffer.Length && (buffer[end] != 0 || buffer[end + 1] != 0)) end += 2;
                    result = Encoding.Unicode.GetString(buffer, 0, end);
                }
                else
                {
                    int end = Array.IndexOf<byte>(buffer, 0);
                    if (end < 0) end = buffer.Length;
                    result = Encoding.ASCII.GetString(buffer, 0, end);
                }

                return $"[0x{addr:X16}] \"{result}\"";
            }
            finally
            {
                Marshal.FreeHGlobal(bufPtr);
            }
        }

        private static int GetRegisterOffset(string reg)
        {
            return reg switch
            {
                "RAX" => 120, "RCX" => 128, "RDX" => 136, "RBX" => 144,
                "RSP" => 152, "RBP" => 160, "RSI" => 168, "RDI" => 176,
                "R8" => 184, "R9" => 192, "R10" => 200, "R11" => 208,
                "R12" => 216, "R13" => 224, "R14" => 232, "R15" => 240,
                "RIP" => 248,
                _ => -1
            };
        }

        private static string GetEventName(int code)
        {
            return code switch
            {
                1 => "EXCEPTION_DEBUG_EVENT",
                2 => "CREATE_THREAD_DEBUG_EVENT",
                3 => "CREATE_PROCESS_DEBUG_EVENT",
                4 => "EXIT_THREAD_DEBUG_EVENT",
                5 => "EXIT_PROCESS_DEBUG_EVENT",
                6 => "LOAD_DLL_DEBUG_EVENT",
                7 => "UNLOAD_DLL_DEBUG_EVENT",
                8 => "OUTPUT_DEBUG_STRING_EVENT",
                9 => "RIP_EVENT",
                _ => "UNKNOWN"
            };
        }

        private static string GetExceptionName(int code)
        {
            return code switch
            {
                unchecked((int)0x80000003) => "BREAKPOINT",
                unchecked((int)0xC0000005) => "ACCESS_VIOLATION",
                unchecked((int)0x80000004) => "SINGLE_STEP",
                unchecked((int)0xC000001D) => "ILLEGAL_INSTRUCTION",
                unchecked((int)0xC0000094) => "INT_DIVIDE_BY_ZERO",
                _ => ""
            };
        }

        private static int GetTypeSize(string type)
        {
            return type.ToLowerInvariant() switch
            {
                "byte" => 1,
                "short" => 2,
                "int" => 4,
                "long" => 8,
                "float" => 4,
                "double" => 8,
                "pointer" or "ptr" => 8,
                _ => 0
            };
        }
    }
}
