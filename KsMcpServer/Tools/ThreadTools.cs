using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using ModelContextProtocol.Server;
using KsDumperClient.Driver;

namespace KsMcpServer.Tools
{
    [McpServerToolType]
    public class ThreadTools
    {
        private readonly IMemoryReader _driver;

        public ThreadTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Gets the CPU context (registers) of a specific thread in a process. Returns register values.")]
        public string GetThreadContext(int pid, int threadId)
        {
            // CONTEXT_FULL for x64 = 0x0010003F
            byte[] context = _driver.GetThreadContext(pid, threadId, 0x0010003F);
            if (context == null || context.Length < 1232)
                return $"Failed to get thread context for TID {threadId} in PID {pid}.";

            var sb = new StringBuilder();
            sb.AppendLine($"Thread {threadId} Context (PID {pid}):");
            sb.AppendLine();

            // x64 CONTEXT register offsets
            sb.AppendLine($"  RAX: 0x{BitConverter.ToUInt64(context, 120):X16}");
            sb.AppendLine($"  RCX: 0x{BitConverter.ToUInt64(context, 128):X16}");
            sb.AppendLine($"  RDX: 0x{BitConverter.ToUInt64(context, 136):X16}");
            sb.AppendLine($"  RBX: 0x{BitConverter.ToUInt64(context, 144):X16}");
            sb.AppendLine($"  RSP: 0x{BitConverter.ToUInt64(context, 152):X16}");
            sb.AppendLine($"  RBP: 0x{BitConverter.ToUInt64(context, 160):X16}");
            sb.AppendLine($"  RSI: 0x{BitConverter.ToUInt64(context, 168):X16}");
            sb.AppendLine($"  RDI: 0x{BitConverter.ToUInt64(context, 176):X16}");
            sb.AppendLine($"  R8:  0x{BitConverter.ToUInt64(context, 184):X16}");
            sb.AppendLine($"  R9:  0x{BitConverter.ToUInt64(context, 192):X16}");
            sb.AppendLine($"  R10: 0x{BitConverter.ToUInt64(context, 200):X16}");
            sb.AppendLine($"  R11: 0x{BitConverter.ToUInt64(context, 208):X16}");
            sb.AppendLine($"  R12: 0x{BitConverter.ToUInt64(context, 216):X16}");
            sb.AppendLine($"  R13: 0x{BitConverter.ToUInt64(context, 224):X16}");
            sb.AppendLine($"  R14: 0x{BitConverter.ToUInt64(context, 232):X16}");
            sb.AppendLine($"  R15: 0x{BitConverter.ToUInt64(context, 240):X16}");
            sb.AppendLine($"  RIP: 0x{BitConverter.ToUInt64(context, 248):X16}");
            sb.AppendLine($"  EFLAGS: 0x{BitConverter.ToUInt32(context, 68):X8}");

            return sb.ToString();
        }

        [McpServerTool, Description("Suspends all threads in a process. Returns the number of threads suspended.")]
        public string SuspendProcess(int pid)
        {
            int count = _driver.SuspendProcess(pid);
            if (count < 0)
                return $"Failed to suspend threads in PID {pid}.";
            return $"Suspended {count} thread(s) in PID {pid}.";
        }

        [McpServerTool, Description("Resumes all threads in a previously suspended process. Returns the number of threads resumed.")]
        public string ResumeProcess(int pid)
        {
            int count = _driver.ResumeProcess(pid);
            if (count < 0)
                return $"Failed to resume threads in PID {pid}.";
            return $"Resumed {count} thread(s) in PID {pid}.";
        }

        [McpServerTool, Description("Reads the instruction bytes at a thread's current RIP (instruction pointer). Shows the next N bytes of code.")]
        public string ReadThreadCode(int pid, int threadId, int bytes = 32)
        {
            byte[] context = _driver.GetThreadContext(pid, threadId, 0x0010003F);
            if (context == null || context.Length < 256)
                return $"Failed to get thread context for TID {threadId}.";

            ulong rip = BitConverter.ToUInt64(context, 248);
            if (rip == 0)
                return "Thread RIP is 0 (thread may not be running).";

            if (bytes > 256) bytes = 256;

            byte[] code = new byte[bytes];
            IntPtr bufPtr = Marshal.AllocHGlobal(bytes);
            try
            {
                if (!_driver.CopyVirtualMemory(pid, (IntPtr)rip, bufPtr, bytes))
                    return $"Failed to read {bytes} bytes at RIP 0x{rip:X16}.";

                Marshal.Copy(bufPtr, code, 0, bytes);

                var sb = new StringBuilder();
                sb.AppendLine($"Thread {threadId} code at RIP 0x{rip:X16}:");
                sb.AppendLine();

                // Hex dump of code bytes
                sb.Append("  ");
                for (int i = 0; i < code.Length; i++)
                {
                    sb.Append($"{code[i]:X2} ");
                    if ((i + 1) % 16 == 0) sb.AppendLine("\n  ");
                }
                sb.AppendLine();

                return sb.ToString();
            }
            finally
            {
                Marshal.FreeHGlobal(bufPtr);
            }
        }
    }
}
