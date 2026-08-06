using System;
using System.ComponentModel;
using System.Linq;
using System.Text;
using ModelContextProtocol.Server;
using KsDumperClient;
using KsDumperClient.Driver;

namespace KsMcpServer.Tools
{
    [McpServerToolType]
    public class KernelTools
    {
        private readonly IMemoryReader _driver;

        public KernelTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Removes process protection (anti-cheat) from a process by clearing kernel protection flags. Returns status.")]
        public string UnprotectProcess(int pid)
        {
            int result = _driver.UnprotectProcess(pid);
            if (result == 0)
                return $"Process {pid} unprotected successfully.";
            return $"UnprotectProcess returned status {result} (0x{result:X}).";
        }

        [McpServerTool, Description("Enumerates kernel-mode callbacks (process creation, image load, thread creation). Optionally removes them to bypass anti-cheat.")]
        public string EnumKernelCallbacks(bool removeCallbacks = false)
        {
            try
            {
                var (callbackCount, removedCount, callbacks) = _driver.EnumKernelCallbacks(removeCallbacks);

                var sb = new StringBuilder();
                sb.AppendLine($"Kernel Callbacks (remove={removeCallbacks}):");
                sb.AppendLine($"  Total callbacks: {callbackCount}");
                if (removeCallbacks)
                    sb.AppendLine($"  Removed: {removedCount}");
                sb.AppendLine();

                if (callbacks != null && callbacks.Length > 0)
                {
                    sb.AppendLine($"{"Type",-12} {"Index",-6} {"Address",-20} {"Driver",-30} {"Removed"}");
                    sb.AppendLine(new string('-', 80));

                    foreach (var cb in callbacks)
                    {
                        string type = cb.CallbackType switch
                        {
                            0 => "Process",
                            1 => "LoadImage",
                            2 => "Thread",
                            _ => $"Type{cb.CallbackType}"
                        };
                        sb.AppendLine($"{type,-12} {cb.Index,-6} 0x{cb.CallbackAddress:X16} {Truncate(cb.DriverName ?? "?", 29),-30} {(cb.Removed != 0 ? "YES" : "")}");
                    }
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"EnumKernelCallbacks failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Clones a process in kernel mode, creating a copy that can be dumped without anti-cheat detecting access. Returns the cloned PID.")]
        public string CloneProcess(int pid)
        {
            try
            {
                var (status, clonedPid) = _driver.CloneProcess(pid);
                if (status == 0 && clonedPid > 0)
                    return $"Process {pid} cloned successfully. Cloned PID: {clonedPid}";
                return $"CloneProcess failed with status {status} (0x{status:X}).";
            }
            catch (Exception ex)
            {
                return $"CloneProcess failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Enumerates the Virtual Address Descriptor (VAD) tree of a process from kernel mode. Shows memory regions with protection and flags.")]
        public string EnumVadTree(int pid, int maxEntries = 200)
        {
            try
            {
                var (vadCount, vads) = _driver.EnumVadTree(pid);

                var sb = new StringBuilder();
                sb.AppendLine($"VAD Tree for PID {pid} ({vadCount} entries):");
                sb.AppendLine();
                sb.AppendLine($"{"Start Address",-20} {"End Address",-20} {"Protection",-12} {"Flags",-10} {"CommitChg",-10} {"ControlArea"}");
                sb.AppendLine(new string('-', 100));

                int shown = 0;
                if (vads != null)
                {
                    foreach (var v in vads)
                    {
                        if (shown >= maxEntries)
                        {
                            sb.AppendLine($"... ({vadCount - shown} more)");
                            break;
                        }
                        sb.AppendLine($"0x{v.StartAddress:X16} 0x{v.EndAddress:X16} 0x{v.Protection:X8} 0x{v.Flags:X8} {v.CommitCharge,-10} 0x{v.ControlArea:X}");
                        shown++;
                    }
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"EnumVadTree failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Enumerates handles (open resources) of a process from kernel mode. Shows handle value, target PID, access rights.")]
        public string EnumHandles(int pid, int maxEntries = 200)
        {
            try
            {
                var (handleCount, handles) = _driver.EnumHandles(pid);

                var sb = new StringBuilder();
                sb.AppendLine($"Handles for PID {pid} ({handleCount} entries):");
                sb.AppendLine();
                sb.AppendLine($"{"Handle",-12} {"TargetPID",-12} {"Access",-14} {"TypeIdx",-8} {"Name"}");
                sb.AppendLine(new string('-', 90));

                int shown = 0;
                if (handles != null)
                {
                    foreach (var h in handles)
                    {
                        if (shown >= maxEntries)
                        {
                            sb.AppendLine($"... ({handleCount - shown} more)");
                            break;
                        }
                        sb.AppendLine($"0x{h.HandleValue:X8}   {h.TargetProcessId,-12} 0x{h.GrantedAccess:X8}   {h.ObjectTypeIndex,-8} {h.ObjectName ?? ""}");
                        shown++;
                    }
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"EnumHandles failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Enumerates kernel modules (loaded drivers). Shows base address, size, name, and path.")]
        public string EnumKernelModules()
        {
            try
            {
                var (moduleCount, modules) = _driver.EnumKernelModules();

                var sb = new StringBuilder();
                sb.AppendLine($"Kernel Modules ({moduleCount} loaded):");
                sb.AppendLine();
                sb.AppendLine($"{"Base Address",-20} {"Size",-12} {"Name",-30} {"Path"}");
                sb.AppendLine(new string('-', 100));

                if (modules != null)
                {
                    foreach (var m in modules)
                    {
                        sb.AppendLine($"0x{m.BaseAddress:X16} 0x{m.ImageSize:X8} {Truncate(m.BaseName ?? "", 29),-30} {m.FullPath ?? ""}");
                    }
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"EnumKernelModules failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Enumerates all loaded drivers on the system. Shows base address, size, name, load time, entry point.")]
        public string EnumDrivers()
        {
            try
            {
                var drivers = _driver.EnumerateDrivers();
                if (drivers == null || drivers.Count == 0)
                    return "No drivers enumerated. Kernel driver may not be loaded.";

                var sb = new StringBuilder();
                sb.AppendLine($"Loaded Drivers ({drivers.Count}):");
                sb.AppendLine();
                sb.AppendLine($"{"Base Address",-20} {"Size",-12} {"Name",-25} {"Entry Point",-20} {"LoadTime"}");
                sb.AppendLine(new string('-', 110));

                foreach (var d in drivers)
                {
                    sb.AppendLine($"0x{d.baseAddress:X16} 0x{d.imageSize:X8} {Truncate(d.baseName ?? "", 24),-25} 0x{d.entryPoint:X16} {d.loadTime:yyyy-MM-dd HH:mm:ss}");
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"EnumDrivers failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Kills a process by name using kernel-mode termination. Bypasses user-mode protections.")]
        public string KillProcessByName(string processName)
        {
            try
            {
                var (status, pid) = _driver.KillProcessByName(processName);
                if (status == 0 && pid > 0)
                    return $"Process '{processName}' (PID {pid}) terminated successfully.";
                return $"KillProcessByName failed with status {status} (0x{status:X}).";
            }
            catch (Exception ex)
            {
                return $"KillProcessByName failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Unloads a driver by name using kernel-mode operations. Use with caution.")]
        public string UnloadDriver(string driverName)
        {
            try
            {
                int result = _driver.UnloadDriverByName(driverName);
                if (result == 0)
                    return $"Driver '{driverName}' unloaded successfully.";
                return $"UnloadDriver returned status {result} (0x{result:X}).";
            }
            catch (Exception ex)
            {
                return $"UnloadDriver failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Unloads a module (DLL) from a process using kernel-mode operations. Requires module base address as hex.")]
        public string UnloadModule(int pid, string moduleBaseAddress)
        {
            ulong addr = MemoryTools.ParseAddress(moduleBaseAddress);
            if (addr == 0) return "Invalid module base address.";

            try
            {
                int result = _driver.UnloadModule(pid, addr);
                if (result == 0)
                    return $"Module at 0x{addr:X16} unloaded from PID {pid}.";
                return $"UnloadModule returned status {result} (0x{result:X}).";
            }
            catch (Exception ex)
            {
                return $"UnloadModule failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Reports whether the MCP server is connected to the kernel driver or running in user-mode fallback.")]
        public string GetDriverStatus()
        {
            bool valid = _driver.HasValidHandle();
            bool kernel = _driver.IsKernelMode;

            var sb = new StringBuilder();
            sb.AppendLine("KsDumper Driver Status:");
            sb.AppendLine($"  Valid handle: {valid}");
            sb.AppendLine($"  Kernel mode: {kernel}");
            sb.AppendLine($"  Interface: {_driver.GetType().Name}");
            return sb.ToString();
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
                return value ?? "";
            return value.Substring(0, maxLength - 1) + "…";
        }
    }
}
