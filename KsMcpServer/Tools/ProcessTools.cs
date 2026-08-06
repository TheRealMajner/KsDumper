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
    public class ProcessTools
    {
        private readonly IMemoryReader _driver;

        public ProcessTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Lists all running processes on the system with PID, name, and path.")]
        public string ListProcesses()
        {
            if (!_driver.GetProcessSummaryList(out ProcessSummary[] processes))
                return "Failed to enumerate processes.";

            var sb = new StringBuilder();
            sb.AppendLine($"{"PID",-8} {"Name",-35} {"Path"}");
            sb.AppendLine(new string('-', 100));

            foreach (var p in processes)
            {
                sb.AppendLine($"{p.ProcessId,-8} {Truncate(p.ProcessName, 34),-35} {p.MainModuleFileName}");
            }

            return sb.ToString();
        }

        [McpServerTool, Description("Searches for a process by name (case-insensitive partial match). Returns matching PIDs and names.")]
        public string FindProcess(string name)
        {
            if (!_driver.GetProcessSummaryList(out ProcessSummary[] processes))
                return "Failed to enumerate processes.";

            var matches = processes.Where(p =>
                p.ProcessName.IndexOf(name, StringComparison.OrdinalIgnoreCase) >= 0).ToArray();

            if (matches.Length == 0)
                return $"No processes found matching '{name}'.";

            var sb = new StringBuilder();
            sb.AppendLine($"Found {matches.Length} process(es) matching '{name}':");
            sb.AppendLine($"{"PID",-8} {"Name",-35} {"Path"}");
            sb.AppendLine(new string('-', 100));

            foreach (var p in matches)
            {
                sb.AppendLine($"{p.ProcessId,-8} {Truncate(p.ProcessName, 34),-35} {p.MainModuleFileName}");
            }

            return sb.ToString();
        }

        [McpServerTool, Description("Gets detailed information about a specific process by PID including modules and memory regions count.")]
        public string GetProcessInfo(int pid)
        {
            if (!_driver.GetProcessSummaryList(out ProcessSummary[] processes))
                return "Failed to enumerate processes.";

            var proc = processes.FirstOrDefault(p => p.ProcessId == pid);
            if (proc == null)
                return $"Process with PID {pid} not found.";

            var sb = new StringBuilder();
            sb.AppendLine($"Process: {proc.ProcessName}");
            sb.AppendLine($"PID: {proc.ProcessId}");
            sb.AppendLine($"Path: {proc.MainModuleFileName}");
            sb.AppendLine($"Main Module Base: 0x{proc.MainModuleBase:X16}");
            sb.AppendLine($"Main Module Size: 0x{proc.MainModuleImageSize:X} ({proc.MainModuleImageSize:N0} bytes)");
            sb.AppendLine($"Entry Point: 0x{proc.MainModuleEntryPoint:X16}");
            sb.AppendLine($"Is WOW64: {proc.IsWOW64}");

            // Get module count
            if (_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                sb.AppendLine($"Loaded Modules: {modules.Length}");

            // Get region count
            var regions = _driver.EnumRegions(pid);
            sb.AppendLine($"Memory Regions: {regions.Count}");

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
