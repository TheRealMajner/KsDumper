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
    public class ModuleTools
    {
        private readonly IMemoryReader _driver;

        public ModuleTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Lists all loaded modules (DLLs) in a process with base address, size, and path.")]
        public string ListModules(int pid)
        {
            if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                return $"Failed to enumerate modules for PID {pid}.";

            var sb = new StringBuilder();
            sb.AppendLine($"{"Base Address",-20} {"Size",-12} {"Name",-30} {"Path"}");
            sb.AppendLine(new string('-', 100));

            foreach (var m in modules)
            {
                sb.AppendLine($"0x{m.BaseAddress:X16} 0x{m.ImageSize:X8} {Truncate(m.ModuleName, 29),-30} {m.FileName}");
            }

            sb.AppendLine($"Total: {modules.Length} modules");
            return sb.ToString();
        }

        [McpServerTool, Description("Searches for a module by name in a process. Returns base address and size if found.")]
        public string FindModule(int pid, string moduleName)
        {
            if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                return $"Failed to enumerate modules for PID {pid}.";

            var matches = modules.Where(m =>
                m.ModuleName.IndexOf(moduleName, StringComparison.OrdinalIgnoreCase) >= 0).ToArray();

            if (matches.Length == 0)
                return $"Module '{moduleName}' not found in PID {pid}.";

            var sb = new StringBuilder();
            foreach (var m in matches)
            {
                sb.AppendLine($"Module: {m.ModuleName}");
                sb.AppendLine($"  Base: 0x{m.BaseAddress:X16}");
                sb.AppendLine($"  Size: 0x{m.ImageSize:X} ({m.ImageSize:N0} bytes)");
                sb.AppendLine($"  End:  0x{m.BaseAddress + m.ImageSize:X16}");
                sb.AppendLine($"  Path: {m.FileName}");
                sb.AppendLine($"  Entry: 0x{m.EntryPoint:X16}");
                sb.AppendLine();
            }
            return sb.ToString();
        }

        [McpServerTool, Description("Gets the export table of a module in a process. Lists exported function names and their addresses.")]
        public string GetModuleExports(int pid, string moduleName)
        {
            var exportMap = _driver.GetExportMap(pid);
            if (exportMap == null || exportMap.Count == 0)
                return $"No exports found for PID {pid}.";

            var sb = new StringBuilder();
            int count = 0;

            foreach (var kvp in exportMap.OrderBy(k => k.Value.dllName).ThenBy(k => k.Value.funcName))
            {
                if (!string.IsNullOrEmpty(moduleName) &&
                    !kvp.Value.dllName.Contains(moduleName, StringComparison.OrdinalIgnoreCase))
                    continue;

                sb.AppendLine($"0x{kvp.Key:X16}  {kvp.Value.dllName}!{kvp.Value.funcName}");
                count++;
                if (count >= 1000)
                {
                    sb.AppendLine($"... (truncated at 1000 exports)");
                    break;
                }
            }

            sb.AppendLine($"Total: {count} exports shown");
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
