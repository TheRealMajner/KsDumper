using System;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using ModelContextProtocol.Server;
using KsDumperClient;
using KsDumperClient.Driver;

namespace KsMcpServer.Tools
{
    [McpServerToolType]
    public class DumpTools
    {
        private readonly IMemoryReader _driver;

        public DumpTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Dumps a process's main module to disk. Returns the file path of the dumped executable.")]
        public string DumpProcess(int pid, string outputPath = "")
        {
            if (!_driver.GetProcessSummaryList(out ProcessSummary[] processes))
                return "Failed to enumerate processes.";

            var proc = processes.FirstOrDefault(p => p.ProcessId == pid);
            if (proc == null)
                return $"Process with PID {pid} not found.";

            if (string.IsNullOrEmpty(outputPath))
                outputPath = Path.Combine(Path.GetTempPath(), $"{proc.ProcessName}_dump_{pid}.exe");

            try
            {
                int size = (int)proc.MainModuleImageSize;
                byte[] buffer = new byte[size];
                IntPtr bufPtr = Marshal.AllocHGlobal(size);

                try
                {
                    if (!_driver.CopyVirtualMemory(pid, (IntPtr)proc.MainModuleBase, bufPtr, size))
                        return $"Failed to read main module memory ({size:N0} bytes) from PID {pid}.";

                    Marshal.Copy(bufPtr, buffer, 0, size);
                }
                finally
                {
                    Marshal.FreeHGlobal(bufPtr);
                }

                // Validate PE header
                if (buffer.Length < 64 || BitConverter.ToUInt16(buffer, 0) != 0x5A4D)
                    return "Dumped data is not a valid PE file (missing MZ header).";

                File.WriteAllBytes(outputPath, buffer);
                return $"Process dumped successfully.\nFile: {outputPath}\nSize: {size:N0} bytes\nBase: 0x{proc.MainModuleBase:X16}";
            }
            catch (Exception ex)
            {
                return $"Dump failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Creates a minidump of a process using comsvcs.dll. Works even on protected processes with SeDebugPrivilege.")]
        public string MiniDumpProcess(int pid, string outputPath = "")
        {
            if (!_driver.GetProcessSummaryList(out ProcessSummary[] processes))
                return "Failed to enumerate processes.";

            var proc = processes.FirstOrDefault(p => p.ProcessId == pid);
            if (proc == null)
                return $"Process with PID {pid} not found.";

            if (string.IsNullOrEmpty(outputPath))
                outputPath = Path.Combine(Path.GetTempPath(), $"{proc.ProcessName}_minidump_{pid}.dmp");

            string comsvcsPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "comsvcs.dll");

            if (!File.Exists(comsvcsPath))
                return $"comsvcs.dll not found at {comsvcsPath}";

            string args = $"comsvcs.dll MiniDump {pid} \"{outputPath}\" full";

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "rundll32.exe",
                    Arguments = args,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using (var p = Process.Start(psi))
                {
                    bool exited = p.WaitForExit(30000);
                    if (!exited)
                    {
                        try { p.Kill(); } catch { }
                        return "MiniDump timed out after 30 seconds.";
                    }
                }

                if (File.Exists(outputPath))
                {
                    var fi = new FileInfo(outputPath);
                    return $"MiniDump created successfully.\nFile: {outputPath}\nSize: {fi.Length:N0} bytes";
                }
                return "MiniDump failed: output file not created.";
            }
            catch (Exception ex)
            {
                return $"MiniDump error: {ex.Message}";
            }
        }

        [McpServerTool, Description("Dumps a specific module (DLL) from a process by name. Returns the file path of the dumped module.")]
        public string DumpModule(int pid, string moduleName, string outputPath = "")
        {
            if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                return $"Failed to enumerate modules for PID {pid}.";

            var mod = modules.FirstOrDefault(m =>
                m.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase));

            if (mod == null)
                return $"Module '{moduleName}' not found in PID {pid}.";

            if (string.IsNullOrEmpty(outputPath))
                outputPath = Path.Combine(Path.GetTempPath(), $"{mod.ModuleName}_dumped_{pid}");

            try
            {
                int size = (int)mod.ImageSize;
                byte[] buffer = new byte[size];
                IntPtr bufPtr = Marshal.AllocHGlobal(size);

                try
                {
                    if (!_driver.CopyVirtualMemory(pid, (IntPtr)mod.BaseAddress, bufPtr, size))
                        return $"Failed to read module memory ({size:N0} bytes).";

                    Marshal.Copy(bufPtr, buffer, 0, size);
                }
                finally
                {
                    Marshal.FreeHGlobal(bufPtr);
                }

                File.WriteAllBytes(outputPath, buffer);
                return $"Module dumped successfully.\nFile: {outputPath}\nSize: {size:N0} bytes\nBase: 0x{mod.BaseAddress:X16}";
            }
            catch (Exception ex)
            {
                return $"Dump failed: {ex.Message}";
            }
        }
    }
}
