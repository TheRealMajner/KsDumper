using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ServiceProcess;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public enum AntiCheatType
    {
        None,
        EasyAntiCheat,
        BattlEye
    }

    public class AntiCheatBypass
    {
        private static readonly Dictionary<AntiCheatType, AntiCheatInfo> AntiCheatDatabase = new Dictionary<AntiCheatType, AntiCheatInfo>
        {
            [AntiCheatType.EasyAntiCheat] = new AntiCheatInfo
            {
                Type = AntiCheatType.EasyAntiCheat,
                DisplayName = "EasyAntiCheat",
                ProcessNames = new[]
                {
                    "EasyAntiCheat_EOS.exe",
                    "EasyAntiCheat.exe",
                    "EasyAntiCheat_Setup.exe",
                    "EasyAntiCheat_EOS_Setup.exe",
                    "EACLauncher.exe",
                    "EasyAntiCheatService.exe"
                },
                ServiceNames = new[] { "EasyAntiCheat_EOS", "EasyAntiCheat" },
                DriverNames = new[] { "EasyAntiCheat_EOS", "EasyAntiCheat" }
            },
            [AntiCheatType.BattlEye] = new AntiCheatInfo
            {
                Type = AntiCheatType.BattlEye,
                DisplayName = "BattlEye",
                ProcessNames = new[]
                {
                    "BEService.exe",
                    "BEClient.exe",
                    "BEClient_x64.exe",
                    "BattlEye.exe",
                    "BattlEye Launcher.exe",
                    "BEClientService.exe",
                    "BEService_x64.exe"
                },
                ServiceNames = new[] { "BEService", "BattlEye Service" },
                DriverNames = new[] { "BEDaisy", "BEKernel" }
            }
        };

        public static AntiCheatInfo GetInfo(AntiCheatType type)
        {
            return AntiCheatDatabase.ContainsKey(type) ? AntiCheatDatabase[type] : null;
        }

        public static AntiCheatType[] GetAvailableTypes()
        {
            return new[] { AntiCheatType.EasyAntiCheat, AntiCheatType.BattlEye };
        }

        public static BypassResult Execute(IMemoryReader driver, AntiCheatType type, Action<string> log)
        {
            var result = new BypassResult { Type = type };

            if (type == AntiCheatType.None)
                return result;

            var info = GetInfo(type);
            if (info == null)
            {
                log($"Unknown anti-cheat type: {type}");
                return result;
            }

            log($"Starting bypass for {info.DisplayName}...");

            // Step 1: Kill all anti-cheat processes via driver (bypasses PPL protection)
            // Multiple passes to catch processes that respawn or start late
            for (int pass = 1; pass <= 3; pass++)
            {
                int killedThisPass = 0;

                foreach (var processName in info.ProcessNames)
                {
                    try
                    {
                        var (status, pid) = driver.KillProcessByName(processName);
                        if (status == 0)
                        {
                            log($"Killed process: {processName} (PID: {pid})");
                            result.ProcessesKilled++;
                            killedThisPass++;
                        }
                        else if (status == 2 && pass == 1)
                        {
                            // Only log failures on first pass (subsequent passes may find nothing)
                            log($"Process not found or kill failed: {processName}");
                            result.ProcessesFailed++;
                        }
                    }
                    catch (Exception ex)
                    {
                        log($"Kill exception ({processName}): {ex.Message}");
                        result.ProcessesFailed++;
                    }
                }

                // Also try user-mode kill for any processes the driver missed
                foreach (var processName in info.ProcessNames)
                {
                    try
                    {
                        var shortName = processName.Replace(".exe", "");
                        var procs = Process.GetProcessesByName(shortName);
                        foreach (var proc in procs)
                        {
                            try
                            {
                                proc.Kill();
                                proc.WaitForExit(3000);
                                log($"Killed (user-mode): {processName} (PID: {proc.Id})");
                                result.ProcessesKilled++;
                                killedThisPass++;
                            }
                            catch { }
                        }
                    }
                    catch { }
                }

                if (killedThisPass == 0 && pass > 1)
                    break; // No more processes found, stop retrying

                if (pass < 3)
                    System.Threading.Thread.Sleep(1000); // Wait before next pass
            }

            // Step 2: Stop services to prevent respawn
            foreach (var serviceName in info.ServiceNames)
            {
                try
                {
                    var sc = new ServiceController(serviceName);
                    if (sc.Status == ServiceControllerStatus.Running)
                    {
                        log($"Stopping service: {serviceName}");
                        sc.Stop();
                        sc.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(5));
                        log($"Service stopped: {serviceName}");
                        result.ServicesStopped++;
                    }
                }
                catch (InvalidOperationException)
                {
                    // Service not found, skip
                }
                catch (Exception ex)
                {
                    log($"Service stop failed ({serviceName}): {ex.Message}");
                    result.ServicesFailed++;
                }
            }

            // Step 3: Kill any remaining processes one final time after services stopped
            foreach (var processName in info.ProcessNames)
            {
                try
                {
                    var (status, pid) = driver.KillProcessByName(processName);
                    if (status == 0)
                    {
                        log($"Final kill: {processName} (PID: {pid})");
                        result.ProcessesKilled++;
                    }
                }
                catch { }
            }

            log($"Bypass complete: {result.ProcessesKilled} processes killed, {result.ServicesStopped} services stopped");
            return result;
        }

        // Suspend anti-cheat processes (non-destructive, for temporary bypass during dump)
        public static int SuspendAntiCheatProcesses(IMemoryReader driver, AntiCheatType type, Action<string> log)
        {
            var info = GetInfo(type);
            if (info == null) return 0;

            int suspended = 0;
            foreach (var processName in info.ProcessNames)
            {
                try
                {
                    var processes = Process.GetProcessesByName(processName.Replace(".exe", ""));
                    foreach (var proc in processes)
                    {
                        int count = driver.SuspendProcess(proc.Id);
                        if (count > 0)
                        {
                            log($"Suspended {count} threads in {processName} (PID: {proc.Id})");
                            suspended += count;
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"Failed to suspend {processName}: {ex.Message}");
                }
            }
            return suspended;
        }

        // Resume previously suspended anti-cheat processes
        public static int ResumeAntiCheatProcesses(IMemoryReader driver, AntiCheatType type, Action<string> log)
        {
            var info = GetInfo(type);
            if (info == null) return 0;

            int resumed = 0;
            foreach (var processName in info.ProcessNames)
            {
                try
                {
                    var processes = Process.GetProcessesByName(processName.Replace(".exe", ""));
                    foreach (var proc in processes)
                    {
                        int count = driver.ResumeProcess(proc.Id);
                        if (count > 0)
                        {
                            log($"Resumed {count} threads in {processName} (PID: {proc.Id})");
                            resumed += count;
                        }
                    }
                }
                catch (Exception ex)
                {
                    log($"Failed to resume {processName}: {ex.Message}");
                }
            }
            return resumed;
        }
    }

    public class AntiCheatInfo
    {
        public AntiCheatType Type;
        public string DisplayName;
        public string[] ProcessNames;
        public string[] ServiceNames;
        public string[] DriverNames;
    }

    public class BypassResult
    {
        public AntiCheatType Type;
        public int ProcessesKilled;
        public int ProcessesFailed;
        public int ServicesStopped;
        public int ServicesFailed;
        public int DriversUnloaded;
        public int DriversFailed;
    }
}
