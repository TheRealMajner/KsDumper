using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class AntiCheatDetector
    {
        public class AntiCheatInfo
        {
            public string Name;
            public string Version;
            public bool Detected;
            public List<string> Evidence = new List<string>();
            public List<ModuleMatch> Modules = new List<ModuleMatch>();
            public List<CallbackMatch> Callbacks = new List<CallbackMatch>();
            public string Severity; // "low", "medium", "high"
        }

        public class ModuleMatch
        {
            public string ModuleName;
            public ulong BaseAddress;
            public uint ImageSize;
        }

        public class CallbackMatch
        {
            public string Type;
            public ulong Address;
            public string DriverName;
        }

        public class DetectionResult
        {
            public List<AntiCheatInfo> DetectedAntiCheats = new List<AntiCheatInfo>();
            public List<string> SuspiciousModules = new List<string>();
            public bool HasKernelCallbacks;
            public int TotalCallbacksFound;
            public string Summary;
        }

        private static readonly (string name, string[] modulePatterns, string[] exportPatterns, string severity)[] KnownAntiCheats =
        {
            ("EasyAntiCheat",
                new[] { "EasyAntiCheat", "eac_launcher", "EasyAntiCheat_x64", "EasyAntiCheat_EOS", "eac_server" },
                new[] { "EAC_Initialize", "EAC_Shutdown", "EAC_CheckIntegrity" },
                "high"),

            ("BattlEye",
                new[] { "BEClient", "BEClient_x64", "BEService", "BEDaisy" },
                new[] { "BE_Init", "BE_Start" },
                "high"),

            ("Vanguard",
                new[] { "vgc", "vgk", "vgkbootstatus", "vgtray" },
                new string[] { },
                "high"),

            ("GameGuard",
                new[] { "GameGuard", "npggNT", "npgg", "GameMon", "GameMon64", "npsc" },
                new[] { "npgl_init", "npgg_auth" },
                "high"),

            ("nProtect",
                new[] { "gcapi", "NPSVSVR", "npsvmgr" },
                new string[] { },
                "medium"),

            ("XIGNCODE3",
                new[] { "xign", "x3", "XIGNCODE", "wellbia" },
                new string[] { },
                "high"),

            ("mhyprot",
                new[] { "mhyprot2", "mhyprot3", "HoYoProtect" },
                new string[] { },
                "high"),

            ("ACE (Tencent)",
                new[] { "ACE-BASE", "ACE-CSClient", "ACE-DRV", "AntiCheatExpert", "tersafe" },
                new string[] { },
                "high"),

            ("Themida/WinLicense",
                new[] { "Themida", "WinLicense" },
                new string[] { },
                "medium"),

            ("VMProtect",
                new[] { "VMProtect" },
                new string[] { },
                "medium"),

            ("Denuvo Anti-Cheat",
                new[] { "denuvo", "DenuvoAntiCheat" },
                new string[] { },
                "high"),

            ("PunkBuster",
                new[] { "PnkBstrA", "PnkBstrB", "pbag", "pbcl", "pbsvc" },
                new string[] { },
                "medium"),

            ("Ricochet",
                new[] { "ricochet", "atvi-" },
                new string[] { },
                "high"),

            ("Hyperion (Roblox)",
                new[] { "hyperion", "RobloxPlayerBeta" },
                new string[] { },
                "medium"),

            ("Unity Runtime Protection",
                new[] { "UnityAntiCheat", "unity_anticheat" },
                new string[] { },
                "low"),
        };

        public static DetectionResult Detect(IMemoryReader driver, int pid)
        {
            var result = new DetectionResult();

            // Phase 1: Module scanning
            if (driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
            {
                ScanModules(modules, result);
            }

            // Phase 2: Kernel callback enumeration (if available)
            try
            {
                var (callbackCount, removedCount, callbacks) = driver.EnumKernelCallbacks(false);
                result.TotalCallbacksFound = callbackCount;
                result.HasKernelCallbacks = callbackCount > 0;

                if (callbacks != null)
                {
                    ScanCallbacks(callbacks, result);
                }
            }
            catch { }

            // Phase 3: Driver enumeration
            try
            {
                var drivers = driver.EnumerateDrivers();
                if (drivers != null)
                {
                    ScanDrivers(drivers, result);
                }
            }
            catch { }

            // Phase 4: Memory pattern scanning for hidden anti-cheat
            ScanMemoryPatterns(driver, pid, modules, result);

            // Build summary
            result.Summary = BuildSummary(result);

            return result;
        }

        private static void ScanModules(ModuleSummary[] modules, DetectionResult result)
        {
            foreach (var ac in KnownAntiCheats)
            {
                var info = new AntiCheatInfo { Name = ac.name, Severity = ac.severity };

                foreach (var mod in modules)
                {
                    string modName = mod.ModuleName ?? mod.FileName ?? "";
                    string modLower = modName.ToLowerInvariant();

                    foreach (var pattern in ac.modulePatterns)
                    {
                        if (modLower.Contains(pattern.ToLowerInvariant()))
                        {
                            info.Detected = true;
                            info.Evidence.Add($"Module: {modName}");
                            info.Modules.Add(new ModuleMatch
                            {
                                ModuleName = modName,
                                BaseAddress = mod.BaseAddress,
                                ImageSize = mod.ImageSize
                            });
                            break;
                        }
                    }
                }

                if (info.Detected)
                    result.DetectedAntiCheats.Add(info);
            }

            // Scan for suspicious/unknown modules
            string[] suspiciousPatterns = { "anticheat", "anti_cheat", "guard", "protect",
                "shield", "secure", "monitor", "detect", "integrity", "tamper" };

            foreach (var mod in modules)
            {
                string modName = (mod.ModuleName ?? mod.FileName ?? "").ToLowerInvariant();
                foreach (var pat in suspiciousPatterns)
                {
                    if (modName.Contains(pat))
                    {
                        bool alreadyKnown = result.DetectedAntiCheats
                            .Any(ac => ac.Modules.Any(m =>
                                m.ModuleName.Equals(mod.ModuleName, StringComparison.OrdinalIgnoreCase)));
                        if (!alreadyKnown)
                        {
                            result.SuspiciousModules.Add($"{mod.ModuleName} @ 0x{mod.BaseAddress:X} ({mod.ImageSize:N0} bytes)");
                        }
                        break;
                    }
                }
            }
        }

        private static void ScanCallbacks(CallbackEntry[] callbacks, DetectionResult result)
        {
            foreach (var cb in callbacks)
            {
                string driverName = cb.DriverName ?? "";
                string driverLower = driverName.ToLowerInvariant();

                foreach (var ac in KnownAntiCheats)
                {
                    foreach (var pattern in ac.modulePatterns)
                    {
                        if (driverLower.Contains(pattern.ToLowerInvariant()))
                        {
                            var existing = result.DetectedAntiCheats.FirstOrDefault(a => a.Name == ac.name);
                            if (existing == null)
                            {
                                existing = new AntiCheatInfo { Name = ac.name, Severity = ac.severity, Detected = true };
                                result.DetectedAntiCheats.Add(existing);
                            }

                            string cbType = cb.CallbackType == 0 ? "Process" : cb.CallbackType == 1 ? "LoadImage" : "Thread";
                            existing.Evidence.Add($"Kernel callback ({cbType}): {driverName}");
                            existing.Callbacks.Add(new CallbackMatch
                            {
                                Type = cbType,
                                Address = cb.CallbackAddress,
                                DriverName = driverName
                            });
                            break;
                        }
                    }
                }
            }
        }

        private static void ScanDrivers(
            List<(string basePath, string baseName, ulong baseAddress, uint imageSize, uint flags, DateTime loadTime, ulong entryPoint, uint checkSum)> drivers,
            DetectionResult result)
        {
            foreach (var drv in drivers)
            {
                string drvName = (drv.baseName ?? drv.basePath ?? "").ToLowerInvariant();

                foreach (var ac in KnownAntiCheats)
                {
                    foreach (var pattern in ac.modulePatterns)
                    {
                        if (drvName.Contains(pattern.ToLowerInvariant()))
                        {
                            var existing = result.DetectedAntiCheats.FirstOrDefault(a => a.Name == ac.name);
                            if (existing == null)
                            {
                                existing = new AntiCheatInfo { Name = ac.name, Severity = ac.severity, Detected = true };
                                result.DetectedAntiCheats.Add(existing);
                            }
                            existing.Evidence.Add($"Kernel driver: {drv.baseName} @ 0x{drv.baseAddress:X}");
                            break;
                        }
                    }
                }
            }
        }

        private static void ScanMemoryPatterns(IMemoryReader driver, int pid, ModuleSummary[] modules, DetectionResult result)
        {
            if (modules == null) return;

            // Look for anti-debug checks by scanning for common API patterns
            string[] antiDebugApis = { "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
                "NtQueryInformationProcess", "OutputDebugString" };

            foreach (var mod in modules)
            {
                string modName = (mod.ModuleName ?? "").ToLowerInvariant();
                if (modName != "gameassembly.dll" && modName != "unityplayer.dll" &&
                    !modName.Contains("assembly") && !modName.Contains("mono"))
                    continue;

                var exports = driver.GetExportMap(pid);
                if (exports == null) continue;

                foreach (var kvp in exports)
                {
                    foreach (var api in antiDebugApis)
                    {
                        if (kvp.Value.funcName != null &&
                            kvp.Value.funcName.IndexOf(api, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            var existing = result.DetectedAntiCheats.FirstOrDefault(a => a.Name == "Custom Anti-Debug");
                            if (existing == null)
                            {
                                existing = new AntiCheatInfo
                                {
                                    Name = "Custom Anti-Debug",
                                    Severity = "low",
                                    Detected = true
                                };
                                result.DetectedAntiCheats.Add(existing);
                            }
                            existing.Evidence.Add($"Import: {api} in {mod.ModuleName}");
                            break;
                        }
                    }
                }

                break;
            }
        }

        private static string BuildSummary(DetectionResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Anti-Cheat Detection Report");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();

            if (result.DetectedAntiCheats.Count == 0)
            {
                sb.AppendLine("No known anti-cheat solutions detected.");
            }
            else
            {
                sb.AppendLine($"Detected {result.DetectedAntiCheats.Count} anti-cheat solution(s):");
                sb.AppendLine();

                foreach (var ac in result.DetectedAntiCheats.OrderByDescending(a => a.Severity))
                {
                    sb.AppendLine($"  [{ac.Severity.ToUpper()}] {ac.Name}");
                    foreach (var e in ac.Evidence)
                        sb.AppendLine($"    - {e}");
                    sb.AppendLine();
                }
            }

            if (result.SuspiciousModules.Count > 0)
            {
                sb.AppendLine("Suspicious modules (not matched to known anti-cheat):");
                foreach (var m in result.SuspiciousModules)
                    sb.AppendLine($"  - {m}");
                sb.AppendLine();
            }

            if (result.HasKernelCallbacks)
                sb.AppendLine($"Kernel callbacks found: {result.TotalCallbacksFound}");

            return sb.ToString();
        }
    }
}
