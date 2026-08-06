using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using ModelContextProtocol.Server;
using KsDumperClient;
using KsDumperClient.Driver;
using KsDumperClient.DotNet;

namespace KsMcpServer.Tools
{
    [McpServerToolType]
    public class DeobfuscationTools
    {
        private readonly IMemoryReader _driver;

        public DeobfuscationTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Analyzes a .NET assembly module for obfuscation protections. Detects: CLR constructor, virtualization, call encryption, anti-ILDASM, math mutations, anti-dnSpy, anti-debug, control flow obfuscation, string encryption. Also guesses the obfuscator used.")]
        public string AnalyzeObfuscation(int pid, string moduleName = "")
        {
            try
            {
                byte[] peBytes = ReadModuleBytes(pid, moduleName, out string resolvedName, out ulong baseAddr);
                if (peBytes == null)
                    return $"Failed to read module '{moduleName}' from PID {pid}.";

                var report = DotNetDeobfuscator.AnalyzeProtection(peBytes);

                var sb = new StringBuilder();
                sb.AppendLine($"Obfuscation Analysis: {resolvedName} (PID {pid})");
                sb.AppendLine($"Base: 0x{baseAddr:X16}  Size: {peBytes.Length:N0} bytes");
                sb.AppendLine(new string('=', 60));
                sb.AppendLine();

                sb.AppendLine($"Protection score: {report.ProtectionScore}/100");
                sb.AppendLine($"Obfuscator guess: {report.ObfuscatorGuess}");
                sb.AppendLine();

                sb.AppendLine("Detections:");
                sb.AppendLine($"  Module .cctor:       {Yn(report.HasModuleCctor)}");
                sb.AppendLine($"  Anti-ILDASM:         {Yn(report.HasAntiIldasm)}");
                sb.AppendLine($"  Call encryption:     {Yn(report.HasCallEncryption)}");
                sb.AppendLine($"  Math mutations:      {Yn(report.HasMathMutations)}");
                sb.AppendLine($"  Virtualization:      {Yn(report.HasVirtualization)}");
                sb.AppendLine($"  Anti-dnSpy:          {Yn(report.HasAntiDnSpy)}");
                sb.AppendLine($"  Anti-debug:          {Yn(report.HasAntiDebug)}");
                sb.AppendLine($"  Control flow obf:    {Yn(report.HasControlFlow)}");
                sb.AppendLine($"  String encryption:   {Yn(report.HasStringEncryption)}");
                sb.AppendLine();

                if (report.Detections != null && report.Detections.Length > 0)
                {
                    sb.AppendLine("Details:");
                    foreach (string det in report.Detections)
                        sb.AppendLine($"  - {det}");
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"Analysis failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Patches ALL detected obfuscation protections on a .NET module and saves the cleaned version. Applies: anti-ILDASM removal, anti-dnSpy fixes, module .cctor neutralization, anti-debug bypass, control flow cleanup, math mutation folding, call proxy inlining, string encryption neutralization. The patched file can be opened in dnSpy/ILSpy.")]
        public string PatchAndDump(int pid, string moduleName = "", string outputPath = "")
        {
            try
            {
                byte[] peBytes = ReadModuleBytes(pid, moduleName, out string resolvedName, out ulong baseAddr);
                if (peBytes == null)
                    return $"Failed to read module from PID {pid}.";

                var sb = new StringBuilder();
                sb.AppendLine($"Patching: {resolvedName} (PID {pid})");
                sb.AppendLine(new string('-', 50));

                int totalPatches = 0;

                // Run all patchers in order (order matters: proxies before control flow)
                var patchers = new (string label, Func<byte[], DotNetDeobfuscator.PatchResult> fn)[]
                {
                    ("Anti-ILDASM",      DotNetDeobfuscator.PatchAntiIldasm),
                    ("Anti-dnSpy",       DotNetDeobfuscator.PatchAntiDnSpy),
                    ("Module .cctor",    DotNetDeobfuscator.PatchModuleCctor),
                    ("Anti-Debug",       DotNetDeobfuscator.PatchAntiDebug),
                    ("Call Proxies",     DotNetDeobfuscator.PatchCallProxies),
                    ("Math Mutations",   DotNetDeobfuscator.PatchMathMutations),
                    ("Control Flow",     DotNetDeobfuscator.PatchControlFlow),
                    ("String Encrypt",   DotNetDeobfuscator.PatchStringEncryption),
                };

                foreach (var (label, fn) in patchers)
                {
                    var result = fn(peBytes);
                    if (result.Success)
                    {
                        foreach (string desc in result.PatchDescriptions)
                            sb.AppendLine($"  [{label}] {desc}");
                        totalPatches += result.PatchCount;
                    }
                }

                if (string.IsNullOrEmpty(outputPath))
                    outputPath = Path.Combine(Path.GetTempPath(), $"{resolvedName}_cleaned.dll");

                File.WriteAllBytes(outputPath, peBytes);

                sb.AppendLine();
                sb.AppendLine($"Total patches applied: {totalPatches}");
                sb.AppendLine($"Cleaned file: {outputPath}");
                sb.AppendLine($"Size: {peBytes.Length:N0} bytes");

                if (totalPatches == 0)
                    sb.AppendLine("\nNo standard patches needed — the module may use non-standard protections.");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"Patch failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Patches a .NET module's CLR constructor (.cctor) to prevent runtime unpacking/decryption code from running. Replaces the <Module>.cctor body with a 'ret' instruction. Use this when the .cctor decrypts methods or loads encrypted resources at startup.")]
        public string PatchModuleCctor(int pid, string moduleName = "", string outputPath = "")
        {
            try
            {
                byte[] peBytes = ReadModuleBytes(pid, moduleName, out string resolvedName, out ulong baseAddr);
                if (peBytes == null)
                    return $"Failed to read module from PID {pid}.";

                var result = DotNetDeobfuscator.PatchModuleCctor(peBytes);

                if (!result.Success)
                    return $"Module .cctor patch: {result.Error}";

                if (string.IsNullOrEmpty(outputPath))
                    outputPath = Path.Combine(Path.GetTempPath(), $"{resolvedName}_no_cctor.dll");

                File.WriteAllBytes(outputPath, peBytes);

                var sb = new StringBuilder();
                sb.AppendLine("Module .cctor neutralized:");
                foreach (string desc in result.PatchDescriptions)
                    sb.AppendLine($"  {desc}");
                sb.AppendLine($"Saved: {outputPath}");
                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"PatchModuleCctor failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Dumps a .NET module from memory AFTER the runtime has decrypted it. Many obfuscators decrypt method bodies at runtime via the .cctor — this dumps the in-memory (decrypted) version. Applies ALL deobfuscation patches automatically.")]
        public string DumpDecryptedModule(int pid, string moduleName = "", bool applyPatches = true, string outputPath = "")
        {
            try
            {
                byte[] peBytes = ReadModuleBytes(pid, moduleName, out string resolvedName, out ulong baseAddr);
                if (peBytes == null)
                    return $"Failed to read module from PID {pid}.";

                var sb = new StringBuilder();
                sb.AppendLine($"Dumped {resolvedName} from memory (runtime-decrypted state)");
                sb.AppendLine($"  Base: 0x{baseAddr:X16}  Size: {peBytes.Length:N0} bytes");

                if (applyPatches)
                {
                    var report = DotNetDeobfuscator.AnalyzeProtection(peBytes);
                    sb.AppendLine($"  Protection score: {report.ProtectionScore}/100 ({report.ObfuscatorGuess})");

                    int patchCount = 0;
                    var patchers = new Func<byte[], DotNetDeobfuscator.PatchResult>[]
                    {
                        DotNetDeobfuscator.PatchAntiIldasm,
                        DotNetDeobfuscator.PatchAntiDnSpy,
                        DotNetDeobfuscator.PatchModuleCctor,
                        DotNetDeobfuscator.PatchAntiDebug,
                        DotNetDeobfuscator.PatchCallProxies,
                        DotNetDeobfuscator.PatchMathMutations,
                        DotNetDeobfuscator.PatchControlFlow,
                        DotNetDeobfuscator.PatchStringEncryption,
                    };

                    foreach (var fn in patchers)
                    {
                        var r = fn(peBytes);
                        patchCount += r.PatchCount;
                    }

                    sb.AppendLine($"  Applied {patchCount} deobfuscation patches");
                }

                if (string.IsNullOrEmpty(outputPath))
                    outputPath = Path.Combine(Path.GetTempPath(), $"{resolvedName}_decrypted.dll");

                File.WriteAllBytes(outputPath, peBytes);
                sb.AppendLine($"  Saved: {outputPath}");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"DumpDecrypted failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Resolves call proxy delegates in a .NET module. Finds tiny methods that just forward to another method (proxy pattern used by ConfuserEx, .NET Reactor) and inlines all call sites to point directly to the real target.")]
        public string PatchCallProxies(int pid, string moduleName = "", string outputPath = "")
        {
            return RunSinglePatch(pid, moduleName, outputPath, "call_proxies_fixed",
                DotNetDeobfuscator.PatchCallProxies, "PatchCallProxies");
        }

        [McpServerTool, Description("Folds math mutation chains in a .NET module. Replaces obfuscated constant expressions like (5 * 3 + 2 ^ 7) with their computed result. Handles ldc.i4 chains with add/sub/mul/div/xor. Multi-pass for cascading folds.")]
        public string PatchMathMutations(int pid, string moduleName = "", string outputPath = "")
        {
            return RunSinglePatch(pid, moduleName, outputPath, "math_cleaned",
                DotNetDeobfuscator.PatchMathMutations, "PatchMathMutations");
        }

        [McpServerTool, Description("Simplifies control flow obfuscation in a .NET module. Cleans ConfuserEx-style switch dispatch patterns, removes dead branches (br.s +0), and identifies switch-based dispatch loops.")]
        public string PatchControlFlow(int pid, string moduleName = "", string outputPath = "")
        {
            return RunSinglePatch(pid, moduleName, outputPath, "cflow_cleaned",
                DotNetDeobfuscator.PatchControlFlow, "PatchControlFlow");
        }

        [McpServerTool, Description("Identifies and neutralizes string decryption in a .NET module. Finds the most-called static decryptor method, logs all encrypted string call sites with their keys, and replaces the decryptor body to return empty string (prevents crashes when dependencies are missing).")]
        public string PatchStringEncryption(int pid, string moduleName = "", string outputPath = "")
        {
            return RunSinglePatch(pid, moduleName, outputPath, "strings_patched",
                DotNetDeobfuscator.PatchStringEncryption, "PatchStringEncryption");
        }

        [McpServerTool, Description("Full runtime deobfuscation: reads live CLR state where the runtime has already decrypted method bodies, strings, and metadata tokens. Much more effective than static patching because the .cctor and JIT have already run. Recovers encrypted method IL, decrypted user strings from the #US heap, resolved metadata tokens, then applies all static patches on top.")]
        public string RuntimeDeobfuscate(int pid, string moduleName = "", string outputPath = "")
        {
            try
            {
                byte[] peBytes = ReadModuleBytes(pid, moduleName, out string resolvedName, out ulong baseAddr);
                if (peBytes == null)
                    return $"Failed to read module from PID {pid}.";

                var rtDeob = new RuntimeDeobfuscator(_driver, pid);
                var logLines = new List<string>();
                var result = rtDeob.DeobfuscateFromRuntime(peBytes, baseAddr,
                    msg => logLines.Add(msg));

                var sb = new StringBuilder();
                sb.AppendLine($"Runtime Deobfuscation: {resolvedName} (PID {pid})");
                sb.AppendLine($"Base: 0x{baseAddr:X16}  Size: {peBytes.Length:N0} bytes");
                sb.AppendLine(new string('=', 60));
                sb.AppendLine();
                sb.AppendLine($"Method bodies recovered:   {result.MethodBodiesRecovered}");
                sb.AppendLine($"Strings recovered:         {result.StringsRecovered}");
                sb.AppendLine($"Encrypted tokens fixed:    {result.TokensFixed}");
                sb.AppendLine($"Static patches applied:    {result.PatchesApplied}");
                sb.AppendLine();

                foreach (string line in logLines)
                    sb.AppendLine($"  {line}");

                int total = result.MethodBodiesRecovered + result.StringsRecovered +
                    result.TokensFixed + result.PatchesApplied;

                if (string.IsNullOrEmpty(outputPath))
                    outputPath = Path.Combine(Path.GetTempPath(), $"{resolvedName}_runtime_deob.dll");

                File.WriteAllBytes(outputPath, peBytes);
                sb.AppendLine();
                sb.AppendLine($"Saved: {outputPath}");
                sb.AppendLine($"Total fixes: {total}");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"Runtime deobfuscation failed: {ex.Message}";
            }
        }

        private string RunSinglePatch(int pid, string moduleName, string outputPath, string suffix,
            Func<byte[], DotNetDeobfuscator.PatchResult> patchFn, string opName)
        {
            try
            {
                byte[] peBytes = ReadModuleBytes(pid, moduleName, out string resolvedName, out ulong baseAddr);
                if (peBytes == null)
                    return $"Failed to read module from PID {pid}.";

                var result = patchFn(peBytes);

                var sb = new StringBuilder();
                sb.AppendLine($"{opName}: {resolvedName}");
                if (result.Success)
                {
                    foreach (string desc in result.PatchDescriptions)
                        sb.AppendLine($"  {desc}");
                }
                else
                {
                    sb.AppendLine($"  {result.Error ?? "No patches applied"}");
                }

                if (result.Success)
                {
                    if (string.IsNullOrEmpty(outputPath))
                        outputPath = Path.Combine(Path.GetTempPath(), $"{resolvedName}_{suffix}.dll");
                    File.WriteAllBytes(outputPath, peBytes);
                    sb.AppendLine($"  Saved: {outputPath}");
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"{opName} failed: {ex.Message}";
            }
        }

        // --- Helpers ---

        private byte[] ReadModuleBytes(int pid, string moduleName, out string resolvedName, out ulong baseAddr)
        {
            resolvedName = "";
            baseAddr = 0;

            if (string.IsNullOrEmpty(moduleName))
            {
                // Use main module
                if (!_driver.GetProcessSummaryList(out ProcessSummary[] procs))
                    return null;
                var proc = procs.FirstOrDefault(p => p.ProcessId == pid);
                if (proc == null) return null;

                resolvedName = proc.ProcessName + ".exe";
                baseAddr = proc.MainModuleBase;
                int size = (int)proc.MainModuleImageSize;
                return ReadMemory(pid, baseAddr, size);
            }
            else
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return null;

                var mod = modules.FirstOrDefault(m =>
                    m.ModuleName != null &&
                    m.ModuleName.IndexOf(moduleName, StringComparison.OrdinalIgnoreCase) >= 0);

                if (mod == null) return null;

                resolvedName = mod.ModuleName;
                baseAddr = mod.BaseAddress;
                int size = (int)mod.ImageSize;
                return ReadMemory(pid, baseAddr, size);
            }
        }

        private byte[] ReadMemory(int pid, ulong address, int size)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                if (!_driver.CopyVirtualMemory(pid, (IntPtr)address, buffer, size))
                    return null;

                byte[] result = new byte[size];
                Marshal.Copy(buffer, result, 0, size);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string Yn(bool val) => val ? "YES" : "no";
    }
}
