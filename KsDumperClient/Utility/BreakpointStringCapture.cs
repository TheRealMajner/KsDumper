using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public class BreakpointStringCapture : IDisposable
    {
        public struct CapturedString
        {
            public ulong Address;
            public string Value;
            public string Method;
            public DateTime Timestamp;
        }

        public struct BreakpointInfo
        {
            public ulong Address;
            public string MethodName;
            public bool IsActive;
        }

        public event Action<CapturedString> OnStringCaptured;
        public event Action<string> OnLog;

        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly Dictionary<ulong, (byte originalByte, string methodName)> breakpoints;
        private readonly List<CapturedString> capturedStrings;
        private readonly object syncLock;
        private CancellationTokenSource cts;
        private bool isCapturing;
        private bool isAttached;
        private IntPtr processHandle;

        public bool IsCapturing => isCapturing;
        public bool IsAttached => isAttached;

        public BreakpointStringCapture(IMemoryReader driver, int processId)
        {
            this.driver = driver;
            this.processId = processId;
            breakpoints = new Dictionary<ulong, (byte, string)>();
            capturedStrings = new List<CapturedString>();
            syncLock = new object();
        }

        public List<BreakpointInfo> GetBreakpoints()
        {
            var result = new List<BreakpointInfo>();
            lock (syncLock)
            {
                foreach (var kvp in breakpoints)
                    result.Add(new BreakpointInfo { Address = kvp.Key, MethodName = kvp.Value.methodName, IsActive = true });
            }
            return result;
        }

        public List<CapturedString> GetCapturedStrings()
        {
            lock (syncLock) return new List<CapturedString>(capturedStrings);
        }

        public bool AttachDebugger()
        {
            if (isAttached) return true;

            processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
            if (processHandle == IntPtr.Zero)
            {
                // Try with reduced rights
                processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | 0x00080000, false, processId);
                if (processHandle == IntPtr.Zero)
                {
                    Log("Failed to open process for debugging (access denied)");
                    return false;
                }
            }

            if (!DebugActiveProcess((uint)processId))
            {
                Log("DebugActiveProcess failed (error: {0})", Marshal.GetLastWin32Error());
                CloseHandle(processHandle);
                processHandle = IntPtr.Zero;
                return false;
            }

            // Don't kill the process when debugger detaches
            DebugSetProcessKillOnExit(false);

            isAttached = true;
            Log("Debugger attached to PID {0}", processId);
            return true;
        }

        public void SetBreakpoint(ulong address, string methodName)
        {
            if (!isAttached || processHandle == IntPtr.Zero)
            {
                Log("Not attached to debugger");
                return;
            }

            byte[] original = new byte[1];
            IntPtr buf = Marshal.AllocHGlobal(1);
            try
            {
                if (!ReadProcessMemory(processHandle, (IntPtr)address, buf, 1, out _))
                {
                    Log("Failed to read memory at 0x{0:X} for breakpoint", address);
                    return;
                }
                Marshal.Copy(buf, original, 0, 1);

                // Write INT3 (0xCC)
                byte[] int3 = new byte[] { 0xCC };
                IntPtr writeBuf = Marshal.AllocHGlobal(1);
                Marshal.Copy(int3, 0, writeBuf, 1);

                uint oldProtect;
                VirtualProtectEx(processHandle, (IntPtr)address, 1, 0x40, out oldProtect); // PAGE_EXECUTE_READWRITE
                if (!WriteProcessMemory(processHandle, (IntPtr)address, writeBuf, 1, out _))
                {
                    Log("Failed to write breakpoint at 0x{0:X}", address);
                    Marshal.FreeHGlobal(writeBuf);
                    return;
                }
                VirtualProtectEx(processHandle, (IntPtr)address, 1, oldProtect, out _);
                Marshal.FreeHGlobal(writeBuf);

                lock (syncLock)
                    breakpoints[address] = (original[0], methodName);

                Log("Breakpoint set at 0x{0:X} ({1})", address, methodName);
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        public void SetBreakpointByName(string dllName, string functionName)
        {
            if (!isAttached) return;

            // Get module base from driver
            if (driver.GetModuleSummaryList(processId, out var modules))
            {
                foreach (var mod in modules)
                {
                    if (mod.ModuleName.Equals(dllName, StringComparison.OrdinalIgnoreCase))
                    {
                        // Get export map to find function address
                        var exportMap = driver.GetExportMap(processId);
                        foreach (var kvp in exportMap)
                        {
                            if (kvp.Value.dllName.Equals(dllName, StringComparison.OrdinalIgnoreCase) &&
                                kvp.Value.funcName.Equals(functionName, StringComparison.OrdinalIgnoreCase))
                            {
                                SetBreakpoint(kvp.Key, $"{dllName}!{functionName}");
                                return;
                            }
                        }
                        break;
                    }
                }
            }
            Log("Could not find {0}!{1}", dllName, functionName);
        }

        public void AutoDetectDecryptionFunctions()
        {
            if (!isAttached) return;

            try
            {
                Log("Auto-detecting decryption functions...");

                // Read the main module's .text section
                if (!driver.GetModuleSummaryList(processId, out var modules) || modules.Length == 0)
                {
                    Log("No modules found");
                    return;
                }

                var mainModule = modules[0];
                byte[] peHeader = ReadBytes(mainModule.BaseAddress, 0x400);
                if (peHeader == null || peHeader.Length < 64) return;

                if (BitConverter.ToUInt16(peHeader, 0) != 0x5A4D) return;
                int e_lfanew = BitConverter.ToInt32(peHeader, 60);
                if (e_lfanew + 24 > peHeader.Length) return;

                ushort numSections = BitConverter.ToUInt16(peHeader, e_lfanew + 6);
                ushort sizeOfOptHdr = BitConverter.ToUInt16(peHeader, e_lfanew + 20);
                int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

                for (int s = 0; s < numSections; s++)
                {
                    int secOff = sectionTableOff + s * 40;
                    if (secOff + 40 > peHeader.Length) break;

                    uint virtualSize = BitConverter.ToUInt32(peHeader, secOff + 8);
                    uint virtualAddr = BitConverter.ToUInt32(peHeader, secOff + 12);
                    uint characteristics = BitConverter.ToUInt32(peHeader, secOff + 36);
                    if ((characteristics & 0x20) == 0) continue; // Not a code section

                    int readSize = (int)Math.Min(virtualSize, 0x10000);
                    byte[] codeData = ReadBytes(mainModule.BaseAddress + virtualAddr, readSize);
                    if (codeData == null) continue;

                    var patterns = StringDecryptor.FindDecryptorPatterns(codeData, mainModule.BaseAddress + virtualAddr);
                    int added = 0;
                    foreach (var p in patterns)
                    {
                        if (added >= 10) break; // Limit auto-detected breakpoints
                        SetBreakpoint(p.Address, p.PatternName);
                        added++;
                    }
                    if (added > 0)
                        Log("Auto-detected {0} decryption patterns in .text", added);
                    break;
                }

                // Also hook common crypto APIs by name
                string[][] cryptoApis = new[]
                {
                    new[] { "advapi32.dll", "CryptDecrypt" },
                    new[] { "advapi32.dll", "CryptEncrypt" },
                    new[] { "bcrypt.dll", "BCryptDecrypt" },
                    new[] { "bcrypt.dll", "BCryptEncrypt" },
                    new[] { "ncrypt.dll", "NCryptDecrypt" },
                };

                foreach (var api in cryptoApis)
                    SetBreakpointByName(api[0], api[1]);
            }
            catch (Exception ex)
            {
                Log("Auto-detect error: {0}", ex.Message);
            }
        }

        public void StartCapturing()
        {
            if (!isAttached || isCapturing) return;
            cts = new CancellationTokenSource();
            isCapturing = true;
            Task.Run(() => DebugEventLoop());
            Log("Breakpoint capture started");
        }

        public void StopCapturing()
        {
            if (!isCapturing) return;
            cts?.Cancel();
            isCapturing = false;

            // Restore all breakpoints
            RestoreAllBreakpoints();
            Log("Breakpoint capture stopped, {0} strings captured", capturedStrings.Count);
        }

        private void DebugEventLoop()
        {
            try
            {
            while (!cts.IsCancellationRequested)
            {
                DEBUG_EVENT debugEvent;
                if (!WaitForDebugEvent(out debugEvent, 100))
                    continue;

                uint continueStatus = 0x00010002; // DBG_CONTINUE

                if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
                {
                    var exInfo = debugEvent.Exception;
                    if (exInfo.ExceptionRecord.ExceptionCode == 0x80000003) // STATUS_BREAKPOINT
                    {
                        ulong bpAddr = (ulong)exInfo.ExceptionRecord.ExceptionAddress.ToInt64();

                        (byte originalByte, string methodName) bp;
                        bool found = false;
                        lock (syncLock)
                            found = breakpoints.TryGetValue(bpAddr, out bp);

                        if (found)
                        {
                            // Get thread context to read registers
                            IntPtr threadHandle = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, debugEvent.dwThreadId);
                            if (threadHandle != IntPtr.Zero)
                            {
                                try
                                {
                                    // Allocate 2048-byte buffer for CONTEXT (larger than the 1232-byte x64 CONTEXT)
                                    IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                                    // Zero the buffer
                                    for (int zi = 0; zi < 2048; zi++) Marshal.WriteByte(ctxPtr, zi, 0);
                                    // Set ContextFlags at offset 48 (after P1Home-P6Home)
                                    // CONTEXT_INTEGER = 0x100000, CONTEXT_CONTROL = 0x00000002
                                    Marshal.WriteInt32(ctxPtr, 48, 0x100002);

                                    if (GetThreadContext(threadHandle, ctxPtr))
                                    {
                                        // Register offsets in CONTEXT_AMD64 (after home space + context flags + mxcsr + segments + eflags + debug regs):
                                        // Home(48) + CtxFlags(4) + MxCsr(4) + Segs(12) + EFlags(4) + Dr0-Dr7(48) = 120
                                        // Rax=120, Rcx=128, Rdx=136, Rbx=144, Rsp=152, Rbp=160, Rsi=168, Rdi=176
                                        // R8=184, R9=192, R10=200, R11=208, R12=216, R13=224, R14=232, R15=240
                                        // Rip=248
                                        ulong rRcx = (ulong)Marshal.ReadInt64(ctxPtr, 128);
                                        ulong rRdx = (ulong)Marshal.ReadInt64(ctxPtr, 136);
                                        ulong rR8  = (ulong)Marshal.ReadInt64(ctxPtr, 184);
                                        ulong rRsp = (ulong)Marshal.ReadInt64(ctxPtr, 152);

                                        // x64 calling convention: RCX, RDX, R8, R9 are first 4 args
                                        TryCaptureString(rRcx, bp.methodName);
                                        TryCaptureString(rRdx, bp.methodName);
                                        TryCaptureString(rR8, bp.methodName);

                                        // For CryptDecrypt: pbData is at [rsp+0x28] (5th param)
                                        // Read stack to find buffer pointer
                                        if (rRsp > 0)
                                        {
                                            byte[] stackBuf = ReadBytes(rRsp, 0x100);
                                            if (stackBuf != null && stackBuf.Length >= 0x30)
                                            {
                                                // 5th param at RSP+0x20 (after return addr at +0x00, plus shadow space)
                                                ulong bufPtr = BitConverter.ToUInt64(stackBuf, 0x28);
                                                if (bufPtr > 0x10000) TryCaptureString(bufPtr, bp.methodName);

                                                ulong bufPtr2 = BitConverter.ToUInt64(stackBuf, 0x20);
                                                if (bufPtr2 > 0x10000) TryCaptureString(bufPtr2, bp.methodName);
                                            }
                                        }
                                    }

                                    // Restore original byte, step over, re-set breakpoint
                                    RestoreBreakpoint(bpAddr, bp.originalByte);

                                    // Set single-step flag (TF bit) at EFlags offset (48+4+4+12 = 68)
                                    int eflagsOffset = 68;
                                    int eflags = Marshal.ReadInt32(ctxPtr, eflagsOffset);
                                    eflags |= 0x100; // TF (Trap Flag)
                                    Marshal.WriteInt32(ctxPtr, eflagsOffset, eflags);
                                    SetThreadContext(threadHandle, ctxPtr);

                                    Marshal.FreeHGlobal(ctxPtr);

                                    // We'll re-set the breakpoint after single step
                                    // For simplicity, skip re-setting in this loop
                                }
                                catch (Exception ex) { Log("Thread context error: {0}", ex.Message); }
                                finally { CloseHandle(threadHandle); }
                            }
                        }
                    }
                    else if (exInfo.ExceptionRecord.ExceptionCode == 0x80000004) // STATUS_SINGLE_STEP
                    {
                        // Single step completed - could re-set breakpoints here
                    }
                }
                else if (debugEvent.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT)
                {
                    Log("Target process exited");
                    isCapturing = false;
                    isAttached = false;
                    break;
                }

                ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
            }
            }
            catch (Exception ex) { Log("Debug event loop error: {0}", ex.Message); }

            isCapturing = false;
        }

        private void TryCaptureString(ulong bufferAddress, string methodName)
        {
            if (bufferAddress < 0x10000 || bufferAddress > 0x7FFFFFFFFFFF) return;

            byte[] buf = ReadBytes(bufferAddress, 512);
            if (buf == null) return;

            // Try ASCII
            int runStart = -1;
            for (int i = 0; i < buf.Length; i++)
            {
                bool printable = buf[i] >= 0x20 && buf[i] < 0x7F;
                if (printable)
                {
                    if (runStart < 0) runStart = i;
                }
                else
                {
                    if (runStart >= 0)
                    {
                        int len = i - runStart;
                        if (len >= 4)
                        {
                            string value = Encoding.ASCII.GetString(buf, runStart, len);
                            if (ScoreText(value) >= 0.5)
                            {
                                var cs = new CapturedString
                                {
                                    Address = bufferAddress + (ulong)runStart,
                                    Value = value,
                                    Method = methodName,
                                    Timestamp = DateTime.Now
                                };
                                lock (syncLock) capturedStrings.Add(cs);
                                try { OnStringCaptured?.Invoke(cs); } catch { }
                                return;
                            }
                        }
                        runStart = -1;
                    }
                    if (i > 32) break; // Only check first 32 bytes for string start
                }
            }

            // Try Unicode
            runStart = -1;
            int charCount = 0;
            for (int i = 0; i < buf.Length - 1; i += 2)
            {
                ushort ch = BitConverter.ToUInt16(buf, i);
                bool printable = ch >= 0x20 && ch < 0x7F;
                if (printable)
                {
                    if (runStart < 0) { runStart = i; charCount = 0; }
                    charCount++;
                }
                else
                {
                    if (charCount >= 4)
                    {
                        string value = Encoding.Unicode.GetString(buf, runStart, charCount * 2);
                        if (ScoreText(value) >= 0.5)
                        {
                            var cs = new CapturedString
                            {
                                Address = bufferAddress + (ulong)runStart,
                                Value = value,
                                Method = methodName + " (Unicode)",
                                Timestamp = DateTime.Now
                            };
                            lock (syncLock) capturedStrings.Add(cs);
                            try { OnStringCaptured?.Invoke(cs); } catch { }
                            return;
                        }
                    }
                    runStart = -1;
                    charCount = 0;
                    if (i > 64) break;
                }
            }
        }

        private void RestoreAllBreakpoints()
        {
            lock (syncLock)
            {
                foreach (var kvp in breakpoints)
                    RestoreBreakpoint(kvp.Key, kvp.Value.originalByte);
                breakpoints.Clear();
            }
        }

        private void RestoreBreakpoint(ulong address, byte originalByte)
        {
            if (processHandle == IntPtr.Zero) return;
            IntPtr ptr = Marshal.AllocHGlobal(1);
            try
            {
                byte[] buf = new byte[] { originalByte };
                Marshal.Copy(buf, 0, ptr, 1);
                uint oldProtect;
                VirtualProtectEx(processHandle, (IntPtr)address, 1, 0x40, out oldProtect);
                WriteProcessMemory(processHandle, (IntPtr)address, ptr, 1, out _);
                VirtualProtectEx(processHandle, (IntPtr)address, 1, oldProtect, out _);
            }
            finally { Marshal.FreeHGlobal(ptr); }
        }

        private byte[] ReadBytes(ulong address, int size)
        {
            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, buf, size)) return null;
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private static double ScoreText(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4) return 0;
            int good = 0;
            foreach (char c in s)
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == ' ' || ".,;:!?/\\-_()[]{}@#$%&*+=<>".IndexOf(c) >= 0) good++;
            return (double)good / s.Length;
        }

        private void Log(string message, params object[] args)
        {
            try { OnLog?.Invoke(string.Format(message, args)); } catch { }
        }

        public void Dispose()
        {
            try { StopCapturing(); } catch { }
            if (isAttached)
            {
                try { RestoreAllBreakpoints(); } catch { }
                try { DebugActiveProcessStop((uint)processId); } catch { }
                isAttached = false;
            }
            if (processHandle != IntPtr.Zero)
            {
                try { CloseHandle(processHandle); } catch { }
                processHandle = IntPtr.Zero;
            }
        }

        // ===== P/Invoke =====

        private const uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        private const uint PROCESS_VM_READ = 0x0010;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint THREAD_GET_CONTEXT = 0x0008;
        private const uint THREAD_SET_CONTEXT = 0x0010;
        private const uint THREAD_QUERY_INFORMATION = 0x0040;

        private const uint EXCEPTION_DEBUG_EVENT = 1;
        private const uint EXIT_PROCESS_DEBUG_EVENT = 5;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DebugActiveProcess(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DebugActiveProcessStop(uint dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool DebugSetProcessKillOnExit(bool KillOnExit);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WaitForDebugEvent(out DEBUG_EVENT lpDebugEvent, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ContinueDebugEvent(uint dwProcessId, uint dwThreadId, uint dwContinueStatus);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct DEBUG_EVENT
        {
            public uint dwDebugEventCode;
            public uint dwProcessId;
            public uint dwThreadId;
            public uint dwSize;
            public EXCEPTION_DEBUG_INFO Exception;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXCEPTION_DEBUG_INFO
        {
            public EXCEPTION_RECORD ExceptionRecord;
            public uint dwFirstChance;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct EXCEPTION_RECORD
        {
            public uint ExceptionCode;
            public uint ExceptionFlags;
            public IntPtr ExceptionRecord;
            public IntPtr ExceptionAddress;
            public uint NumberParameters;
            // ExceptionInformation omitted for simplicity
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct CONTEXT_AMD64
        {
            // Home space (6 * 8 = 48 bytes)
            public ulong P1Home, P2Home, P3Home, P4Home, P5Home, P6Home;
            // Control flags (8 bytes)
            public uint ContextFlags;
            public uint MxCsr;
            // Segment registers (12 bytes)
            public ushort SegCs, SegDs, SegEs, SegFs, SegGs, SegSs;
            // EFlags (4 bytes)
            public uint EFlags;
            // Debug registers (48 bytes)
            public ulong Dr0, Dr1, Dr2, Dr3, Dr6, Dr7;
            // Integer registers (128 bytes): Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi, R8-R15
            public ulong Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi;
            public ulong R8, R9, R10, R11, R12, R13, R14, R15;
            // Instruction pointer
            public ulong Rip;
            // Padding for XMM registers, vector state, debug control, etc.
            // Total CONTEXT size is 1232 bytes on x64
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 992)]
            public byte[] Padding;
        }
    }
}
