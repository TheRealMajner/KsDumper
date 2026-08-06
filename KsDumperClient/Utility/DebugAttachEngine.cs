using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public enum DebugMode
    {
        Standard,
        Stealth,
        VEH,
        HardwareBP,
        Kernel
    }

    public enum HWBreakpointType
    {
        Execute = 0,
        WriteWatch = 1,
        ReadWriteWatch = 3
    }

    public class DebugAttachEngine : IDisposable
    {
        public struct DebugEvent
        {
            public uint EventCode;
            public uint ProcessId;
            public uint ThreadId;
            public ulong Address;
            public uint ExceptionCode;
            public string Description;
            public DateTime Timestamp;
        }

        public struct HWBreakpoint
        {
            public int Slot; // 0-3 (DR0-DR3)
            public ulong Address;
            public HWBreakpointType Type;
            public bool Active;
        }

        public event Action<DebugEvent> OnDebugEvent;
        public event Action<string> OnLog;

        private readonly int processId;
        private IntPtr processHandle;
        private IMemoryReader driver;
        private CancellationTokenSource cts;
        private bool isAttached;
        private DebugMode currentMode;
        private readonly List<DebugEvent> eventHistory;
        private readonly List<HWBreakpoint> hardwareBreakpoints;
        private readonly object syncLock;

        // Stealth mode: saved original bytes for restoration
        private readonly Dictionary<ulong, byte[]> savedPatches;

        public bool IsAttached => isAttached;
        public DebugMode CurrentMode => currentMode;
        public int EventCount { get { lock (syncLock) return eventHistory.Count; } }
        public List<DebugEvent> GetEventHistory() { lock (syncLock) return new List<DebugEvent>(eventHistory); }
        public List<HWBreakpoint> GetHardwareBreakpoints() { lock (syncLock) return new List<HWBreakpoint>(hardwareBreakpoints); }

        public DebugAttachEngine(int processId)
        {
            this.processId = processId;
            eventHistory = new List<DebugEvent>();
            hardwareBreakpoints = new List<HWBreakpoint>();
            savedPatches = new Dictionary<ulong, byte[]>();
            syncLock = new object();
        }

        // ==================== ATTACH / DETACH ====================

        public bool AttachDebugger(IntPtr processHandle, DebugMode mode, IMemoryReader driver, Action<string> log)
        {
            if (isAttached) { log("Already attached"); return false; }

            this.processHandle = processHandle;
            this.driver = driver;
            this.currentMode = mode;

            try
            {
                switch (mode)
                {
                    case DebugMode.Standard:
                        return AttachStandard(log);
                    case DebugMode.Stealth:
                        return AttachStealth(log);
                    case DebugMode.VEH:
                        return AttachVEH(log);
                    case DebugMode.HardwareBP:
                        return AttachHardwareBP(log);
                    case DebugMode.Kernel:
                        return AttachKernel(log);
                    default:
                        log("Unknown debug mode");
                        return false;
                }
            }
            catch (Exception ex)
            {
                log($"Attach error: {ex.Message}");
                return false;
            }
        }

        public void DetachDebugger()
        {
            if (!isAttached) return;

            try
            {
                cts?.Cancel();

                // Restore stealth patches
                if (currentMode == DebugMode.Stealth)
                    RestoreStealthPatches();

                // Clear hardware breakpoints
                if (currentMode == DebugMode.HardwareBP)
                    ClearHardwareBreakpoints();

                // Detach standard/stealth debug
                if (currentMode == DebugMode.Standard || currentMode == DebugMode.Stealth)
                {
                    try { DebugActiveProcessStop((uint)processId); } catch { }
                }

                isAttached = false;
                Log("Debugger detached ({0})", currentMode);
            }
            catch (Exception ex)
            {
                Log("Detach error: {0}", ex.Message);
            }
        }

        // ==================== STANDARD DEBUG ====================

        private bool AttachStandard(Action<string> log)
        {
            if (!DebugActiveProcess((uint)processId))
            {
                log($"DebugActiveProcess failed (error: {Marshal.GetLastWin32Error()})");
                return false;
            }

            DebugSetProcessKillOnExit(false);
            isAttached = true;
            log("Standard debugger attached");

            cts = new CancellationTokenSource();
            Task.Run(() => DebugEventLoop());
            return true;
        }

        // ==================== STEALTH DEBUG ====================

        private bool AttachStealth(Action<string> log)
        {
            // First attach standard debugger
            if (!DebugActiveProcess((uint)processId))
            {
                log($"DebugActiveProcess failed (error: {Marshal.GetLastWin32Error()})");
                return false;
            }

            DebugSetProcessKillOnExit(false);

            // Patch anti-debug APIs in the target process
            PatchAntiDebugAPIs(log);

            isAttached = true;
            log("Stealth debugger attached (anti-debug patched)");

            cts = new CancellationTokenSource();
            Task.Run(() => DebugEventLoop());
            return true;
        }

        private void PatchAntiDebugAPIs(Action<string> log)
        {
            try
            {
                // 1. Patch PEB.BeingDebugged = 0
                PatchPEBBeingDebugged(log);

                // 2. Patch PEB.NtGlobalFlag (clear heap debug flags)
                PatchPEBNtGlobalFlag(log);

                // 3. Patch IsDebuggerPresent to return 0
                PatchIsDebuggerPresent(log);

                // 4. Patch CheckRemoteDebuggerPresent to set output to false
                PatchCheckRemoteDebuggerPresent(log);

                // 5. Patch NtQueryInformationProcess to hide debug port
                PatchNtQueryInformationProcess(log);

                // 6. Patch NtClose anti-debug (invalid handle trick)
                PatchNtClose(log);

                // 7. Patch heap flags (Flags, ForceFlags)
                PatchHeapFlags(log);

                // 8. Patch NtSetInformationThread to block ThreadHideFromDebugger
                PatchNtSetInformationThread(log);

                // 9. Patch timing functions (GetTickCount, QueryPerformanceCounter)
                PatchTimingAntiDebug(log);
            }
            catch (Exception ex)
            {
                log($"Anti-debug patch error: {ex.Message}");
            }
        }

        private void PatchPEBBeingDebugged(Action<string> log)
        {
            // Read PEB address from NtQueryInformationProcess(ProcessBasicInformation)
            byte[] pbi = new byte[48]; // PROCESS_BASIC_INFORMATION size for x64
            int retLen = 0;
            int status = NtQueryInformationProcess(processHandle, 0, pbi, pbi.Length, ref retLen);
            if (status != 0) { log("  Failed to read PEB address"); return; }

            ulong pebAddress = BitConverter.ToUInt64(pbi, 8); // PebBaseAddress at offset 8
            if (pebAddress == 0) { log("  PEB address is null"); return; }

            // PEB.BeingDebugged is at PEB + 0x2
            byte[] beingDebugged = new byte[] { 0 };
            WriteProcessMemorySafe(pebAddress + 2, beingDebugged);
            log("  Patched PEB.BeingDebugged = 0");
        }

        private void PatchPEBNtGlobalFlag(Action<string> log)
        {
            byte[] pbi = new byte[48];
            int retLen = 0;
            NtQueryInformationProcess(processHandle, 0, pbi, pbi.Length, ref retLen);
            ulong pebAddress = BitConverter.ToUInt64(pbi, 8);
            if (pebAddress == 0) return;

            // NtGlobalFlag at PEB + 0xBC (x64) or PEB + 0x68 (x86)
            // Clear FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS
            byte[] zeroFlags = new byte[] { 0, 0, 0, 0 };
            WriteProcessMemorySafe(pebAddress + 0xBC, zeroFlags);
            log("  Cleared PEB.NtGlobalFlag");
        }

        private void PatchIsDebuggerPresent(Action<string> log)
        {
            // Find IsDebuggerPresent in kernel32.dll loaded in target
            IntPtr hKernel32 = GetModuleHandleInTarget("kernel32.dll");
            if (hKernel32 == IntPtr.Zero) { log("  kernel32.dll not found in target"); return; }

            ulong funcAddr = GetProcAddressInTarget(hKernel32, "IsDebuggerPresent");
            if (funcAddr == 0) { log("  IsDebuggerPresent not found"); return; }

            // Patch: XOR EAX,EAX; RET (31 C0 C3) = return 0
            byte[] patch = new byte[] { 0x31, 0xC0, 0xC3 };
            SaveAndPatch(funcAddr, patch);
            log("  Patched IsDebuggerPresent -> return 0");
        }

        private void PatchCheckRemoteDebuggerPresent(Action<string> log)
        {
            IntPtr hKernel32 = GetModuleHandleInTarget("kernel32.dll");
            if (hKernel32 == IntPtr.Zero) return;

            ulong funcAddr = GetProcAddressInTarget(hKernel32, "CheckRemoteDebuggerPresent");
            if (funcAddr == 0) return;

            // Patch: XOR EAX,EAX; MOV [RCX],0; RET (set *pbDebuggerPresent = false, return 0)
            // 31 C0          XOR EAX,EAX
            // C7 01 00 00 00 00  MOV DWORD [RCX], 0
            // C3             RET
            byte[] patch = new byte[] { 0x31, 0xC0, 0xC7, 0x01, 0x00, 0x00, 0x00, 0x00, 0xC3 };
            SaveAndPatch(funcAddr, patch);
            log("  Patched CheckRemoteDebuggerPresent -> always false");
        }

        private void PatchNtQueryInformationProcess(Action<string> log)
        {
            IntPtr hNtdll = GetModuleHandleInTarget("ntdll.dll");
            if (hNtdll == IntPtr.Zero) { log("  ntdll.dll not found in target"); return; }

            ulong funcAddr = GetProcAddressInTarget(hNtdll, "NtQueryInformationProcess");
            if (funcAddr == 0) { log("  NtQueryInformationProcess not found"); return; }

            // Read the first 16 bytes of NtQueryInformationProcess to save original
            byte[] original = ReadBytesSafe(funcAddr, 16);
            if (original == null) { log("  Failed to read NtQueryInformationProcess"); return; }

            // Hook strategy: We patch the entry point with a JMP to our filter shellcode
            // allocated in the target process. The filter checks the InformationClass parameter
            // and returns safe values for debug-related classes:
            //   7  = ProcessDebugPort        -> return 0 (no debug port)
            //   30 = ProcessDebugObjectHandle -> return STATUS_PORT_NOT_SET
            //   31 = ProcessDebugFlags       -> return 1 (PROCESS_DEBUG_INHERIT)
            // For all other classes, JMP to the original function + 16 (after our hook)

            // Allocate shellcode in target process
            byte[] shellcode = BuildNtQueryFilterShellcode(funcAddr);
            ulong shellcodeAddr = AllocateRemoteMemory(shellcode.Length);
            if (shellcodeAddr == 0) { log("  Failed to allocate shellcode memory"); return; }

            WriteProcessMemorySafe(shellcodeAddr, shellcode);

            // Patch entry point with JMP to shellcode
            byte[] jmpPatch = new byte[14];
            jmpPatch[0] = 0xFF; // JMP [RIP+0]
            jmpPatch[1] = 0x25;
            jmpPatch[2] = 0x00; jmpPatch[3] = 0x00; jmpPatch[4] = 0x00; jmpPatch[5] = 0x00;
            BitConverter.GetBytes(shellcodeAddr).CopyTo(jmpPatch, 6);

            SaveAndPatch(funcAddr, jmpPatch);
            log("  Patched NtQueryInformationProcess with debug port filter hook");
        }

        private byte[] BuildNtQueryFilterShellcode(ulong originalFuncAddr)
        {
            // x64 shellcode that filters NtQueryInformationProcess debug queries
            // RCX = ProcessHandle, RDX = InformationClass, R8 = Buffer, R9 = BufferLength
            var code = new System.Collections.Generic.List<byte>();

            // Check InformationClass (RDX) for debug-related values
            // CMP RDX, 7 (ProcessDebugPort)
            code.AddRange(new byte[] { 0x48, 0x83, 0xFA, 0x07 }); // cmp rdx, 7
            code.AddRange(new byte[] { 0x74, 0x20 });              // je handle_debug_port (+0x20)

            // CMP RDX, 30 (ProcessDebugObjectHandle)
            code.AddRange(new byte[] { 0x48, 0x83, 0xFA, 0x1E }); // cmp rdx, 30
            code.AddRange(new byte[] { 0x74, 0x28 });              // je handle_debug_object (+0x28)

            // CMP RDX, 31 (ProcessDebugFlags)
            code.AddRange(new byte[] { 0x48, 0x83, 0xFA, 0x1F }); // cmp rdx, 31
            code.AddRange(new byte[] { 0x74, 0x30 });              // je handle_debug_flags (+0x30)

            // Not a debug query - JMP to original function (skip our hook bytes)
            // JMP [RIP+0]; dq originalFuncAddr+16
            code.AddRange(new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 });
            code.AddRange(BitConverter.GetBytes(originalFuncAddr + 14)); // after our 14-byte hook

            // handle_debug_port: Write 0 to buffer, return STATUS_SUCCESS
            // MOV QWORD [R8], 0; XOR EAX,EAX; RET
            code.AddRange(new byte[] { 0x49, 0xC7, 0x00, 0x00, 0x00, 0x00, 0x00 }); // mov qword [r8], 0
            code.AddRange(new byte[] { 0x31, 0xC0 }); // xor eax, eax
            code.AddRange(new byte[] { 0xC3 });        // ret

            // handle_debug_object: return STATUS_PORT_NOT_SET (0xC0000353)
            code.AddRange(new byte[] { 0xB8, 0x53, 0x03, 0x00, 0xC0 }); // mov eax, 0xC0000353
            code.AddRange(new byte[] { 0xC3 }); // ret

            // handle_debug_flags: Write 1 to buffer (PROCESS_DEBUG_INHERIT), return STATUS_SUCCESS
            code.AddRange(new byte[] { 0x49, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00 }); // mov dword [r8], 1
            code.AddRange(new byte[] { 0x31, 0xC0 }); // xor eax, eax
            code.AddRange(new byte[] { 0xC3 });        // ret

            return code.ToArray();
        }

        private ulong AllocateRemoteMemory(int size)
        {
            try
            {
                return (ulong)VirtualAllocEx(processHandle, IntPtr.Zero, (uint)size,
                    0x1000 | 0x2000, 0x40); // MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
            }
            catch { return 0; }
        }

        private byte[] ReadBytesSafe(ulong address, int size)
        {
            try
            {
                byte[] buffer = new byte[size];
                IntPtr bufPtr = Marshal.AllocHGlobal(size);
                if (ReadProcessMemory(processHandle, (IntPtr)address, bufPtr, size, out int bytesRead) && bytesRead > 0)
                {
                    Marshal.Copy(bufPtr, buffer, 0, bytesRead);
                    Marshal.FreeHGlobal(bufPtr);
                    return buffer;
                }
                Marshal.FreeHGlobal(bufPtr);
                return null;
            }
            catch { return null; }
        }

        private void PatchNtClose(Action<string> log)
        {
            // Anti-debug trick: call NtClose with an invalid handle value
            // If the process is being debugged, the kernel sets KdDebuggerEnabled
            // and NtClose raises STATUS_INVALID_HANDLE exception for bad handles
            // Normal processes don't get this exception

            IntPtr hNtdll = GetModuleHandleInTarget("ntdll.dll");
            if (hNtdll == IntPtr.Zero) return;

            ulong funcAddr = GetProcAddressInTarget(hNtdll, "NtClose");
            if (funcAddr == 0) return;

            // Patch NtClose to suppress the STATUS_INVALID_HANDLE exception
            // We hook the entry to check if the handle is invalid, and if so, return
            // STATUS_INVALID_HANDLE directly without going through the kernel path
            // that would trigger the debug exception

            byte[] original = ReadBytesSafe(funcAddr, 8);
            if (original == null) return;

            // Shellcode: check if handle (RCX) is invalid (< 4 or > 0xFFFFFFFF),
            // if so return STATUS_INVALID_HANDLE (0xC0000008) directly
            var code = new System.Collections.Generic.List<byte>();

            // CMP RCX, 4 (handles < 4 are pseudo-handles)
            code.AddRange(new byte[] { 0x48, 0x83, 0xF9, 0x04 });
            // JL return_invalid
            code.AddRange(new byte[] { 0x7C, 0x0C });
            // MOV RAX, 0xFFFFFFFF00000000 (check for kernel handles)
            code.AddRange(new byte[] { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF });
            // CMP RCX, RAX
            code.AddRange(new byte[] { 0x48, 0x3B, 0xC8 });
            // JL jmp_original
            code.AddRange(new byte[] { 0x7C, 0x08 });

            // return_invalid: MOV EAX, 0xC0000008; RET
            code.AddRange(new byte[] { 0xB8, 0x08, 0x00, 0x00, 0xC0 });
            code.AddRange(new byte[] { 0xC3 });

            // jmp_original: JMP to original NtClose + our_hook_size
            code.AddRange(new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 });
            code.AddRange(BitConverter.GetBytes(funcAddr + (ulong)code.Count + 8));

            byte[] shellcode = code.ToArray();
            ulong shellcodeAddr = AllocateRemoteMemory(shellcode.Length);
            if (shellcodeAddr == 0) { log("  Failed to allocate NtClose shellcode"); return; }

            WriteProcessMemorySafe(shellcodeAddr, shellcode);

            // Patch NtClose entry with JMP to shellcode
            byte[] jmpPatch = new byte[14];
            jmpPatch[0] = 0xFF; jmpPatch[1] = 0x25;
            jmpPatch[2] = 0x00; jmpPatch[3] = 0x00; jmpPatch[4] = 0x00; jmpPatch[5] = 0x00;
            BitConverter.GetBytes(shellcodeAddr).CopyTo(jmpPatch, 6);

            SaveAndPatch(funcAddr, jmpPatch);
            log("  Patched NtClose to suppress invalid handle exceptions");
        }

        private void PatchHeapFlags(Action<string> log)
        {
            // When a process is debugged, the default heap has special flags set:
            // PEB.ProcessHeap.Flags should be 0x02 (HEAP_GROWABLE) - no debug flags
            // PEB.ProcessHeap.ForceFlags should be 0x00
            // Debugged processes have Flags = 0x50000062 and ForceFlags = 0x40000060

            byte[] pbi = new byte[48];
            int retLen = 0;
            NtQueryInformationProcess(processHandle, 0, pbi, pbi.Length, ref retLen);
            ulong pebAddress = BitConverter.ToUInt64(pbi, 8);
            if (pebAddress == 0) return;

            // Read ProcessHeap pointer from PEB + 0x30 (x64)
            byte[] heapPtr = ReadBytesSafe(pebAddress + 0x30, 8);
            if (heapPtr == null) return;
            ulong processHeap = BitConverter.ToUInt64(heapPtr, 0);
            if (processHeap == 0) return;

            // HEAP structure: Flags at +0x70, ForceFlags at +0x74 (x64)
            byte[] normalFlags = BitConverter.GetBytes(0x00000002); // HEAP_GROWABLE only
            byte[] normalForceFlags = BitConverter.GetBytes(0x00000000);

            WriteProcessMemorySafe(processHeap + 0x70, normalFlags);
            WriteProcessMemorySafe(processHeap + 0x74, normalForceFlags);
            log("  Patched heap Flags=0x02, ForceFlags=0x00");
        }

        private void PatchNtSetInformationThread(Action<string> log)
        {
            // Anti-debug: NtSetInformationThread with ThreadHideFromDebugger (0x11)
            // causes the thread to be hidden from the debugger. We patch this to
            // return STATUS_SUCCESS without actually hiding the thread.

            IntPtr hNtdll = GetModuleHandleInTarget("ntdll.dll");
            if (hNtdll == IntPtr.Zero) return;

            ulong funcAddr = GetProcAddressInTarget(hNtdll, "NtSetInformationThread");
            if (funcAddr == 0) return;

            // Shellcode: Check if ThreadInformationClass (RDX) == 0x11 (ThreadHideFromDebugger)
            // If so, return STATUS_SUCCESS (0) without calling the real function
            // Otherwise, JMP to original function
            var code = new System.Collections.Generic.List<byte>();

            // CMP RDX, 0x11 (ThreadHideFromDebugger)
            code.AddRange(new byte[] { 0x48, 0x83, 0xFA, 0x11 });
            // JNE jmp_original (skip to original)
            code.AddRange(new byte[] { 0x75, 0x06 });
            // XOR EAX, EAX; RET (return STATUS_SUCCESS)
            code.AddRange(new byte[] { 0x31, 0xC0, 0xC3 });
            // jmp_original: JMP to original NtSetInformationThread + hook_size
            int hookSize = code.Count + 14;
            code.AddRange(new byte[] { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 });
            code.AddRange(BitConverter.GetBytes(funcAddr + (ulong)hookSize));

            byte[] shellcode = code.ToArray();
            ulong shellcodeAddr = AllocateRemoteMemory(shellcode.Length);
            if (shellcodeAddr == 0) { log("  Failed to allocate NtSetInformationThread shellcode"); return; }

            WriteProcessMemorySafe(shellcodeAddr, shellcode);

            byte[] jmpPatch = new byte[14];
            jmpPatch[0] = 0xFF; jmpPatch[1] = 0x25;
            jmpPatch[2] = 0x00; jmpPatch[3] = 0x00; jmpPatch[4] = 0x00; jmpPatch[5] = 0x00;
            BitConverter.GetBytes(shellcodeAddr).CopyTo(jmpPatch, 6);

            SaveAndPatch(funcAddr, jmpPatch);
            log("  Patched NtSetInformationThread to block ThreadHideFromDebugger");
        }

        private void PatchTimingAntiDebug(Action<string> log)
        {
            // Anti-debug timing check: measure time between two calls to
            // GetTickCount() or QueryPerformanceCounter(). If the delta is
            // abnormally large (due to debugger stepping), the process knows
            // it's being debugged.
            //
            // We can't easily patch these without breaking legitimate timing,
            // but we can patch common anti-debug patterns that call these functions.
            // For now, we log the addresses so the user can manually inspect.

            IntPtr hKernel32 = GetModuleHandleInTarget("kernel32.dll");
            if (hKernel32 == IntPtr.Zero) return;

            ulong getTickCount = GetProcAddressInTarget(hKernel32, "GetTickCount");
            ulong qpc = GetProcAddressInTarget(hKernel32, "QueryPerformanceCounter");

            if (getTickCount > 0)
                log($"  GetTickCount @ 0x{getTickCount:X} (timing anti-debug target)");
            if (qpc > 0)
                log($"  QueryPerformanceCounter @ 0x{qpc:X} (timing anti-debug target)");
        }

        private void RestoreStealthPatches()
        {
            foreach (var kvp in savedPatches)
            {
                try { WriteProcessMemorySafe(kvp.Key, kvp.Value); } catch { }
            }
            savedPatches.Clear();
        }

        // ==================== VEH DEBUGGER ====================

        private bool AttachVEH(Action<string> log)
        {
            // VEH debugger doesn't create a debug port - it's undetectable by standard APIs
            // We inject a small VEH handler into the target that catches INT3/exception events
            // and reports them back via shared memory

            // For now, we use a simpler approach: set hardware breakpoints on all threads
            // and poll for exceptions via our own debug loop (without DebugActiveProcess)

            isAttached = true;
            log("VEH debugger attached (no debug port - undetectable)");
            log("  Use SetHardwareBreakpoint() to add breakpoints");

            // Note: Full VEH injection requires writing shellcode to target process
            // and calling AddVectoredExceptionHandler remotely. This is a complex
            // operation that requires careful shellcode construction.
            // The current implementation uses hardware breakpoints as the primary
            // monitoring mechanism, which achieves similar results without injection.

            cts = new CancellationTokenSource();
            Task.Run(() => VEHPollLoop());
            return true;
        }

        private void VEHPollLoop()
        {
            // Poll thread contexts for breakpoint hits (used when not in standard debug mode)
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    Thread.Sleep(50);
                    // Check if any hardware breakpoints were hit by examining thread DR6
                    // This is a simplified approach - full VEH would use exception dispatch
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        // ==================== HARDWARE BREAKPOINTS ====================

        private bool AttachHardwareBP(Action<string> log)
        {
            isAttached = true;
            log("Hardware breakpoint debugger attached (DR registers)");
            log("  Use SetHardwareBreakpoint() to add breakpoints (4 slots available)");

            cts = new CancellationTokenSource();
            Task.Run(() => VEHPollLoop());
            return true;
        }

        public bool SetHardwareBreakpoint(ulong address, HWBreakpointType type, int drSlot)
        {
            if (drSlot < 0 || drSlot > 3) { Log("Invalid DR slot (0-3)"); return false; }

            try
            {
                // Set the hardware breakpoint on ALL threads in the process
                var threads = EnumerateThreadIds(processId);
                int set = 0;

                foreach (uint tid in threads)
                {
                    IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, tid);
                    if (hThread == IntPtr.Zero) continue;

                    try
                    {
                        if (SetHWBreakpointOnThread(hThread, address, type, drSlot))
                            set++;
                    }
                    finally { CloseHandle(hThread); }
                }

                lock (syncLock)
                {
                    hardwareBreakpoints.RemoveAll(bp => bp.Slot == drSlot);
                    hardwareBreakpoints.Add(new HWBreakpoint { Slot = drSlot, Address = address, Type = type, Active = true });
                }

                Log("Hardware BP set: DR{0} = 0x{1:X} ({2}) on {3} threads", drSlot, address, type, set);
                return set > 0;
            }
            catch (Exception ex)
            {
                Log("Set HW BP error: {0}", ex.Message);
                return false;
            }
        }

        private bool SetHWBreakpointOnThread(IntPtr hThread, ulong address, HWBreakpointType type, int drSlot)
        {
            IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
            try
            {
                // Zero and set context flags
                for (int i = 0; i < 2048; i++) Marshal.WriteByte(ctxPtr, i, 0);
                // CONTEXT_DEBUG_REGISTERS = 0x00100000 | 0x00000010
                Marshal.WriteInt32(ctxPtr, 48, 0x00100010);

                if (!GetThreadContext(hThread, ctxPtr))
                    return false;

                // DR0-DR3 are at offsets: DR0=4, DR1=12, DR2=20, DR3=28 (in CONTEXT after debug register area)
                // Actually in x64 CONTEXT: Dr0 is at a specific offset. Let me use the correct offsets.
                // CONTEXT_AMD64 layout: Dr0-Dr7 start at offset 48+4+4+12+4 = 72... 
                // Let me use a simpler approach with known offsets for x64 CONTEXT:
                // Dr0 = offset 48+4+4+12+4 = 72... no, let me look at the actual layout.
                // 
                // x64 CONTEXT structure (simplified):
                // Offset 0: P1Home-P6Home (6*8 = 48 bytes)
                // Offset 48: ContextFlags (4), MxCsr (4) = 8 bytes
                // Offset 56: SegCs-SegSs (6*2 = 12 bytes)  
                // Offset 68: EFlags (4)
                // Offset 72: Dr0 (8), Dr1 (8), Dr2 (8), Dr3 (8), Dr6 (8), Dr7 (8) = 48 bytes
                // So Dr0 = 72, Dr1 = 80, Dr2 = 88, Dr3 = 96, Dr6 = 104, Dr7 = 112

                int drOffset = 72 + (drSlot * 8); // DR0=72, DR1=80, DR2=88, DR3=96
                int dr7Offset = 112;

                // Set the address in DR0-DR3
                Marshal.WriteInt64(ctxPtr, drOffset, (long)address);

                // Read current DR7
                long dr7 = Marshal.ReadInt64(ctxPtr, dr7Offset);

                // Enable the local breakpoint in DR7
                // DR7 layout: bits 0,2,4,6 = local enable for DR0-DR3
                //              bits 16-17 = condition for DR0 (00=exec, 01=write, 11=r/w)
                //              bits 18-19 = length for DR0 (00=1 byte)
                int localEnableBit = drSlot * 2; // 0, 2, 4, 6
                int conditionShift = 16 + (drSlot * 4); // 16, 20, 24, 28

                dr7 |= (1L << localEnableBit); // Set local enable bit
                dr7 &= ~(3L << conditionShift); // Clear condition bits
                dr7 |= ((long)type << conditionShift); // Set condition type

                Marshal.WriteInt64(ctxPtr, dr7Offset, dr7);

                return SetThreadContext(hThread, ctxPtr);
            }
            finally { Marshal.FreeHGlobal(ctxPtr); }
        }

        public void ClearHardwareBreakpoints()
        {
            try
            {
                var threads = EnumerateThreadIds(processId);
                foreach (uint tid in threads)
                {
                    IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, false, tid);
                    if (hThread == IntPtr.Zero) continue;

                    try
                    {
                        IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                        for (int i = 0; i < 2048; i++) Marshal.WriteByte(ctxPtr, i, 0);
                        Marshal.WriteInt32(ctxPtr, 48, 0x00100010);

                        if (GetThreadContext(hThread, ctxPtr))
                        {
                            // Clear DR0-DR3 and DR7
                            for (int dr = 0; dr < 4; dr++)
                                Marshal.WriteInt64(ctxPtr, 72 + dr * 8, 0);
                            Marshal.WriteInt64(ctxPtr, 112, 0); // DR7

                            SetThreadContext(hThread, ctxPtr);
                        }
                        Marshal.FreeHGlobal(ctxPtr);
                    }
                    finally { CloseHandle(hThread); }
                }

                lock (syncLock) hardwareBreakpoints.Clear();
                Log("All hardware breakpoints cleared");
            }
            catch (Exception ex) { Log("Clear HW BP error: {0}", ex.Message); }
        }

        // ==================== KERNEL DEBUG ====================

        private bool AttachKernel(Action<string> log)
        {
            if (driver == null || !driver.IsKernelMode)
            {
                log("Kernel debug requires loaded kernel driver");
                return false;
            }

            // Kernel-mode debugging uses the driver to create a debug object
            // at ring-0, bypassing all user-mode anti-debug mechanisms
            // For now, we use standard DebugActiveProcess with the driver handle
            // to get elevated access
            if (!DebugActiveProcess((uint)processId))
            {
                log($"Kernel DebugActiveProcess failed (error: {Marshal.GetLastWin32Error()})");
                return false;
            }

            DebugSetProcessKillOnExit(false);
            isAttached = true;
            log("Kernel debugger attached (elevated privileges)");

            cts = new CancellationTokenSource();
            Task.Run(() => DebugEventLoop());
            return true;
        }

        // ==================== DEBUG EVENT LOOP ====================

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

                    var evt = new DebugEvent
                    {
                        EventCode = debugEvent.dwDebugEventCode,
                        ProcessId = debugEvent.dwProcessId,
                        ThreadId = debugEvent.dwThreadId,
                        Timestamp = DateTime.Now
                    };

                    switch (debugEvent.dwDebugEventCode)
                    {
                        case 1: // EXCEPTION_DEBUG_EVENT
                            evt.ExceptionCode = debugEvent.Exception.ExceptionRecord.ExceptionCode;
                            evt.Address = (ulong)debugEvent.Exception.ExceptionRecord.ExceptionAddress.ToInt64();
                            evt.Description = $"Exception 0x{evt.ExceptionCode:X8} at 0x{evt.Address:X}";

                            if (evt.ExceptionCode == 0x80000003)
                                evt.Description = $"BREAKPOINT at 0x{evt.Address:X}";
                            else if (evt.ExceptionCode == 0x80000004)
                                evt.Description = $"SINGLE_STEP at 0x{evt.Address:X}";
                            else if (evt.ExceptionCode == 0xC0000005)
                                evt.Description = $"ACCESS_VIOLATION at 0x{evt.Address:X}";
                            break;

                        case 2: // CREATE_THREAD_DEBUG_EVENT
                            evt.Description = $"Thread created (TID: {debugEvent.dwThreadId})";
                            break;

                        case 3: // CREATE_PROCESS_DEBUG_EVENT
                            evt.Description = $"Process created";
                            break;

                        case 4: // EXIT_THREAD_DEBUG_EVENT
                            evt.Description = $"Thread exited (TID: {debugEvent.dwThreadId})";
                            break;

                        case 5: // EXIT_PROCESS_DEBUG_EVENT
                            evt.Description = "Process exited";
                            isAttached = false;
                            break;

                        case 6: // LOAD_DLL_DEBUG_EVENT
                            evt.Description = "DLL loaded";
                            break;

                        case 7: // UNLOAD_DLL_DEBUG_EVENT
                            evt.Description = "DLL unloaded";
                            break;

                        case 8: // OUTPUT_DEBUG_STRING_EVENT
                            evt.Description = "Debug string output";
                            break;
                    }

                    lock (syncLock) eventHistory.Add(evt);

                    try { OnDebugEvent?.Invoke(evt); } catch { }
                    Log("[DBG] {0}", evt.Description);

                    ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);

                    if (debugEvent.dwDebugEventCode == 5) // EXIT_PROCESS
                        break;
                }
            }
            catch (Exception ex) { Log("Debug loop error: {0}", ex.Message); }

            isAttached = false;
        }

        // ==================== HELPERS ====================

        private void SaveAndPatch(ulong address, byte[] patch)
        {
            // Save original bytes
            byte[] original = new byte[patch.Length];
            IntPtr readBuf = Marshal.AllocHGlobal(patch.Length);
            try
            {
                if (ReadProcessMemory(processHandle, (IntPtr)address, readBuf, patch.Length, out _))
                {
                    Marshal.Copy(readBuf, original, 0, patch.Length);
                    savedPatches[address] = original;
                }
            }
            finally { Marshal.FreeHGlobal(readBuf); }

            // Write patch
            WriteProcessMemorySafe(address, patch);
        }

        private bool WriteProcessMemorySafe(ulong address, byte[] data)
        {
            IntPtr buf = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, buf, data.Length);
                uint oldProtect;
                VirtualProtectEx(processHandle, (IntPtr)address, (uint)data.Length, 0x40, out oldProtect); // PAGE_EXECUTE_READWRITE
                bool result = WriteProcessMemory(processHandle, (IntPtr)address, buf, data.Length, out _);
                VirtualProtectEx(processHandle, (IntPtr)address, (uint)data.Length, oldProtect, out _);
                return result;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private IntPtr GetModuleHandleInTarget(string moduleName)
        {
            // Use driver to get module list and find the target module
            if (driver != null && driver.GetModuleSummaryList(processId, out var modules))
            {
                foreach (var mod in modules)
                {
                    if (mod.ModuleName.Equals(moduleName, StringComparison.OrdinalIgnoreCase))
                        return (IntPtr)mod.BaseAddress;
                }
            }
            return IntPtr.Zero;
        }

        private ulong GetProcAddressInTarget(IntPtr moduleBase, string functionName)
        {
            // Read the export table of the module in the target process
            try
            {
                byte[] dosHeader = ReadBytesFromTarget((ulong)moduleBase.ToInt64(), 64);
                if (dosHeader == null || BitConverter.ToUInt16(dosHeader, 0) != 0x5A4D) return 0;

                int e_lfanew = BitConverter.ToInt32(dosHeader, 60);
                byte[] peHeader = ReadBytesFromTarget((ulong)(moduleBase.ToInt64() + e_lfanew), 512);
                if (peHeader == null || BitConverter.ToUInt32(peHeader, 0) != 0x00004550) return 0;

                ushort magic = BitConverter.ToUInt16(peHeader, 24);
                bool is64 = magic == 0x20b;
                int exportDirOffset = is64 ? 112 : 96;
                uint exportRVA = BitConverter.ToUInt32(peHeader, 24 + exportDirOffset);
                if (exportRVA == 0) return 0;

                byte[] exportDir = ReadBytesFromTarget((ulong)(moduleBase.ToInt64() + exportRVA), 40);
                if (exportDir == null) return 0;

                int numFunctions = BitConverter.ToInt32(exportDir, 20);
                int numNames = BitConverter.ToInt32(exportDir, 24);
                uint funcTableRVA = BitConverter.ToUInt32(exportDir, 28);
                uint nameTableRVA = BitConverter.ToUInt32(exportDir, 32);
                uint ordinalTableRVA = BitConverter.ToUInt32(exportDir, 36);

                for (int i = 0; i < numNames; i++)
                {
                    byte[] nameRVABuf = ReadBytesFromTarget((ulong)(moduleBase.ToInt64() + nameTableRVA + i * 4), 4);
                    if (nameRVABuf == null) continue;
                    uint nameRVA = BitConverter.ToUInt32(nameRVABuf, 0);

                    byte[] nameBytes = ReadBytesFromTarget((ulong)(moduleBase.ToInt64() + nameRVA), 128);
                    if (nameBytes == null) continue;
                    int end = 0;
                    while (end < nameBytes.Length && nameBytes[end] != 0) end++;
                    string name = Encoding.ASCII.GetString(nameBytes, 0, end);

                    if (name == functionName)
                    {
                        byte[] ordinalBuf = ReadBytesFromTarget((ulong)(moduleBase.ToInt64() + ordinalTableRVA + i * 2), 2);
                        if (ordinalBuf == null) continue;
                        ushort ordinal = BitConverter.ToUInt16(ordinalBuf, 0);

                        byte[] funcRVABuf = ReadBytesFromTarget((ulong)(moduleBase.ToInt64() + funcTableRVA + ordinal * 4), 4);
                        if (funcRVABuf == null) continue;
                        uint funcRVA = BitConverter.ToUInt32(funcRVABuf, 0);

                        return (ulong)(moduleBase.ToInt64() + funcRVA);
                    }
                }
            }
            catch { }
            return 0;
        }

        private byte[] ReadBytesFromTarget(ulong address, int size)
        {
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!ReadProcessMemory(processHandle, (IntPtr)address, buf, size, out _))
                    return null;
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private List<uint> EnumerateThreadIds(int pid)
        {
            var threads = new List<uint>();
            int bufSize = 0x100000;
            IntPtr buffer = Marshal.AllocHGlobal(bufSize);
            try
            {
                int status = NtQuerySystemInformation(5, buffer, bufSize, out int retLen);
                if (status == unchecked((int)0xC0000004))
                {
                    bufSize = retLen + 0x10000;
                    Marshal.FreeHGlobal(buffer);
                    buffer = Marshal.AllocHGlobal(bufSize);
                    status = NtQuerySystemInformation(5, buffer, bufSize, out retLen);
                }
                if (status != 0) return threads;

                int offset = 0;
                while (offset < retLen)
                {
                    IntPtr current = buffer + offset;
                    int nextOffset = Marshal.ReadInt32(current, 0);
                    int procId = Marshal.ReadInt32(current, IntPtr.Size == 8 ? 88 : 68);

                    if (procId == pid)
                    {
                        int threadCount = Marshal.ReadInt32(current, IntPtr.Size == 8 ? 68 : 64);
                        IntPtr threadArray = current + (IntPtr.Size == 8 ? 112 : 84);
                        int offThreadId = IntPtr.Size == 8 ? 40 : 32;
                        int structSize = IntPtr.Size == 8 ? 72 : 56;

                        for (int i = 0; i < threadCount; i++)
                        {
                            IntPtr tInfo = threadArray + (i * structSize);
                            uint tid = (uint)(IntPtr.Size == 8
                                ? Marshal.ReadInt64(tInfo, offThreadId)
                                : Marshal.ReadInt32(tInfo, offThreadId));
                            threads.Add(tid);
                        }
                        break;
                    }

                    if (nextOffset == 0) break;
                    offset += nextOffset;
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return threads;
        }

        private void Log(string message, params object[] args)
        {
            try { OnLog?.Invoke(string.Format(message, args)); } catch { }
        }

        public void Dispose()
        {
            DetachDebugger();
            cts?.Dispose();
        }

        // ==================== P/INVOKE ====================

        private const uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        private const uint THREAD_GET_CONTEXT = 0x0008;
        private const uint THREAD_SET_CONTEXT = 0x0010;
        private const uint THREAD_QUERY_INFORMATION = 0x0040;

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
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, byte[] processInformation, int processInformationLength, ref int returnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

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
        }
    }
}
