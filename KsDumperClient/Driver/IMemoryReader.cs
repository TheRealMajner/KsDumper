using System;
using System.Collections.Generic;

namespace KsDumperClient.Driver
{
    public interface IMemoryReader
    {
        bool HasValidHandle();
        bool IsKernelMode { get; }

        // Core operations (both modes)
        bool GetProcessSummaryList(out ProcessSummary[] result);
        bool GetModuleSummaryList(int targetProcessId, out ModuleSummary[] result);
        bool CopyVirtualMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize);
        bool WriteVirtualMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize);
        Dictionary<ulong, (string dllName, string funcName)> GetExportMap(int targetProcessId);

        // Kernel-only operations (return failure in usermode)
        int UnprotectProcess(int targetProcessId);
        int SuspendProcess(int targetProcessId);
        int ResumeProcess(int targetProcessId);
        int CheckTablesReady(int targetProcessId);
        int UnloadModule(int targetProcessId, ulong moduleBaseAddress);
        bool LsassReadMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize);
        (int status, int pid) KillProcessByName(string processName);
        int UnloadDriverByName(string driverName);

        // Scanning operations (can work in usermode via RPM)
        List<(ulong address, bool isUnicode, string value)> DumpLiveStrings(int targetProcessId, int minStringLength = 4);
        List<(ulong baseAddress, ulong regionSize, uint protect, uint state, uint type)> EnumRegions(int targetProcessId);
        List<ulong> FindPattern(int targetProcessId, byte[] pattern, byte wildcard = 0xCC, int maxResults = 1000);
        (byte[] metadata, ulong address) ReadIl2CppMetadata(int targetProcessId);

        // Kernel driver enumeration (requires driver)
        List<(string basePath, string baseName, ulong baseAddress, uint imageSize, uint flags, DateTime loadTime, ulong entryPoint, uint checkSum)> EnumerateDrivers();

        // Kernel-mode thread context operations (requires driver, returns null/empty in usermode)
        byte[] GetThreadContext(int processId, int threadId, int contextFlags);
        bool SetThreadContext(int processId, int threadId, byte[] context);

        // Kernel-mode debug operations (requires driver)
        bool DebugAttach(int processId);
        (int eventCode, int threadId, ulong eventAddress, int exceptionCode) DebugWaitEvent(int timeoutMs);
        bool DebugContinue(int threadId, int continueStatus);

        // Anti-cheat bypass operations (requires driver)
        (int callbackCount, int removedCount, CallbackEntry[] callbacks) EnumKernelCallbacks(bool removeCallbacks);
        (int status, int clonedProcessId) CloneProcess(int processId);
        (int vadCount, VADEntry[] vads) EnumVadTree(int processId);
        (int handleCount, HandleEntry[] handles) EnumHandles(int processId);
        (int moduleCount, KernelModuleEntry[] modules) EnumKernelModules();
    }

    // VAD entry for kernel-mode VAD tree enumeration
    public struct VADEntry
    {
        public ulong StartAddress;
        public ulong EndAddress;
        public uint Protection;
        public uint Flags;
        public uint CommitCharge;
        public ulong ControlArea;
    }

    // Handle entry for kernel-mode handle enumeration
    public struct HandleEntry
    {
        public ulong HandleValue;
        public int ProcessId;
        public int TargetProcessId;
        public uint GrantedAccess;
        public uint HandleAttributes;
        public string ObjectName;
        public uint ObjectTypeIndex;
    }

    // Callback entry for kernel callback enumeration
    public struct CallbackEntry
    {
        public ulong CallbackAddress;
        public string DriverName;
        public uint CallbackType;   // 0=Process, 1=LoadImage, 2=Thread
        public uint Index;
        public uint Removed;
    }

    // Kernel module entry for kernel-mode module enumeration
    public struct KernelModuleEntry
    {
        public ulong BaseAddress;
        public uint ImageSize;
        public string BaseName;
        public string FullPath;
        public uint Flags;
    }
}
