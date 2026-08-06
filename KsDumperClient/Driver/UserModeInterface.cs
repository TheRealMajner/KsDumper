using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Utility;

using static KsDumperClient.Utility.WinApi;

namespace KsDumperClient.Driver
{
    public class UserModeInterface : IMemoryReader
    {
        private readonly ConcurrentDictionary<int, IntPtr> handleCache = new ConcurrentDictionary<int, IntPtr>();

        public bool IsKernelMode => false;
        public bool HasValidHandle() => true;

        private IntPtr GetProcessHandle(int processId)
        {
            return handleCache.GetOrAdd(processId, pid =>
                OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION, false, pid));
        }

        public void CloseHandles()
        {
            foreach (var kvp in handleCache)
            {
                if (kvp.Value != IntPtr.Zero && kvp.Value != INVALID_HANDLE_VALUE)
                    CloseHandle(kvp.Value);
            }
            handleCache.Clear();
        }

        // ---- Core operations ----

        public bool GetProcessSummaryList(out ProcessSummary[] result)
        {
            var list = new List<ProcessSummary>();

            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id == 0 || proc.Id == 4) continue;

                        IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, proc.Id);
                        if (hProc == IntPtr.Zero)
                        {
                            hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, proc.Id);
                            if (hProc == IntPtr.Zero) continue;
                        }

                        ulong baseAddr = 0;
                        string fileName = "";
                        uint imageSize = 0;
                        ulong entryPoint = 0;

                        try
                        {
                            ProcessModule mainMod = null;
                            try { mainMod = proc.MainModule; } catch { }

                            if (mainMod != null)
                            {
                                baseAddr = (ulong)mainMod.BaseAddress.ToInt64();
                                fileName = mainMod.FileName;
                                imageSize = (uint)mainMod.ModuleMemorySize;
                                entryPoint = 0;
                            }
                            else
                            {
                                fileName = proc.ProcessName;
                            }

                            bool isWow64 = false;
                            IsWow64Process(hProc, out isWow64);

                            var summary = new ProcessSummary(
                                proc.Id, proc.ProcessName, baseAddr, fileName, imageSize, entryPoint);

                            list.Add(summary);
                        }
                        finally
                        {
                            if (hProc != IntPtr.Zero)
                                CloseHandle(hProc);
                        }
                    }
                    catch { }
                }
            }
            catch { }

            result = list.ToArray();
            return result.Length > 0;
        }

        public bool GetModuleSummaryList(int targetProcessId, out ModuleSummary[] result)
        {
            var list = new List<ModuleSummary>();

            IntPtr hProc = GetProcessHandle(targetProcessId);

            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)targetProcessId);
            if (snapshot == INVALID_HANDLE_VALUE)
            {
                result = new ModuleSummary[0];
                return false;
            }

            try
            {
                var entry = new MODULEENTRY32();
                entry.dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>();

                if (Module32First(snapshot, ref entry))
                {
                    do
                    {
                        ulong baseAddr = (ulong)entry.modBaseAddr.ToInt64();
                        ulong entryPoint = ReadEntryPoint(targetProcessId, hProc, baseAddr);

                        var mod = ModuleSummary.Create(
                            targetProcessId,
                            baseAddr,
                            entryPoint,
                            entry.modBaseSize,
                            entry.szExePath,
                            false);
                        list.Add(mod);
                        entry.dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>();
                    }
                    while (Module32Next(snapshot, ref entry));
                }
            }
            finally
            {
                CloseHandle(snapshot);
            }

            result = list.ToArray();
            return result.Length > 0;
        }

        public bool CopyVirtualMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize)
        {
            IntPtr hProc = GetProcessHandle(targetProcessId);
            if (hProc == IntPtr.Zero || hProc == INVALID_HANDLE_VALUE)
                return false;

            // For small reads, do it directly
            if (bufferSize <= 0x10000) // 64KB
            {
                return ReadWithRetry(hProc, targetAddress, bufferAddress, bufferSize, 2);
            }

            // For large reads, chunk it to handle guard pages and partial failures
            int chunkSize = 0x1000; // 4KB pages
            int totalRead = 0;
            long currentAddr = targetAddress.ToInt64();
            long currentBuf = bufferAddress.ToInt64();

            while (totalRead < bufferSize)
            {
                int remaining = bufferSize - totalRead;
                int thisChunk = Math.Min(chunkSize, remaining);

                if (!ReadProcessMemory(hProc, (IntPtr)currentAddr, (IntPtr)currentBuf, thisChunk, out int bytesRead))
                {
                    // Try with smaller chunk on failure (might be hitting a guard page boundary)
                    thisChunk = Math.Min(256, remaining);
                    if (!ReadProcessMemory(hProc, (IntPtr)currentAddr, (IntPtr)currentBuf, thisChunk, out bytesRead))
                    {
                        // Zero-fill the failed chunk and continue (partial read is better than total failure)
                        for (int z = 0; z < thisChunk; z++)
                            System.Runtime.InteropServices.Marshal.WriteByte((IntPtr)(currentBuf + z), 0);
                        bytesRead = thisChunk;
                    }
                }

                totalRead += bytesRead;
                currentAddr += bytesRead;
                currentBuf += bytesRead;
            }

            return totalRead > 0;
        }

        private bool ReadWithRetry(IntPtr hProc, IntPtr targetAddr, IntPtr bufferAddr, int size, int maxRetries)
        {
            for (int attempt = 0; attempt <= maxRetries; attempt++)
            {
                if (ReadProcessMemory(hProc, targetAddr, bufferAddr, size, out int bytesRead) && bytesRead == size)
                    return true;

                if (attempt < maxRetries)
                    System.Threading.Thread.Sleep(10); // Brief pause before retry
            }
            return false;
        }

        public bool WriteVirtualMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize)
        {
            IntPtr hProc = GetProcessHandle(targetProcessId);
            if (hProc == IntPtr.Zero || hProc == INVALID_HANDLE_VALUE)
                return false;

            return WriteProcessMemory(hProc, targetAddress, bufferAddress, bufferSize, out int bytesWritten) && bytesWritten == bufferSize;
        }

        public Dictionary<ulong, (string dllName, string funcName)> GetExportMap(int targetProcessId)
        {
            var result = new Dictionary<ulong, (string, string)>();
            IntPtr hProc = GetProcessHandle(targetProcessId);
            if (hProc == IntPtr.Zero || hProc == INVALID_HANDLE_VALUE) return result;

            IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, (uint)targetProcessId);
            if (snapshot == INVALID_HANDLE_VALUE) return result;

            try
            {
                var entry = new MODULEENTRY32();
                entry.dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>();

                if (Module32First(snapshot, ref entry))
                {
                    do
                    {
                        try
                        {
                            ulong baseAddr = (ulong)entry.modBaseAddr.ToInt64();
                            string dllName = System.IO.Path.GetFileName(entry.szExePath);
                            ParseExportsFromModule(hProc, baseAddr, dllName, result);
                        }
                        catch { }

                        entry.dwSize = (uint)Marshal.SizeOf<MODULEENTRY32>();
                    }
                    while (Module32Next(snapshot, ref entry));
                }
            }
            finally
            {
                CloseHandle(snapshot);
            }

            return result;
        }

        private void ParseExportsFromModule(IntPtr hProc, ulong baseAddr, string dllName, Dictionary<ulong, (string, string)> result)
        {
            // Read DOS header
            byte[] dosHeader = new byte[64];
            IntPtr buf = Marshal.AllocHGlobal(64);
            if (!ReadProcessMemory(hProc, (IntPtr)baseAddr, buf, 64, out _))
            {
                Marshal.FreeHGlobal(buf);
                return;
            }
            Marshal.Copy(buf, dosHeader, 0, 64);

            if (BitConverter.ToUInt16(dosHeader, 0) != 0x5A4D)
            {
                Marshal.FreeHGlobal(buf);
                return;
            }

            int e_lfanew = BitConverter.ToInt32(dosHeader, 60);
            if (e_lfanew <= 0 || e_lfanew > 0x1000)
            {
                Marshal.FreeHGlobal(buf);
                return;
            }

            // Read PE headers (enough for optional header + data directories)
            int peHeaderSize = 512;
            byte[] peHeader = new byte[peHeaderSize];
            if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + (ulong)e_lfanew), buf, peHeaderSize, out _))
            {
                Marshal.FreeHGlobal(buf);
                return;
            }
            Marshal.Copy(buf, peHeader, 0, peHeaderSize);
            Marshal.FreeHGlobal(buf);

            if (BitConverter.ToUInt32(peHeader, 0) != 0x00004550) return;

            ushort magic = BitConverter.ToUInt16(peHeader, 24);
            bool is64 = magic == 0x20b;
            int dataDirBase = is64 ? 112 : 96;

            // Export directory is data directory [0]
            if (24 + dataDirBase + 8 > peHeaderSize) return;
            uint exportDirRVA = BitConverter.ToUInt32(peHeader, 24 + dataDirBase);
            uint exportDirSize = BitConverter.ToUInt32(peHeader, 24 + dataDirBase + 4);

            if (exportDirRVA == 0 || exportDirSize == 0) return;

            // Read export directory (40 bytes)
            byte[] exportDir = new byte[40];
            buf = Marshal.AllocHGlobal(40);
            if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + exportDirRVA), buf, 40, out _))
            {
                Marshal.FreeHGlobal(buf);
                return;
            }
            Marshal.Copy(buf, exportDir, 0, 40);
            Marshal.FreeHGlobal(buf);

            uint numFunctions = BitConverter.ToUInt32(exportDir, 20);
            uint numNames = BitConverter.ToUInt32(exportDir, 24);
            uint funcTableRVA = BitConverter.ToUInt32(exportDir, 28);
            uint nameTableRVA = BitConverter.ToUInt32(exportDir, 32);
            uint ordinalTableRVA = BitConverter.ToUInt32(exportDir, 36);

            if (numNames == 0 || numNames > 8192) return;

            // Read name RVAs, ordinals, and function RVAs
            int nameTableSize = (int)(numNames * 4);
            int ordinalTableSize = (int)(numNames * 2);
            int funcTableSize = (int)(numFunctions * 4);

            byte[] nameRVAs = new byte[nameTableSize];
            byte[] ordinals = new byte[ordinalTableSize];
            byte[] funcRVAs = new byte[funcTableSize];

            buf = Marshal.AllocHGlobal(Math.Max(nameTableSize, Math.Max(ordinalTableSize, funcTableSize)));

            try
            {
                if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + nameTableRVA), buf, nameTableSize, out _)) return;
                Marshal.Copy(buf, nameRVAs, 0, nameTableSize);

                if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + ordinalTableRVA), buf, ordinalTableSize, out _)) return;
                Marshal.Copy(buf, ordinals, 0, ordinalTableSize);

                if (!ReadProcessMemory(hProc, (IntPtr)(baseAddr + funcTableRVA), buf, funcTableSize, out _)) return;
                Marshal.Copy(buf, funcRVAs, 0, funcTableSize);
            }
            finally { Marshal.FreeHGlobal(buf); }

            // Resolve each named export
            for (uint i = 0; i < numNames; i++)
            {
                try
                {
                    uint nameRVA = BitConverter.ToUInt32(nameRVAs, (int)(i * 4));
                    ushort ordinal = BitConverter.ToUInt16(ordinals, (int)(i * 2));

                    if (ordinal >= numFunctions) continue;
                    uint funcRVA = BitConverter.ToUInt32(funcRVAs, ordinal * 4);
                    if (funcRVA == 0) continue;

                    // Read function name (up to 128 bytes)
                    byte[] nameBytes = new byte[128];
                    buf = Marshal.AllocHGlobal(128);
                    if (ReadProcessMemory(hProc, (IntPtr)(baseAddr + nameRVA), buf, 128, out _))
                    {
                        Marshal.Copy(buf, nameBytes, 0, 128);
                        int end = Array.IndexOf(nameBytes, (byte)0);
                        if (end > 0)
                        {
                            string funcName = Encoding.ASCII.GetString(nameBytes, 0, end);
                            ulong funcAddr = baseAddr + funcRVA;
                            if (!result.ContainsKey(funcAddr))
                                result[funcAddr] = (dllName, funcName);
                        }
                    }
                    Marshal.FreeHGlobal(buf);
                }
                catch { }
            }
        }

        // ---- Entry Point Recovery ----

        private ulong ReadEntryPoint(int processId, IntPtr hProc, ulong baseAddress)
        {
            if (hProc == IntPtr.Zero || hProc == INVALID_HANDLE_VALUE || baseAddress == 0)
                return 0;

            try
            {
                // Read DOS header (need e_lfanew at offset 60)
                byte[] dosHeader = new byte[64];
                IntPtr dosBuf = Marshal.AllocHGlobal(64);
                if (!ReadProcessMemory(hProc, (IntPtr)baseAddress, dosBuf, 64, out _))
                {
                    Marshal.FreeHGlobal(dosBuf);
                    return 0;
                }
                Marshal.Copy(dosBuf, dosHeader, 0, 64);
                Marshal.FreeHGlobal(dosBuf);

                if (BitConverter.ToUInt16(dosHeader, 0) != 0x5A4D) return 0;
                int e_lfanew = BitConverter.ToInt32(dosHeader, 60);
                if (e_lfanew <= 0 || e_lfanew > 0x1000) return 0;

                // Read PE optional header: AddressOfEntryPoint is at optional_header + 16
                // Optional header starts at e_lfanew + 24 (PE sig 4 + FileHeader 20)
                int optHeaderAddr = e_lfanew + 24;
                byte[] optHeader = new byte[20];
                IntPtr optBuf = Marshal.AllocHGlobal(20);
                if (!ReadProcessMemory(hProc, (IntPtr)(baseAddress + (ulong)optHeaderAddr), optBuf, 20, out _))
                {
                    Marshal.FreeHGlobal(optBuf);
                    return 0;
                }
                Marshal.Copy(optBuf, optHeader, 0, 20);
                Marshal.FreeHGlobal(optBuf);

                uint entryPointRVA = BitConverter.ToUInt32(optHeader, 16);
                if (entryPointRVA == 0) return 0;
                return baseAddress + entryPointRVA;
            }
            catch
            {
                return 0;
            }
        }

        // ---- Kernel-only (return failure) ----

        public int UnprotectProcess(int targetProcessId) => -1;
        public int SuspendProcess(int targetProcessId) => -1;
        public int ResumeProcess(int targetProcessId) => -1;
        public int CheckTablesReady(int targetProcessId) => -1;
        public int UnloadModule(int targetProcessId, ulong moduleBaseAddress) => -1;
        public bool LsassReadMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize) => false;
        public (int status, int pid) KillProcessByName(string processName) => (2, -1);
        public int UnloadDriverByName(string driverName) => 2;
        public List<(string basePath, string baseName, ulong baseAddress, uint imageSize, uint flags, DateTime loadTime, ulong entryPoint, uint checkSum)> EnumerateDrivers() => new List<(string, string, ulong, uint, uint, DateTime, ulong, uint)>();

        // ---- Kernel-mode operations (not available in usermode) ----

        public byte[] GetThreadContext(int processId, int threadId, int contextFlags) => null;
        public bool SetThreadContext(int processId, int threadId, byte[] context) => false;
        public bool DebugAttach(int processId) => false;
        public (int eventCode, int threadId, ulong eventAddress, int exceptionCode) DebugWaitEvent(int timeoutMs) => (0, 0, 0, 0);
        public bool DebugContinue(int threadId, int continueStatus) => false;

        // ---- Scanning operations ----

        public List<(ulong baseAddress, ulong regionSize, uint protect, uint state, uint type)> EnumRegions(int targetProcessId)
        {
            var result = new List<(ulong, ulong, uint, uint, uint)>();
            IntPtr hProc = GetProcessHandle(targetProcessId);
            if (hProc == IntPtr.Zero || hProc == INVALID_HANDLE_VALUE) return result;

            IntPtr address = IntPtr.Zero;
            var mbi = new MEMORY_BASIC_INFORMATION();
            uint mbiSize = (uint)Marshal.SizeOf<MEMORY_BASIC_INFORMATION>();

            while (VirtualQueryEx(hProc, address, out mbi, mbiSize) != 0)
            {
                result.Add(((ulong)mbi.BaseAddress.ToInt64(), (ulong)mbi.RegionSize.ToInt64(),
                    mbi.Protect, mbi.State, mbi.Type));

                long next = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                if (next <= 0 || next > long.MaxValue) break;
                address = new IntPtr(next);
            }

            return result;
        }

        public List<(ulong address, bool isUnicode, string value)> DumpLiveStrings(int targetProcessId, int minStringLength = 4)
        {
            var result = new List<(ulong, bool, string)>();
            var regions = EnumRegions(targetProcessId);

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (state != 0x1000) continue; // MEM_COMMIT
                if (type != 0x20000 && type != 0x40000) continue; // MEM_PRIVATE or MEM_MAPPED
                if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0)
                    continue; // not readable

                int size = (int)Math.Min(regionSize, 0x100000); // cap at 1MB per region
                IntPtr buffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buffer == IntPtr.Zero) continue;
                try
                {
                    if (!CopyVirtualMemory(targetProcessId, (IntPtr)baseAddr, buffer, size))
                        continue;

                    byte[] data = new byte[size];
                    Marshal.Copy(buffer, data, 0, size);

                    // Scan for ASCII strings
                    int runStart = -1;
                    for (int i = 0; i < size; i++)
                    {
                        bool printable = data[i] >= 0x20 && data[i] < 0x7F;
                        if (printable) { if (runStart < 0) runStart = i; }
                        else
                        {
                            if (runStart >= 0)
                            {
                                int len = i - runStart;
                                if (len >= minStringLength)
                                {
                                    string s = Encoding.ASCII.GetString(data, runStart, len);
                                    result.Add((baseAddr + (ulong)runStart, false, s));
                                }
                                runStart = -1;
                            }
                        }
                    }
                }
                finally
                {
                    VirtualFree(buffer, UIntPtr.Zero, MEM_RELEASE);
                }

                if (result.Count > 50000) break; // safety limit
            }

            return result;
        }

        public List<ulong> FindPattern(int targetProcessId, byte[] pattern, byte wildcard = 0xCC, int maxResults = 1000)
        {
            var result = new List<ulong>();
            var regions = EnumRegions(targetProcessId);

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (state != 0x1000) continue;
                if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0)
                    continue;

                int size = (int)Math.Min(regionSize, 0x1000000);
                IntPtr buffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buffer == IntPtr.Zero) continue;
                try
                {
                    if (!CopyVirtualMemory(targetProcessId, (IntPtr)baseAddr, buffer, size))
                        continue;

                    byte[] data = new byte[size];
                    Marshal.Copy(buffer, data, 0, size);

                    for (int i = 0; i <= size - pattern.Length; i++)
                    {
                        bool match = true;
                        for (int j = 0; j < pattern.Length; j++)
                        {
                            if (pattern[j] != wildcard && data[i + j] != pattern[j])
                            {
                                match = false;
                                break;
                            }
                        }
                        if (match)
                        {
                            result.Add(baseAddr + (ulong)i);
                            if (result.Count >= maxResults) return result;
                        }
                    }
                }
                finally
                {
                    VirtualFree(buffer, UIntPtr.Zero, MEM_RELEASE);
                }
            }

            return result;
        }

        public (byte[] metadata, ulong address) ReadIl2CppMetadata(int targetProcessId)
        {
            const uint IL2CPP_MAGIC = 0xFAB11BAF;
            var regions = EnumRegions(targetProcessId);

            // Phase 1: Scan for plain magic (unencrypted metadata in memory)
            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (state != 0x1000) continue;
                if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0)
                    continue;

                int size = (int)Math.Min(regionSize, 0x4000000);
                IntPtr buffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buffer == IntPtr.Zero) continue;
                try
                {
                    if (!CopyVirtualMemory(targetProcessId, (IntPtr)baseAddr, buffer, size))
                        continue;

                    byte[] data = new byte[size];
                    Marshal.Copy(buffer, data, 0, size);

                    for (int i = 0; i <= size - 280; i += 4)
                    {
                        if (BitConverter.ToUInt32(data, i) == IL2CPP_MAGIC)
                        {
                            int version = BitConverter.ToInt32(data, i + 4);
                            if (version < 16 || version > 40) continue;

                            byte[] candidate = new byte[Math.Min(size - i, 0x2000000)];
                            Array.Copy(data, i, candidate, 0, candidate.Length);

                            if (!Il2CppDumper.ValidateMetadataStructure(candidate))
                                continue;

                            int metadataSize = Il2CppDumper.EstimateMetadataSizeFromHeader(candidate);
                            if (metadataSize <= 0) continue;

                            if (metadataSize > candidate.Length)
                            {
                                // Need to re-read with the correct size
                                int fullSize = metadataSize + 256;
                                IntPtr fullBuf = VirtualAlloc(IntPtr.Zero, (UIntPtr)fullSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                if (fullBuf != IntPtr.Zero)
                                {
                                    try
                                    {
                                        if (CopyVirtualMemory(targetProcessId, (IntPtr)(baseAddr + (ulong)i), fullBuf, fullSize))
                                        {
                                            byte[] full = new byte[fullSize];
                                            Marshal.Copy(fullBuf, full, 0, fullSize);
                                            return (full, baseAddr + (ulong)i);
                                        }
                                    }
                                    finally { VirtualFree(fullBuf, UIntPtr.Zero, MEM_RELEASE); }
                                }
                            }

                            byte[] result = new byte[metadataSize];
                            Array.Copy(candidate, 0, result, 0, Math.Min(metadataSize, candidate.Length));
                            return (result, baseAddr + (ulong)i);
                        }
                    }
                }
                finally
                {
                    VirtualFree(buffer, UIntPtr.Zero, MEM_RELEASE);
                }
            }

            // Phase 2: Scan for XOR-encrypted metadata (common obfuscation: single-byte XOR)
            // Common keys: 0xFE (Guardian Tales, Tale of Immortal), 0xFF, 0xAA, 0x55
            byte[] commonXorKeys = { 0xFE, 0xFF, 0xAA, 0x55, 0xCC, 0x42 };
            byte[] magicBytes = { 0xAF, 0x1B, 0xB1, 0xFA };

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                if (state != 0x1000) continue;
                if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0)
                    continue;

                int size = (int)Math.Min(regionSize, 0x4000000);
                IntPtr buffer = VirtualAlloc(IntPtr.Zero, (UIntPtr)size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buffer == IntPtr.Zero) continue;
                try
                {
                    if (!CopyVirtualMemory(targetProcessId, (IntPtr)baseAddr, buffer, size))
                        continue;

                    byte[] data = new byte[size];
                    Marshal.Copy(buffer, data, 0, size);

                    foreach (byte xorKey in commonXorKeys)
                    {
                        byte[] encMagic = { (byte)(magicBytes[0] ^ xorKey), (byte)(magicBytes[1] ^ xorKey),
                                           (byte)(magicBytes[2] ^ xorKey), (byte)(magicBytes[3] ^ xorKey) };

                        for (int i = 0; i <= size - 280; i += 4)
                        {
                            if (data[i] == encMagic[0] && data[i + 1] == encMagic[1] &&
                                data[i + 2] == encMagic[2] && data[i + 3] == encMagic[3])
                            {
                                int remaining = size - i;
                                int decryptSize = Math.Min(remaining, 0x2000000);
                                byte[] decrypted = new byte[decryptSize];
                                for (int j = 0; j < decryptSize; j++)
                                    decrypted[j] = (byte)(data[i + j] ^ xorKey);

                                if (!Il2CppDumper.ValidateMetadataStructure(decrypted))
                                    continue;

                                int metaSize = Il2CppDumper.EstimateMetadataSizeFromHeader(decrypted);
                                if (metaSize <= 0 || metaSize > decryptSize) continue;

                                byte[] result = new byte[metaSize];
                                Array.Copy(decrypted, 0, result, 0, metaSize);
                                return (result, baseAddr + (ulong)i);
                            }
                        }
                    }

                    // Phase 2b: brute-force all 255 XOR keys (slower, last resort per region)
                    for (int i = 0; i <= size - 280; i += 4)
                    {
                        byte[] xorResult = Il2CppDumper.TryXorDecryptMagic(data, i, out byte foundKey);
                        if (xorResult != null && Il2CppDumper.ValidateMetadataStructure(xorResult))
                        {
                            int metaSize = Il2CppDumper.EstimateMetadataSizeFromHeader(xorResult);
                            if (metaSize > 0 && metaSize <= xorResult.Length)
                            {
                                byte[] result = new byte[metaSize];
                                Array.Copy(xorResult, 0, result, 0, metaSize);
                                return (result, baseAddr + (ulong)i);
                            }
                        }
                    }
                }
                finally
                {
                    VirtualFree(buffer, UIntPtr.Zero, MEM_RELEASE);
                }
            }

            // Phase 3: Find s_GlobalMetadataHeader pointer in GameAssembly.dll .data section
            // The decrypted metadata pointer is stored in a static global after MetadataCache::Initialize
            if (GetModuleSummaryList(targetProcessId, out ModuleSummary[] modules))
            {
                ModuleSummary gameAssembly = null;
                foreach (var m in modules)
                {
                    if (m.ModuleName != null &&
                        m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        gameAssembly = m;
                        break;
                    }
                }

                if (gameAssembly != null)
                {
                    // Read PE header to find .data section
                    int headerSize = 0x1000;
                    IntPtr hdrBuf = VirtualAlloc(IntPtr.Zero, (UIntPtr)headerSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                    if (hdrBuf != IntPtr.Zero)
                    {
                        try
                        {
                            if (CopyVirtualMemory(targetProcessId, (IntPtr)gameAssembly.BaseAddress, hdrBuf, headerSize))
                            {
                                byte[] hdr = new byte[headerSize];
                                Marshal.Copy(hdrBuf, hdr, 0, headerSize);

                                var sections = ParsePESections(hdr, gameAssembly.BaseAddress);
                                foreach (var (secName, secVA, secVSize) in sections)
                                {
                                    if (secName != ".data" && secName != ".rdata") continue;

                                    int scanSize = (int)Math.Min(secVSize, 0x2000000);
                                    IntPtr secBuf = VirtualAlloc(IntPtr.Zero, (UIntPtr)scanSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                    if (secBuf == IntPtr.Zero) continue;
                                    try
                                    {
                                        if (!CopyVirtualMemory(targetProcessId, (IntPtr)secVA, secBuf, scanSize))
                                            continue;

                                        byte[] secData = new byte[scanSize];
                                        Marshal.Copy(secBuf, secData, 0, scanSize);

                                        // Scan for pointers that point to valid metadata
                                        for (int i = 0; i <= scanSize - 8; i += 8)
                                        {
                                            ulong ptr = BitConverter.ToUInt64(secData, i);
                                            if (ptr < 0x10000 || ptr > 0x7FFFFFFFFFFF) continue;

                                            // Read 8 bytes at the pointer to check for magic
                                            IntPtr checkBuf = VirtualAlloc(IntPtr.Zero, (UIntPtr)8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                            if (checkBuf == IntPtr.Zero) continue;
                                            try
                                            {
                                                if (!CopyVirtualMemory(targetProcessId, (IntPtr)ptr, checkBuf, 8))
                                                    continue;

                                                byte[] check = new byte[8];
                                                Marshal.Copy(checkBuf, check, 0, 8);

                                                uint maybeMagic = BitConverter.ToUInt32(check, 0);
                                                int maybeVersion = BitConverter.ToInt32(check, 4);

                                                if (maybeMagic == IL2CPP_MAGIC && maybeVersion >= 16 && maybeVersion <= 40)
                                                {
                                                    // Found the pointer. Read enough for header first.
                                                    int readSize = 0x1000;
                                                    IntPtr metaBuf = VirtualAlloc(IntPtr.Zero, (UIntPtr)readSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                                    if (metaBuf == IntPtr.Zero) continue;
                                                    try
                                                    {
                                                        if (!CopyVirtualMemory(targetProcessId, (IntPtr)ptr, metaBuf, readSize))
                                                            continue;

                                                        byte[] headerData = new byte[readSize];
                                                        Marshal.Copy(metaBuf, headerData, 0, readSize);

                                                        if (!Il2CppDumper.ValidateMetadataStructure(headerData))
                                                            continue;

                                                        int fullSize = Il2CppDumper.EstimateMetadataSizeFromHeader(headerData);
                                                        if (fullSize <= 0) continue;

                                                        IntPtr fullBuf = VirtualAlloc(IntPtr.Zero, (UIntPtr)fullSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                                        if (fullBuf == IntPtr.Zero) continue;
                                                        try
                                                        {
                                                            if (CopyVirtualMemory(targetProcessId, (IntPtr)ptr, fullBuf, fullSize))
                                                            {
                                                                byte[] result = new byte[fullSize];
                                                                Marshal.Copy(fullBuf, result, 0, fullSize);
                                                                return (result, ptr);
                                                            }
                                                        }
                                                        finally { VirtualFree(fullBuf, UIntPtr.Zero, MEM_RELEASE); }
                                                    }
                                                    finally { VirtualFree(metaBuf, UIntPtr.Zero, MEM_RELEASE); }
                                                }
                                            }
                                            finally { VirtualFree(checkBuf, UIntPtr.Zero, MEM_RELEASE); }
                                        }
                                    }
                                    finally { VirtualFree(secBuf, UIntPtr.Zero, MEM_RELEASE); }
                                }
                            }
                        }
                        finally { VirtualFree(hdrBuf, UIntPtr.Zero, MEM_RELEASE); }
                    }
                }
            }

            return (null, 0);
        }

        private List<(string name, ulong va, uint vsize)> ParsePESections(byte[] peHeader, ulong imageBase)
        {
            var result = new List<(string, ulong, uint)>();
            if (peHeader.Length < 64) return result;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            if (peOff < 0 || peOff + 24 >= peHeader.Length) return result;
            if (peHeader[peOff] != 'P' || peHeader[peOff + 1] != 'E') return result;

            ushort numSections = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionStart = peOff + 24 + optHeaderSize;

            for (int i = 0; i < numSections; i++)
            {
                int off = sectionStart + i * 40;
                if (off + 40 > peHeader.Length) break;

                string name = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                uint vsize = BitConverter.ToUInt32(peHeader, off + 8);
                uint rva = BitConverter.ToUInt32(peHeader, off + 12);

                result.Add((name, imageBase + rva, vsize));
            }
            return result;
        }

        // ---- Anti-Cheat Bypass (kernel-only — return empty/failed in user mode) ----

        public (int callbackCount, int removedCount, CallbackEntry[] callbacks) EnumKernelCallbacks(bool removeCallbacks) => (0, 0, new CallbackEntry[0]);
        public (int status, int clonedProcessId) CloneProcess(int processId) => (2, -1);
        public (int vadCount, VADEntry[] vads) EnumVadTree(int processId) => (0, new VADEntry[0]);
        public (int handleCount, HandleEntry[] handles) EnumHandles(int processId) => (0, new HandleEntry[0]);
        public (int moduleCount, KernelModuleEntry[] modules) EnumKernelModules() => (0, new KernelModuleEntry[0]);
    }
}
