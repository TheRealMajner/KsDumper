using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using KsDumperClient.Utility;

using static KsDumperClient.Driver.Operations;

namespace KsDumperClient.Driver
{
    public class DriverInterface : IMemoryReader
    {
        private readonly IntPtr driverHandle;

        public DriverInterface(string registryPath)
        {
            driverHandle = WinApi.CreateFileA(registryPath, FileAccess.ReadWrite, 
                FileShare.ReadWrite, IntPtr.Zero, FileMode.Open, 0, IntPtr.Zero);
        }

        public bool HasValidHandle()
        {
            return driverHandle != WinApi.INVALID_HANDLE_VALUE;
        }

        public bool IsKernelMode => driverHandle != WinApi.INVALID_HANDLE_VALUE;

        public bool GetProcessSummaryList(out ProcessSummary[] result)
        {
            result = new ProcessSummary[0];

            if (driverHandle == WinApi.INVALID_HANDLE_VALUE)
                return false;

            for (int attempt = 0; attempt < 3; attempt++)
            {
                int requiredBufferSize = GetProcessListRequiredBufferSize();
                if (requiredBufferSize <= 0)
                    return false;

                int allocSize = requiredBufferSize + requiredBufferSize / 4 + 4096;

                // Use VirtualAlloc instead of HeapAlloc — the kernel driver writes directly
                // to this buffer, and HeapAlloc places metadata adjacent to the allocation
                // that gets corrupted by kernel-mode writes at buffer boundaries.
                IntPtr bufferPointer = WinApi.VirtualAlloc(
                    IntPtr.Zero,
                    (UIntPtr)allocSize,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE,
                    WinApi.PAGE_READWRITE);

                if (bufferPointer == IntPtr.Zero)
                    return false;

                KERNEL_PROCESS_LIST_OPERATION operation = new KERNEL_PROCESS_LIST_OPERATION
                {
                    bufferAddress = (ulong)bufferPointer.ToInt64(),
                    bufferSize = allocSize
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_PROCESS_LIST_OPERATION>();

                try
                {
                    if (WinApi.DeviceIoControl(driverHandle, IO_GET_PROCESS_LIST, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                    {
                        operation = MarshalUtility.GetStructFromMemory<KERNEL_PROCESS_LIST_OPERATION>(operationPointer);
                        operationPointer = IntPtr.Zero;

                        if (operation.processCount > 0)
                        {
                            int dataSize = operation.processCount * 537;
                            byte[] managedBuffer = new byte[dataSize];
                            Marshal.Copy(bufferPointer, managedBuffer, 0, dataSize);

                            result = new ProcessSummary[operation.processCount];

                            using (BinaryReader reader = new BinaryReader(new MemoryStream(managedBuffer)))
                            {
                                for (int i = 0; i < result.Length; i++)
                                {
                                    result[i] = ProcessSummary.FromStream(reader);
                                }
                            }
                            return true;
                        }
                    }
                }
                finally
                {
                    WinApi.VirtualFree(bufferPointer, UIntPtr.Zero, WinApi.MEM_RELEASE);
                    if (operationPointer != IntPtr.Zero)
                        Marshal.FreeHGlobal(operationPointer);
                }
            }
            return false;
        }

        private int GetProcessListRequiredBufferSize()
        {
            IntPtr operationPointer = MarshalUtility.AllocEmptyStruct<KERNEL_PROCESS_LIST_OPERATION>();
            int operationSize = Marshal.SizeOf<KERNEL_PROCESS_LIST_OPERATION>();

            if (WinApi.DeviceIoControl(driverHandle, IO_GET_PROCESS_LIST, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
            {
                KERNEL_PROCESS_LIST_OPERATION operation = MarshalUtility.GetStructFromMemory<KERNEL_PROCESS_LIST_OPERATION>(operationPointer);

                if (operation.bufferSize > 0)
                    return operation.bufferSize;
            }
            else
            {
                Marshal.FreeHGlobal(operationPointer);
            }
            return 0;
        }

        public bool GetModuleSummaryList(int targetProcessId, out ModuleSummary[] result)
        {
            result = new ModuleSummary[0];

            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                int requiredBufferSize = GetModuleListRequiredBufferSize(targetProcessId);

                if (requiredBufferSize > 0)
                {
                    IntPtr bufferPointer = WinApi.VirtualAlloc(
                        IntPtr.Zero,
                        (UIntPtr)requiredBufferSize,
                        WinApi.MEM_COMMIT | WinApi.MEM_RESERVE,
                        WinApi.PAGE_READWRITE);

                    if (bufferPointer == IntPtr.Zero)
                        return false;

                    KERNEL_MODULE_LIST_OPERATION operation = new KERNEL_MODULE_LIST_OPERATION
                    {
                        bufferAddress = (ulong)bufferPointer.ToInt64(),
                        bufferSize = requiredBufferSize,
                        targetProcessId = targetProcessId
                    };
                    IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                    int operationSize = Marshal.SizeOf<KERNEL_MODULE_LIST_OPERATION>();

                    try
                    {
                        if (WinApi.DeviceIoControl(driverHandle, IO_GET_MODULE_LIST, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                        {
                            operation = MarshalUtility.GetStructFromMemory<KERNEL_MODULE_LIST_OPERATION>(operationPointer);
                            operationPointer = IntPtr.Zero;

                            if (operation.moduleCount > 0)
                            {
                                byte[] managedBuffer = new byte[requiredBufferSize];
                                Marshal.Copy(bufferPointer, managedBuffer, 0, requiredBufferSize);

                                result = new ModuleSummary[operation.moduleCount];

                                using (BinaryReader reader = new BinaryReader(new MemoryStream(managedBuffer)))
                                {
                                    for (int i = 0; i < result.Length; i++)
                                    {
                                        result[i] = ModuleSummary.FromStream(reader, null);
                                    }
                                }
                                return true;
                            }
                        }
                    }
                    finally
                    {
                        WinApi.VirtualFree(bufferPointer, UIntPtr.Zero, WinApi.MEM_RELEASE);
                        if (operationPointer != IntPtr.Zero)
                            Marshal.FreeHGlobal(operationPointer);
                    }
                }
            }
            return false;
        }

        private int GetModuleListRequiredBufferSize(int targetProcessId)
        {
            KERNEL_MODULE_LIST_OPERATION operation = new KERNEL_MODULE_LIST_OPERATION
            {
                targetProcessId = targetProcessId
            };
            IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
            int operationSize = Marshal.SizeOf<KERNEL_MODULE_LIST_OPERATION>();

            if (WinApi.DeviceIoControl(driverHandle, IO_GET_MODULE_LIST, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
            {
                KERNEL_MODULE_LIST_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_MODULE_LIST_OPERATION>(operationPointer);

                if (response.moduleCount == 0 && response.bufferSize > 0)
                {
                    return response.bufferSize;
                }
            }
            return 0;
        }

        public int UnprotectProcess(int targetProcessId)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_UNPROTECT_OPERATION operation = new KERNEL_UNPROTECT_OPERATION
                {
                    targetProcessId = targetProcessId,
                    status = 0
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_UNPROTECT_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_UNPROTECT_PROCESS, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                {
                    KERNEL_UNPROTECT_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_UNPROTECT_OPERATION>(operationPointer);
                    return response.status;
                }
                Marshal.FreeHGlobal(operationPointer);
            }
            return -1;
        }

        public int CheckTablesReady(int targetProcessId)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_TABLE_CHECK_OPERATION operation = new KERNEL_TABLE_CHECK_OPERATION
                {
                    targetProcessId = targetProcessId,
                    status = TABLES_NOT_READY
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_TABLE_CHECK_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_CHECK_TABLES_READY, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                {
                    KERNEL_TABLE_CHECK_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_TABLE_CHECK_OPERATION>(operationPointer);
                    return response.status;
                }
                Marshal.FreeHGlobal(operationPointer);
            }
            return -1;
        }

        public int SuspendProcess(int targetProcessId)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_SUSPEND_OPERATION operation = new KERNEL_SUSPEND_OPERATION
                {
                    targetProcessId = targetProcessId,
                    threadCount = 0
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_SUSPEND_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_SUSPEND_PROCESS, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                {
                    KERNEL_SUSPEND_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_SUSPEND_OPERATION>(operationPointer);
                    return response.threadCount;
                }
                Marshal.FreeHGlobal(operationPointer);
            }
            return -1;
        }

        public int ResumeProcess(int targetProcessId)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_SUSPEND_OPERATION operation = new KERNEL_SUSPEND_OPERATION
                {
                    targetProcessId = targetProcessId,
                    threadCount = 0
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_SUSPEND_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_RESUME_PROCESS, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                {
                    KERNEL_SUSPEND_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_SUSPEND_OPERATION>(operationPointer);
                    return response.threadCount;
                }
                Marshal.FreeHGlobal(operationPointer);
            }
            return -1;
        }

        // Reads export tables of all loaded modules in the target process.
        // Returns a map: absolute function address → (dllName, functionName).
        public Dictionary<ulong, (string dllName, string funcName)> GetExportMap(int targetProcessId)
        {
            var result = new Dictionary<ulong, (string, string)>();

            if (driverHandle == WinApi.INVALID_HANDLE_VALUE)
                return result;

            // Phase 1: query required buffer size
            EXPORT_MAP_OPERATION query = new EXPORT_MAP_OPERATION
            {
                targetProcessId = targetProcessId,
                bufferAddress = 0,
                bufferSize = 0,
                requiredSize = 0,
                moduleCount = 0
            };
            IntPtr queryPtr = MarshalUtility.CopyStructToMemory(query);
            int opSize = Marshal.SizeOf<EXPORT_MAP_OPERATION>();

            if (!WinApi.DeviceIoControl(driverHandle, IO_GET_EXPORT_MAP, queryPtr, opSize, queryPtr, opSize, out int _, IntPtr.Zero))
            {
                Marshal.FreeHGlobal(queryPtr);
                return result;
            }

            query = MarshalUtility.GetStructFromMemory<EXPORT_MAP_OPERATION>(queryPtr, false);
            Marshal.FreeHGlobal(queryPtr);

            if (query.requiredSize <= 0 || query.moduleCount <= 0)
                return result;

            // Phase 2: allocate with extra padding (modules can load between Phase 1 and 2)
            int allocSize = query.requiredSize + 64 * 1024;
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)allocSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return result;

            EXPORT_MAP_OPERATION fill = new EXPORT_MAP_OPERATION
            {
                targetProcessId = targetProcessId,
                bufferAddress = (ulong)buffer.ToInt64(),
                bufferSize = allocSize,
                requiredSize = 0,
                moduleCount = 0
            };
            IntPtr fillPtr = MarshalUtility.CopyStructToMemory(fill);

            if (WinApi.DeviceIoControl(driverHandle, IO_GET_EXPORT_MAP, fillPtr, opSize, fillPtr, opSize, out int _, IntPtr.Zero))
            {
                fill = MarshalUtility.GetStructFromMemory<EXPORT_MAP_OPERATION>(fillPtr, false);

                if (fill.moduleCount > 0)
                {
                    int copySize = Math.Min(fill.requiredSize, allocSize);
                    byte[] raw = new byte[copySize];
                    Marshal.Copy(buffer, raw, 0, copySize);

                    const int MOD_HEADER_SIZE = 140;
                    const int ENTRY_SIZE = 74;

                    int offset = 0;
                    for (int m = 0; m < fill.moduleCount && offset + MOD_HEADER_SIZE <= raw.Length; m++)
                    {
                        string dllName = System.Text.Encoding.Unicode.GetString(raw, offset + 8, 128).Split('\0')[0];
                        int entryCount = BitConverter.ToInt32(raw, offset + 136);

                        offset += MOD_HEADER_SIZE;

                        for (int e = 0; e < entryCount && offset + ENTRY_SIZE <= raw.Length; e++)
                        {
                            ulong addr = BitConverter.ToUInt64(raw, offset);
                            string funcName = System.Text.Encoding.ASCII.GetString(raw, offset + 8, 64).Split('\0')[0];

                            if (addr != 0 && !string.IsNullOrEmpty(funcName) && !result.ContainsKey(addr))
                            {
                                result[addr] = (dllName, funcName);
                            }

                            offset += ENTRY_SIZE;
                        }
                    }
                }
            }

            WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            Marshal.FreeHGlobal(fillPtr);
            return result;
        }

        public bool CopyVirtualMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_COPY_MEMORY_OPERATION operation = new KERNEL_COPY_MEMORY_OPERATION
                {
                    targetProcessId = targetProcessId,
                    targetAddress = (ulong)targetAddress.ToInt64(),
                    bufferAddress = (ulong)bufferAddress.ToInt64(),
                    bufferSize = bufferSize
                };

                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);

                bool result = WinApi.DeviceIoControl(driverHandle, IO_COPY_MEMORY, operationPointer, Marshal.SizeOf<KERNEL_COPY_MEMORY_OPERATION>(), IntPtr.Zero, 0, out int _, IntPtr.Zero);
                Marshal.FreeHGlobal(operationPointer);

                return result;
            }
            return false;
        }

        public bool WriteVirtualMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_COPY_MEMORY_OPERATION operation = new KERNEL_COPY_MEMORY_OPERATION
                {
                    targetProcessId = targetProcessId,
                    targetAddress = (ulong)targetAddress.ToInt64(),
                    bufferAddress = (ulong)bufferAddress.ToInt64(),
                    bufferSize = bufferSize
                };

                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);

                bool result = WinApi.DeviceIoControl(driverHandle, IO_WRITE_MEMORY, operationPointer, Marshal.SizeOf<KERNEL_COPY_MEMORY_OPERATION>(), IntPtr.Zero, 0, out int _, IntPtr.Zero);
                Marshal.FreeHGlobal(operationPointer);

                return result;
            }
            return false;
        }

        // Scans all readable memory in the target process for decrypted strings.
        // Returns a list of (address, isUnicode, value) tuples.
        public List<(ulong address, bool isUnicode, string value)> DumpLiveStrings(int targetProcessId, int minStringLength = 4)
        {
            var result = new List<(ulong, bool, string)>();

            if (driverHandle == WinApi.INVALID_HANDLE_VALUE)
                return result;

            // Phase 1: get required buffer size
            KERNEL_STRING_DUMP_OPERATION query = new KERNEL_STRING_DUMP_OPERATION
            {
                targetProcessId = targetProcessId,
                minStringLength = minStringLength,
                bufferAddress = 0,
                bufferSize = 0,
                requiredSize = 0,
                stringCount = 0
            };
            IntPtr queryPtr = MarshalUtility.CopyStructToMemory(query);
            int opSize = Marshal.SizeOf<KERNEL_STRING_DUMP_OPERATION>();

            if (!WinApi.DeviceIoControl(driverHandle, IO_DUMP_STRINGS, queryPtr, opSize, queryPtr, opSize, out int _, IntPtr.Zero))
            {
                Marshal.FreeHGlobal(queryPtr);
                return result;
            }

            query = MarshalUtility.GetStructFromMemory<KERNEL_STRING_DUMP_OPERATION>(queryPtr, false);
            Marshal.FreeHGlobal(queryPtr);

            if (query.requiredSize <= 0 || query.stringCount <= 0)
                return result;

            // Phase 2: allocate buffer with padding and scan again
            int allocSize = query.requiredSize + 64 * 1024;
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)allocSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return result;

            KERNEL_STRING_DUMP_OPERATION fill = new KERNEL_STRING_DUMP_OPERATION
            {
                targetProcessId = targetProcessId,
                minStringLength = minStringLength,
                bufferAddress = (ulong)buffer.ToInt64(),
                bufferSize = allocSize,
                requiredSize = 0,
                stringCount = 0
            };
            IntPtr fillPtr = MarshalUtility.CopyStructToMemory(fill);

            if (WinApi.DeviceIoControl(driverHandle, IO_DUMP_STRINGS, fillPtr, opSize, fillPtr, opSize, out int _, IntPtr.Zero))
            {
                fill = MarshalUtility.GetStructFromMemory<KERNEL_STRING_DUMP_OPERATION>(fillPtr, false);

                if (fill.stringCount > 0)
                {
                    int copySize = Math.Min(fill.requiredSize, allocSize);
                    byte[] raw = new byte[copySize];
                    Marshal.Copy(buffer, raw, 0, copySize);
                    result = ParseStringBuffer(raw);
                }
            }

            WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            Marshal.FreeHGlobal(fillPtr);
            return result;
        }

        private List<(ulong address, bool isUnicode, string value)> ParseStringBuffer(byte[] raw)
        {
            var result = new List<(ulong, bool, string)>();
            int offset = 0;
            const int headerSize = 11; // 8 (address) + 2 (byteLength) + 1 (isUnicode)

            while (offset + headerSize <= raw.Length)
            {
                ulong address = BitConverter.ToUInt64(raw, offset);
                ushort byteLength = BitConverter.ToUInt16(raw, offset + 8);
                bool isUnicode = raw[offset + 10] != 0;

                offset += headerSize;

                if (offset + byteLength > raw.Length)
                    break;

                string value;
                if (isUnicode)
                    value = System.Text.Encoding.Unicode.GetString(raw, offset, byteLength);
                else
                    value = System.Text.Encoding.ASCII.GetString(raw, offset, byteLength);

                result.Add((address, isUnicode, value));
                offset += byteLength;
            }

            return result;
        }

        // Enumerates all committed memory regions in the target process.
        // Returns list of (baseAddress, regionSize, protect, state, type).
        public List<(ulong baseAddress, ulong regionSize, uint protect, uint state, uint type)> EnumRegions(int targetProcessId)
        {
            var result = new List<(ulong, ulong, uint, uint, uint)>();

            if (driverHandle == WinApi.INVALID_HANDLE_VALUE)
                return result;

            // Phase 1: get required size
            KERNEL_ENUM_REGIONS_OPERATION query = new KERNEL_ENUM_REGIONS_OPERATION
            {
                targetProcessId = targetProcessId,
                bufferAddress = 0,
                bufferSize = 0,
                requiredSize = 0,
                regionCount = 0
            };
            IntPtr queryPtr = MarshalUtility.CopyStructToMemory(query);
            int opSize = Marshal.SizeOf<KERNEL_ENUM_REGIONS_OPERATION>();

            if (!WinApi.DeviceIoControl(driverHandle, IO_ENUM_REGIONS, queryPtr, opSize, queryPtr, opSize, out int _, IntPtr.Zero))
            {
                Marshal.FreeHGlobal(queryPtr);
                return result;
            }

            query = MarshalUtility.GetStructFromMemory<KERNEL_ENUM_REGIONS_OPERATION>(queryPtr, false);
            Marshal.FreeHGlobal(queryPtr);

            if (query.requiredSize <= 0 || query.regionCount <= 0)
                return result;

            // Phase 2: read regions with padding
            int allocSize = query.requiredSize + 64 * 1024;
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)allocSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return result;

            KERNEL_ENUM_REGIONS_OPERATION fill = new KERNEL_ENUM_REGIONS_OPERATION
            {
                targetProcessId = targetProcessId,
                bufferAddress = (ulong)buffer.ToInt64(),
                bufferSize = allocSize,
                requiredSize = 0,
                regionCount = 0
            };
            IntPtr fillPtr = MarshalUtility.CopyStructToMemory(fill);

            if (WinApi.DeviceIoControl(driverHandle, IO_ENUM_REGIONS, fillPtr, opSize, fillPtr, opSize, out int _, IntPtr.Zero))
            {
                fill = MarshalUtility.GetStructFromMemory<KERNEL_ENUM_REGIONS_OPERATION>(fillPtr, false);

                if (fill.regionCount > 0)
                {
                    int copySize = Math.Min(fill.requiredSize, allocSize);
                    byte[] raw = new byte[copySize];
                    Marshal.Copy(buffer, raw, 0, copySize);

                    const int entrySize = 28;
                    int offset = 0;
                    for (int i = 0; i < fill.regionCount && offset + entrySize <= raw.Length; i++)
                    {
                        ulong baseAddr = BitConverter.ToUInt64(raw, offset);
                        ulong size = BitConverter.ToUInt64(raw, offset + 8);
                        uint protect = BitConverter.ToUInt32(raw, offset + 16);
                        uint state = BitConverter.ToUInt32(raw, offset + 20);
                        uint type = BitConverter.ToUInt32(raw, offset + 24);
                        result.Add((baseAddr, size, protect, state, type));
                        offset += entrySize;
                    }
                }
            }

            WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            Marshal.FreeHGlobal(fillPtr);
            return result;
        }

        // Scans process memory for a byte pattern with wildcard support.
        public List<ulong> FindPattern(int targetProcessId, byte[] pattern, byte wildcard = 0xCC, int maxResults = 1000)
        {
            var result = new List<ulong>();

            if (driverHandle == WinApi.INVALID_HANDLE_VALUE || pattern.Length == 0)
                return result;

            IntPtr patternPtr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)pattern.Length,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (patternPtr == IntPtr.Zero) return result;
            Marshal.Copy(pattern, 0, patternPtr, pattern.Length);

            int resultsSize = maxResults * 8;
            IntPtr resultsPtr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)resultsSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (resultsPtr == IntPtr.Zero)
            {
                WinApi.VirtualFree(patternPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);
                return result;
            }

            KERNEL_PATTERN_SCAN_OPERATION op = new KERNEL_PATTERN_SCAN_OPERATION
            {
                targetProcessId = targetProcessId,
                patternAddress = (ulong)patternPtr.ToInt64(),
                patternLength = pattern.Length,
                wildcardByte = wildcard,
                resultsAddress = (ulong)resultsPtr.ToInt64(),
                maxResults = maxResults,
                matchCount = 0
            };
            IntPtr opPtr = MarshalUtility.CopyStructToMemory(op);
            int opSize = Marshal.SizeOf<KERNEL_PATTERN_SCAN_OPERATION>();

            if (WinApi.DeviceIoControl(driverHandle, IO_FIND_PATTERN, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
            {
                op = MarshalUtility.GetStructFromMemory<KERNEL_PATTERN_SCAN_OPERATION>(opPtr, false);

                if (op.matchCount > 0)
                {
                    int clampedCount = Math.Min(op.matchCount, maxResults);
                    byte[] raw = new byte[clampedCount * 8];
                    Marshal.Copy(resultsPtr, raw, 0, raw.Length);
                    for (int i = 0; i < clampedCount; i++)
                        result.Add(BitConverter.ToUInt64(raw, i * 8));
                }
            }

            WinApi.VirtualFree(patternPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);
            WinApi.VirtualFree(resultsPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);
            Marshal.FreeHGlobal(opPtr);
            return result;
        }

        // Reads Il2Cpp global-metadata.dat from process memory.
        // Returns (metadata bytes, virtual address) or (null, 0) if not found.
        public (byte[] metadata, ulong address) ReadIl2CppMetadata(int targetProcessId)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE)
                return (null, 0);

            // Phase 1: find metadata and get size
            KERNEL_IL2CPP_METADATA_OPERATION query = new KERNEL_IL2CPP_METADATA_OPERATION
            {
                targetProcessId = targetProcessId,
                bufferAddress = 0,
                bufferSize = 0,
                metadataSize = 0,
                metadataAddress = 0
            };
            IntPtr queryPtr = MarshalUtility.CopyStructToMemory(query);
            int opSize = Marshal.SizeOf<KERNEL_IL2CPP_METADATA_OPERATION>();

            if (!WinApi.DeviceIoControl(driverHandle, IO_READ_IL2CPP_METADATA, queryPtr, opSize, queryPtr, opSize, out int _, IntPtr.Zero))
            {
                Marshal.FreeHGlobal(queryPtr);
                return (null, 0);
            }

            query = MarshalUtility.GetStructFromMemory<KERNEL_IL2CPP_METADATA_OPERATION>(queryPtr, false);
            Marshal.FreeHGlobal(queryPtr);

            if (query.metadataSize <= 0 || query.metadataAddress == 0)
                return (null, 0);

            // Phase 2: read the metadata
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)query.metadataSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return (null, 0);

            KERNEL_IL2CPP_METADATA_OPERATION fill = new KERNEL_IL2CPP_METADATA_OPERATION
            {
                targetProcessId = targetProcessId,
                bufferAddress = (ulong)buffer.ToInt64(),
                bufferSize = query.metadataSize,
                metadataSize = 0,
                metadataAddress = 0
            };
            IntPtr fillPtr = MarshalUtility.CopyStructToMemory(fill);

            byte[] metadata = null;
            ulong address = 0;

            if (WinApi.DeviceIoControl(driverHandle, IO_READ_IL2CPP_METADATA, fillPtr, opSize, fillPtr, opSize, out int _, IntPtr.Zero))
            {
                fill = MarshalUtility.GetStructFromMemory<KERNEL_IL2CPP_METADATA_OPERATION>(fillPtr, false);

                if (fill.metadataSize > 0)
                {
                    metadata = new byte[fill.metadataSize];
                    Marshal.Copy(buffer, metadata, 0, fill.metadataSize);
                    address = fill.metadataAddress;
                }
            }

            WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            Marshal.FreeHGlobal(fillPtr);
            return (metadata, address);
        }

        // Kills a process by name via the kernel driver.
        // Returns (status, pid): status 0=success, 1=not found, 2=failed; pid=-1 if not found.
        public (int status, int pid) KillProcessByName(string processName)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_KILL_PROCESS_OPERATION operation = new KERNEL_KILL_PROCESS_OPERATION
                {
                    processName = processName,
                    killedPid = -1,
                    status = 1
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_KILL_PROCESS_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_KILL_PROCESS_BY_NAME, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                {
                    KERNEL_KILL_PROCESS_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_KILL_PROCESS_OPERATION>(operationPointer);
                    return (response.status, response.killedPid);
                }
                Marshal.FreeHGlobal(operationPointer);
            }
            return (2, -1);
        }

        // Unloads a kernel driver by name via the kernel driver.
        // Returns status: 0=success, 1=not found, 2=failed.
        public int UnloadDriverByName(string driverName)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_UNLOAD_DRIVER_OPERATION operation = new KERNEL_UNLOAD_DRIVER_OPERATION
                {
                    driverName = driverName,
                    status = 1
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_UNLOAD_DRIVER_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_UNLOAD_DRIVER_BY_NAME, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                {
                    KERNEL_UNLOAD_DRIVER_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_UNLOAD_DRIVER_OPERATION>(operationPointer);
                    return response.status;
                }
                Marshal.FreeHGlobal(operationPointer);
            }
            return 2;
        }

        // Unlinks a module from the PEB loader lists and zeroes its PE header.
        // Returns status: 0=success, 1=not found, 2=failed, -1=driver error.
        public int UnloadModule(int targetProcessId, ulong moduleBaseAddress)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_UNLOAD_MODULE_OPERATION operation = new KERNEL_UNLOAD_MODULE_OPERATION
                {
                    targetProcessId = targetProcessId,
                    moduleBaseAddress = moduleBaseAddress,
                    status = 1
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_UNLOAD_MODULE_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_UNLOAD_MODULE, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                {
                    KERNEL_UNLOAD_MODULE_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_UNLOAD_MODULE_OPERATION>(operationPointer);
                    return response.status;
                }
                Marshal.FreeHGlobal(operationPointer);
            }
            return -1;
        }

        // Reads process memory through LSASS context (bypasses PPL protections).
        // Returns true on success.
        public bool LsassReadMemory(int targetProcessId, IntPtr targetAddress, IntPtr bufferAddress, int bufferSize)
        {
            if (driverHandle != WinApi.INVALID_HANDLE_VALUE)
            {
                KERNEL_LSASS_READ_OPERATION operation = new KERNEL_LSASS_READ_OPERATION
                {
                    targetProcessId = targetProcessId,
                    targetAddress = (ulong)targetAddress.ToInt64(),
                    bufferAddress = (ulong)bufferAddress.ToInt64(),
                    bufferSize = bufferSize,
                    status = 1
                };
                IntPtr operationPointer = MarshalUtility.CopyStructToMemory(operation);
                int operationSize = Marshal.SizeOf<KERNEL_LSASS_READ_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_LSASS_READ_MEMORY, operationPointer, operationSize, operationPointer, operationSize, out int _, IntPtr.Zero))
                {
                    KERNEL_LSASS_READ_OPERATION response = MarshalUtility.GetStructFromMemory<KERNEL_LSASS_READ_OPERATION>(operationPointer);
                    return response.status == 0;
                }
                Marshal.FreeHGlobal(operationPointer);
            }
            return false;
        }

        // Enumerates all loaded kernel drivers (.sys files) via PsLoadedModuleList.
        // Returns list of (basePath, baseName, baseAddress, imageSize, flags, loadTime, entryPoint, checkSum).
        public List<(string basePath, string baseName, ulong baseAddress, uint imageSize, uint flags, DateTime loadTime, ulong entryPoint, uint checkSum)> EnumerateDrivers()
        {
            var result = new List<(string, string, ulong, uint, uint, DateTime, ulong, uint)>();
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return result;

            // Phase 1: query required size
            KERNEL_DRIVER_LIST_OPERATION query = new KERNEL_DRIVER_LIST_OPERATION
            {
                bufferAddress = 0, bufferSize = 0, requiredSize = 0, driverCount = 0
            };
            IntPtr queryPtr = MarshalUtility.CopyStructToMemory(query);
            int opSize = Marshal.SizeOf<KERNEL_DRIVER_LIST_OPERATION>();

            WinApi.DeviceIoControl(driverHandle, IO_ENUM_DRIVERS, queryPtr, opSize, queryPtr, opSize, out int _, IntPtr.Zero);
            query = MarshalUtility.GetStructFromMemory<KERNEL_DRIVER_LIST_OPERATION>(queryPtr);

            if (query.requiredSize <= 0) return result;

            // Phase 2: read driver data with padding
            int allocSize = query.requiredSize + 64 * 1024;
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)allocSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return result;

            KERNEL_DRIVER_LIST_OPERATION fill = new KERNEL_DRIVER_LIST_OPERATION
            {
                bufferAddress = (ulong)buffer.ToInt64(), bufferSize = allocSize,
                requiredSize = 0, driverCount = 0
            };
            IntPtr fillPtr = MarshalUtility.CopyStructToMemory(fill);

            if (WinApi.DeviceIoControl(driverHandle, IO_ENUM_DRIVERS, fillPtr, opSize, fillPtr, opSize, out int _, IntPtr.Zero))
            {
                fill = MarshalUtility.GetStructFromMemory<KERNEL_DRIVER_LIST_OPERATION>(fillPtr, false);

                if (fill.driverCount > 0)
                {
                    int copySize = Math.Min(fill.requiredSize, allocSize);
                    byte[] raw = new byte[copySize];
                    Marshal.Copy(buffer, raw, 0, copySize);

                    const int ENTRY_SIZE = 680;
                    int offset = 0;

                    for (int i = 0; i < fill.driverCount && offset + ENTRY_SIZE <= raw.Length; i++)
                    {
                        ulong baseAddr = BitConverter.ToUInt64(raw, offset);
                        uint imgSize = BitConverter.ToUInt32(raw, offset + 8);
                        string fullPath = System.Text.Encoding.Unicode.GetString(raw, offset + 12, 512).Split('\0')[0];
                        string baseName = System.Text.Encoding.Unicode.GetString(raw, offset + 524, 128).Split('\0')[0];
                        uint flags = BitConverter.ToUInt32(raw, offset + 652);
                        long loadTimeTicks = BitConverter.ToInt64(raw, offset + 660);
                        ulong entryPoint = BitConverter.ToUInt64(raw, offset + 668);
                        uint checkSum = BitConverter.ToUInt32(raw, offset + 676);

                        DateTime loadTime = DateTime.MinValue;
                        if (loadTimeTicks > 0)
                        {
                            try { loadTime = DateTime.FromFileTimeUtc(loadTimeTicks).ToLocalTime(); }
                            catch { }
                        }

                        result.Add((fullPath, baseName, baseAddr, imgSize, flags, loadTime, entryPoint, checkSum));
                        offset += ENTRY_SIZE;
                    }
                }
            }

            WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            Marshal.FreeHGlobal(fillPtr);
            return result;
        }

        // ---- Thread Context Operations ----

        private const uint IO_GET_THREAD_CONTEXT = 0x225CEC; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173B, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
        private const uint IO_SET_THREAD_CONTEXT = 0x225CF0; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173C, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
        private const uint IO_DEBUG_ACTIVE_PROCESS = 0x225CF4; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173D, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
        private const uint IO_DEBUG_WAIT_EVENT = 0x225CF8;     // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173E, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
        private const uint IO_DEBUG_CONTINUE = 0x225CFC;       // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173F, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_THREAD_CONTEXT_OPERATION
        {
            public int targetProcessId;
            public int threadId;
            public IntPtr contextBuffer;
            public int contextSize;
            public int contextFlags;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_DEBUG_OPERATION
        {
            public int targetProcessId;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_DEBUG_WAIT_OPERATION
        {
            public int timeoutMs;
            public IntPtr eventBuffer;
            public int bufferSize;
            public int eventCode;
            public int threadId;
            public IntPtr eventAddress;
            public int exceptionCode;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_DEBUG_CONTINUE_OPERATION
        {
            public int threadId;
            public int continueStatus;
            public int status;
        }

        public byte[] GetThreadContext(int processId, int threadId, int contextFlags)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return null;

            int ctxSize = 2048;
            IntPtr ctxBuf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)ctxSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (ctxBuf == IntPtr.Zero) return null;
            try
            {
                var op = new KERNEL_THREAD_CONTEXT_OPERATION
                {
                    targetProcessId = processId,
                    threadId = threadId,
                    contextBuffer = ctxBuf,
                    contextSize = ctxSize,
                    contextFlags = contextFlags,
                    status = 2
                };
                IntPtr opPtr = MarshalUtility.CopyStructToMemory(op);
                int opSize = Marshal.SizeOf<KERNEL_THREAD_CONTEXT_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_GET_THREAD_CONTEXT, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
                {
                    op = MarshalUtility.GetStructFromMemory<KERNEL_THREAD_CONTEXT_OPERATION>(opPtr);
                    if (op.status == 0)
                    {
                        byte[] result = new byte[ctxSize];
                        Marshal.Copy(ctxBuf, result, 0, ctxSize);
                        return result;
                    }
                }
            }
            finally { WinApi.VirtualFree(ctxBuf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
            return null;
        }

        public bool SetThreadContext(int processId, int threadId, byte[] context)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE || context == null) return false;

            IntPtr ctxBuf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)context.Length,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (ctxBuf == IntPtr.Zero) return false;
            try
            {
                Marshal.Copy(context, 0, ctxBuf, context.Length);

                var op = new KERNEL_THREAD_CONTEXT_OPERATION
                {
                    targetProcessId = processId,
                    threadId = threadId,
                    contextBuffer = ctxBuf,
                    contextSize = context.Length,
                    contextFlags = 0,
                    status = 2
                };
                IntPtr opPtr = MarshalUtility.CopyStructToMemory(op);
                int opSize = Marshal.SizeOf<KERNEL_THREAD_CONTEXT_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_SET_THREAD_CONTEXT, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
                {
                    op = MarshalUtility.GetStructFromMemory<KERNEL_THREAD_CONTEXT_OPERATION>(opPtr);
                    return op.status == 0;
                }
            }
            finally { WinApi.VirtualFree(ctxBuf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
            return false;
        }

        public bool DebugAttach(int processId)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return false;

            var op = new KERNEL_DEBUG_OPERATION { targetProcessId = processId, status = 2 };
            IntPtr opPtr = MarshalUtility.CopyStructToMemory(op);
            int opSize = Marshal.SizeOf<KERNEL_DEBUG_OPERATION>();

            if (WinApi.DeviceIoControl(driverHandle, IO_DEBUG_ACTIVE_PROCESS, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
            {
                op = MarshalUtility.GetStructFromMemory<KERNEL_DEBUG_OPERATION>(opPtr);
                return op.status == 0;
            }
            return false;
        }

        public (int eventCode, int threadId, ulong eventAddress, int exceptionCode) DebugWaitEvent(int timeoutMs)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return (0, 0, 0, 0);

            var op = new KERNEL_DEBUG_WAIT_OPERATION { timeoutMs = timeoutMs, status = 3 };
            IntPtr opPtr = MarshalUtility.CopyStructToMemory(op);
            int opSize = Marshal.SizeOf<KERNEL_DEBUG_WAIT_OPERATION>();

            if (WinApi.DeviceIoControl(driverHandle, IO_DEBUG_WAIT_EVENT, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
            {
                op = MarshalUtility.GetStructFromMemory<KERNEL_DEBUG_WAIT_OPERATION>(opPtr);
                if (op.status == 0)
                    return (op.eventCode, op.threadId, (ulong)op.eventAddress.ToInt64(), op.exceptionCode);
            }
            return (0, 0, 0, 0);
        }

        public bool DebugContinue(int threadId, int continueStatus)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return false;

            var op = new KERNEL_DEBUG_CONTINUE_OPERATION { threadId = threadId, continueStatus = continueStatus, status = 2 };
            IntPtr opPtr = MarshalUtility.CopyStructToMemory(op);
            int opSize = Marshal.SizeOf<KERNEL_DEBUG_CONTINUE_OPERATION>();

            if (WinApi.DeviceIoControl(driverHandle, IO_DEBUG_CONTINUE, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
            {
                op = MarshalUtility.GetStructFromMemory<KERNEL_DEBUG_CONTINUE_OPERATION>(opPtr);
                return op.status == 0;
            }
            return false;
        }

        // ---- Anti-Cheat Bypass: Kernel Callbacks ----

        private const uint IO_ENUM_KERNEL_CALLBACKS = 0x225D04; // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1741, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
        private const uint IO_CLONE_PROCESS = 0x225D0C;       // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1743, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
        private const uint IO_ENUM_VAD = 0x225D10;             // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1744, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
        private const uint IO_ENUM_HANDLES = 0x225D14;         // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1745, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
        private const uint IO_ENUM_KERNEL_MODULES = 0x225D18;  // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1746, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_CALLBACK_OPERATION
        {
            public int removeCallbacks;
            public int callbackCount;
            public IntPtr bufferAddress;
            public int bufferSize;
            public int removedCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_CLONE_PROCESS_OPERATION
        {
            public int targetProcessId;
            public int clonedProcessId;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_VAD_OPERATION
        {
            public int targetProcessId;
            public IntPtr bufferAddress;
            public int bufferSize;
            public int requiredSize;
            public int vadCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_HANDLE_OPERATION
        {
            public int targetProcessId;
            public IntPtr bufferAddress;
            public int bufferSize;
            public int requiredSize;
            public int handleCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct KERNEL_MODULE_ENUM_OPERATION
        {
            public IntPtr bufferAddress;
            public int bufferSize;
            public int requiredSize;
            public int moduleCount;
        }

        public (int callbackCount, int removedCount, CallbackEntry[] callbacks) EnumKernelCallbacks(bool removeCallbacks)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return (0, 0, new CallbackEntry[0]);

            int bufSize = 276 * 256;
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)bufSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return (0, 0, new CallbackEntry[0]);
            IntPtr opPtr = IntPtr.Zero;

            try
            {
                var op = new KERNEL_CALLBACK_OPERATION
                {
                    removeCallbacks = removeCallbacks ? 1 : 0,
                    bufferAddress = buffer,
                    bufferSize = bufSize
                };
                opPtr = MarshalUtility.CopyStructToMemory(op);
                int opSize = Marshal.SizeOf<KERNEL_CALLBACK_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_ENUM_KERNEL_CALLBACKS, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
                {
                    op = MarshalUtility.GetStructFromMemory<KERNEL_CALLBACK_OPERATION>(opPtr, false);
                    if (op.callbackCount > 0)
                    {
                        const int ENTRY_SIZE = 276;
                        byte[] raw = new byte[op.callbackCount * ENTRY_SIZE];
                        Marshal.Copy(buffer, raw, 0, Math.Min(raw.Length, bufSize));

                        CallbackEntry[] entries = new CallbackEntry[op.callbackCount];
                        for (int i = 0; i < op.callbackCount; i++)
                        {
                            int off = i * ENTRY_SIZE;
                            if (off + ENTRY_SIZE > raw.Length) break;
                            entries[i] = new CallbackEntry
                            {
                                CallbackAddress = BitConverter.ToUInt64(raw, off),
                                DriverName = System.Text.Encoding.Unicode.GetString(raw, off + 8, 256).Split('\0')[0],
                                CallbackType = BitConverter.ToUInt32(raw, off + 264),
                                Index = BitConverter.ToUInt32(raw, off + 268),
                                Removed = BitConverter.ToUInt32(raw, off + 272)
                            };
                        }
                        return (op.callbackCount, op.removedCount, entries);
                    }
                    return (op.callbackCount, op.removedCount, new CallbackEntry[0]);
                }
            }
            finally
            {
                if (opPtr != IntPtr.Zero) Marshal.FreeHGlobal(opPtr);
                WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
            return (0, 0, new CallbackEntry[0]);
        }

        public (int status, int clonedProcessId) CloneProcess(int processId)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return (2, -1);

            IntPtr opPtr = IntPtr.Zero;
            try
            {
                var op = new KERNEL_CLONE_PROCESS_OPERATION { targetProcessId = processId, clonedProcessId = -1, status = 2 };
                opPtr = MarshalUtility.CopyStructToMemory(op);
                int opSize = Marshal.SizeOf<KERNEL_CLONE_PROCESS_OPERATION>();

                bool ioctlOk = WinApi.DeviceIoControl(driverHandle, IO_CLONE_PROCESS, opPtr, opSize, opPtr, opSize, out int bytesRet, IntPtr.Zero);
                int lastErr = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
                System.IO.File.AppendAllText(@"C:\Users\windows\Desktop\ksdumper_debug.log",
                    $"[CloneProcess] IOCTL result={ioctlOk}, bytesRet={bytesRet}, opSize={opSize}, pid={processId}, lastErr={lastErr}\r\n");
                if (ioctlOk)
                {
                    op = MarshalUtility.GetStructFromMemory<KERNEL_CLONE_PROCESS_OPERATION>(opPtr, false);
                    System.IO.File.AppendAllText(@"C:\Users\windows\Desktop\ksdumper_debug.log",
                        $"[CloneProcess] status={op.status}, clonedPid={op.clonedProcessId}\r\n");
                    return (op.status, op.clonedProcessId);
                }
                System.IO.File.AppendAllText(@"C:\Users\windows\Desktop\ksdumper_debug.log",
                    $"[CloneProcess] DeviceIoControl FAILED\r\n");
            }
            finally
            {
                if (opPtr != IntPtr.Zero) Marshal.FreeHGlobal(opPtr);
            }
            return (2, -1);
        }

        public (int vadCount, VADEntry[] vads) EnumVadTree(int processId)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return (0, new VADEntry[0]);

            int bufSize = 65536 * 32;
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)bufSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return (0, new VADEntry[0]);
            IntPtr opPtr = IntPtr.Zero;

            try
            {
                var op = new KERNEL_VAD_OPERATION
                {
                    targetProcessId = processId,
                    bufferAddress = buffer,
                    bufferSize = bufSize
                };
                opPtr = MarshalUtility.CopyStructToMemory(op);
                int opSize = Marshal.SizeOf<KERNEL_VAD_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_ENUM_VAD, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
                {
                    op = MarshalUtility.GetStructFromMemory<KERNEL_VAD_OPERATION>(opPtr, false);
                    if (op.vadCount > 0)
                    {
                        const int VAD_ENTRY_SIZE = 36;
                        byte[] raw = new byte[op.vadCount * VAD_ENTRY_SIZE];
                        Marshal.Copy(buffer, raw, 0, Math.Min(raw.Length, bufSize));

                        VADEntry[] vads = new VADEntry[op.vadCount];
                        for (int i = 0; i < op.vadCount; i++)
                        {
                            int off = i * VAD_ENTRY_SIZE;
                            if (off + VAD_ENTRY_SIZE > raw.Length) break;
                            vads[i] = new VADEntry
                            {
                                StartAddress = BitConverter.ToUInt64(raw, off),
                                EndAddress = BitConverter.ToUInt64(raw, off + 8),
                                Protection = BitConverter.ToUInt32(raw, off + 16),
                                Flags = BitConverter.ToUInt32(raw, off + 20),
                                CommitCharge = BitConverter.ToUInt32(raw, off + 24),
                                ControlArea = BitConverter.ToUInt64(raw, off + 28)
                            };
                        }
                        return (op.vadCount, vads);
                    }
                }
            }
            finally
            {
                if (opPtr != IntPtr.Zero) Marshal.FreeHGlobal(opPtr);
                WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
            return (0, new VADEntry[0]);
        }

        public (int handleCount, HandleEntry[] handles) EnumHandles(int processId)
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return (0, new HandleEntry[0]);

            int bufSize = 65536 * 64;
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)bufSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return (0, new HandleEntry[0]);
            IntPtr opPtr = IntPtr.Zero;

            try
            {
                var op = new KERNEL_HANDLE_OPERATION
                {
                    targetProcessId = processId,
                    bufferAddress = buffer,
                    bufferSize = bufSize
                };
                opPtr = MarshalUtility.CopyStructToMemory(op);
                int opSize = Marshal.SizeOf<KERNEL_HANDLE_OPERATION>();

                bool ioctlOk = WinApi.DeviceIoControl(driverHandle, IO_ENUM_HANDLES, opPtr, opSize, opPtr, opSize, out int bytesRet, IntPtr.Zero);
                int lastErr = Marshal.GetLastWin32Error();
                System.IO.File.AppendAllText(@"C:\Users\windows\Desktop\ksdumper_debug.log",
                    $"[EnumHandles] IOCTL result={ioctlOk}, bytesRet={bytesRet}, opSize={opSize}, pid={processId}, lastErr={lastErr}\r\n");
                if (ioctlOk)
                {
                    op = MarshalUtility.GetStructFromMemory<KERNEL_HANDLE_OPERATION>(opPtr, false);
                    System.IO.File.AppendAllText(@"C:\Users\windows\Desktop\ksdumper_debug.log",
                        $"[EnumHandles] handleCount={op.handleCount}, requiredSize={op.requiredSize}\r\n");
                    if (op.handleCount > 0)
                    {
                        const int HANDLE_ENTRY_SIZE = 284;
                        byte[] raw = new byte[op.handleCount * HANDLE_ENTRY_SIZE];
                        Marshal.Copy(buffer, raw, 0, Math.Min(raw.Length, bufSize));

                        HandleEntry[] handles = new HandleEntry[op.handleCount];
                        for (int i = 0; i < op.handleCount; i++)
                        {
                            int off = i * HANDLE_ENTRY_SIZE;
                            if (off + HANDLE_ENTRY_SIZE > raw.Length) break;
                            handles[i] = new HandleEntry
                            {
                                HandleValue = BitConverter.ToUInt64(raw, off),
                                ProcessId = BitConverter.ToInt32(raw, off + 8),
                                TargetProcessId = BitConverter.ToInt32(raw, off + 12),
                                GrantedAccess = BitConverter.ToUInt32(raw, off + 16),
                                HandleAttributes = BitConverter.ToUInt32(raw, off + 20),
                                ObjectName = System.Text.Encoding.Unicode.GetString(raw, off + 24, 256).Split('\0')[0],
                                ObjectTypeIndex = BitConverter.ToUInt32(raw, off + 280)
                            };
                        }
                        return (op.handleCount, handles);
                    }
                }
            }
            finally
            {
                if (opPtr != IntPtr.Zero) Marshal.FreeHGlobal(opPtr);
                WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
            return (0, new HandleEntry[0]);
        }

        public (int moduleCount, KernelModuleEntry[] modules) EnumKernelModules()
        {
            if (driverHandle == WinApi.INVALID_HANDLE_VALUE) return (0, new KernelModuleEntry[0]);

            int bufSize = 1024 * 396;
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)bufSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return (0, new KernelModuleEntry[0]);
            IntPtr opPtr = IntPtr.Zero;

            try
            {
                var op = new KERNEL_MODULE_ENUM_OPERATION
                {
                    bufferAddress = buffer,
                    bufferSize = bufSize
                };
                opPtr = MarshalUtility.CopyStructToMemory(op);
                int opSize = Marshal.SizeOf<KERNEL_MODULE_ENUM_OPERATION>();

                if (WinApi.DeviceIoControl(driverHandle, IO_ENUM_KERNEL_MODULES, opPtr, opSize, opPtr, opSize, out int _, IntPtr.Zero))
                {
                    op = MarshalUtility.GetStructFromMemory<KERNEL_MODULE_ENUM_OPERATION>(opPtr, false);
                    if (op.moduleCount > 0)
                    {
                        const int ENTRY_SIZE = 784;
                        byte[] raw = new byte[op.moduleCount * ENTRY_SIZE];
                        Marshal.Copy(buffer, raw, 0, Math.Min(raw.Length, bufSize));

                        KernelModuleEntry[] modules = new KernelModuleEntry[op.moduleCount];
                        for (int i = 0; i < op.moduleCount; i++)
                        {
                            int off = i * ENTRY_SIZE;
                            if (off + ENTRY_SIZE > raw.Length) break;
                            modules[i] = new KernelModuleEntry
                            {
                                BaseAddress = BitConverter.ToUInt64(raw, off),
                                ImageSize = BitConverter.ToUInt32(raw, off + 8),
                                BaseName = System.Text.Encoding.Unicode.GetString(raw, off + 12, 256).Split('\0')[0],
                                FullPath = System.Text.Encoding.Unicode.GetString(raw, off + 268, 512).Split('\0')[0],
                                Flags = BitConverter.ToUInt32(raw, off + 780)
                            };
                        }
                        return (op.moduleCount, modules);
                    }
                }
            }
            finally
            {
                if (opPtr != IntPtr.Zero) Marshal.FreeHGlobal(opPtr);
                WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
            return (0, new KernelModuleEntry[0]);
        }
    }
}
