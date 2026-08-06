using System.Runtime.InteropServices;

using static KsDumperClient.Utility.WinApi;

namespace KsDumperClient.Driver
{
    public static class Operations
    {
        public static readonly uint IO_GET_PROCESS_LIST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1724, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_COPY_MEMORY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1725, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_GET_MODULE_LIST = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1726, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_UNPROTECT_PROCESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1727, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_CHECK_TABLES_READY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1728, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_GET_EXPORT_MAP = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1729, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_SUSPEND_PROCESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1730, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_RESUME_PROCESS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1731, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_DUMP_STRINGS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1732, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_ENUM_REGIONS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1733, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_FIND_PATTERN = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1734, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_READ_IL2CPP_METADATA = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1735, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_KILL_PROCESS_BY_NAME = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1736, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_UNLOAD_DRIVER_BY_NAME = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1737, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_UNLOAD_MODULE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1738, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_LSASS_READ_MEMORY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1739, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_WRITE_MEMORY = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1740, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public static readonly uint IO_ENUM_DRIVERS = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x173A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        public const int TABLES_NOT_READY = 0;
        public const int TABLES_READY = 1;
        public const int TABLES_NO_IMPORTS = 2;

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_PROCESS_LIST_OPERATION
        {
            public ulong bufferAddress;
            public int bufferSize;
            public int processCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_COPY_MEMORY_OPERATION
        {
            public int targetProcessId;
            public ulong targetAddress;
            public ulong bufferAddress;
            public int bufferSize;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_MODULE_LIST_OPERATION
        {
            public ulong bufferAddress;
            public int bufferSize;
            public int moduleCount;
            public int targetProcessId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_UNPROTECT_OPERATION
        {
            public int targetProcessId;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_TABLE_CHECK_OPERATION
        {
            public int targetProcessId;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct EXPORT_MAP_OPERATION
        {
            public int targetProcessId;
            public ulong bufferAddress;
            public int bufferSize;
            public int requiredSize;
            public int moduleCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_SUSPEND_OPERATION
        {
            public int targetProcessId;
            public int threadCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_STRING_DUMP_OPERATION
        {
            public int targetProcessId;
            public int minStringLength;
            public ulong bufferAddress;
            public int bufferSize;
            public int requiredSize;
            public int stringCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_ENUM_REGIONS_OPERATION
        {
            public int targetProcessId;
            public ulong bufferAddress;
            public int bufferSize;
            public int requiredSize;
            public int regionCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_PATTERN_SCAN_OPERATION
        {
            public int targetProcessId;
            public ulong patternAddress;
            public int patternLength;
            public byte wildcardByte;
            public ulong resultsAddress;
            public int maxResults;
            public int matchCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_IL2CPP_METADATA_OPERATION
        {
            public int targetProcessId;
            public ulong bufferAddress;
            public int bufferSize;
            public int metadataSize;
            public ulong metadataAddress;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct KERNEL_KILL_PROCESS_OPERATION
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string processName;
            public int killedPid;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct KERNEL_UNLOAD_DRIVER_OPERATION
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)]
            public string driverName;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_UNLOAD_MODULE_OPERATION
        {
            public int targetProcessId;
            public ulong moduleBaseAddress;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_LSASS_READ_OPERATION
        {
            public int targetProcessId;
            public ulong targetAddress;
            public ulong bufferAddress;
            public int bufferSize;
            public int status;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct KERNEL_DRIVER_LIST_OPERATION
        {
            public ulong bufferAddress;
            public int bufferSize;
            public int requiredSize;
            public int driverCount;
        }

        // Must match kernel DRIVER_SUMMARY struct layout (packed)
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct DRIVER_SUMMARY
        {
            public ulong BaseAddress;     // PVOID = 8 bytes
            public uint ImageSize;        // UINT32 = 4 bytes
            // FullPath: 256 WCHAR = 512 bytes
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] FullPath;
            // BaseName: 64 WCHAR = 128 bytes
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 128)]
            public byte[] BaseName;
            public uint Flags;            // UINT32 = 4 bytes
            public uint LoadOrderIndex;   // UINT32 = 4 bytes
            public long LoadTime;         // LARGE_INTEGER = 8 bytes
            public ulong EntryPoint;      // PVOID = 8 bytes
            public uint CheckSum;         // UINT32 = 4 bytes
            // Total: 8+4+512+128+4+4+8+8+4 = 680 bytes
        }

        private static uint CTL_CODE(int deviceType, int function, int method, int access)
        {
            return (uint)(((deviceType) << 16) | ((access) << 14) | ((function) << 2) | (method));
        }
    }
}
