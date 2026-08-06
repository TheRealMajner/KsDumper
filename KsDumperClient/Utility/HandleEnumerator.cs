using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class HandleEnumerator
    {
        public struct HandleInfo
        {
            public int ProcessId;
            public ushort Handle;
            public string TypeName;
            public string ObjectName;
            public uint GrantedAccess;
        }

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int bufferSize, out int returnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryObject(IntPtr handle, int infoClass, IntPtr buffer, int bufferSize, out int returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(IntPtr hSourceProcess, IntPtr hSourceHandle, IntPtr hTargetProcess, out IntPtr hTarget, uint dwDesiredAccess, bool bInheritHandle, uint dwOptions);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        private const int SYSTEM_HANDLE_INFORMATION = 16;
        private const int OBJECT_NAME_INFORMATION = 1;
        private const int OBJECT_TYPE_INFORMATION = 2;

        public static List<HandleInfo> EnumerateHandles(int targetProcessId)
        {
            var result = new List<HandleInfo>();
            int bufSize = 0x400000; // 4MB
            IntPtr buffer = Marshal.AllocHGlobal(bufSize);

            try
            {
                int status = NtQuerySystemInformation(SYSTEM_HANDLE_INFORMATION, buffer, bufSize, out int retLen);
                if (status == unchecked((int)0xC0000004)) // STATUS_INFO_LENGTH_MISMATCH
                {
                    bufSize = retLen + 0x10000;
                    Marshal.FreeHGlobal(buffer);
                    buffer = Marshal.AllocHGlobal(bufSize);
                    status = NtQuerySystemInformation(SYSTEM_HANDLE_INFORMATION, buffer, bufSize, out retLen);
                }
                if (status != 0) return result;

                // Parse handle table
                // x64: ULONG NumberOfHandles at offset 0, then SYSTEM_HANDLE_ENTRY[]
                long numHandles = Marshal.ReadInt64(buffer, 0);
                int entrySize = 24; // x64 SYSTEM_HANDLE_ENTRY size
                int entryOffset = 8; // after the count

                var typeCache = new Dictionary<IntPtr, string>();

                for (long i = 0; i < Math.Min(numHandles, 500000); i++)
                {
                    int off = entryOffset + (int)(i * entrySize);
                    if (off + entrySize > retLen) break;

                    int pid = Marshal.ReadInt32(buffer, off);
                    if (pid != targetProcessId) continue;

                    ushort handleVal = (ushort)Marshal.ReadInt16(buffer, off + 8);
                    // ushort objectTypeIndex at off + 10
                    // uint grantedAccess at off + 16
                    uint grantedAccess = (uint)Marshal.ReadInt32(buffer, off + 16);

                    string typeName = $"Type_{Marshal.ReadByte(buffer, off + 10)}";

                    // Try to query object name (only for certain types to avoid hangs)
                    string objectName = "";
                    try
                    {
                        IntPtr hProcess = OpenProcess(0x0040, false, targetProcessId); // PROCESS_DUP_HANDLE
                        if (hProcess != IntPtr.Zero)
                        {
                            IntPtr dupHandle;
                            if (DuplicateHandle(hProcess, (IntPtr)handleVal, GetCurrentProcess(), out dupHandle, 0, false, 0x00000002)) // DUPLICATE_SAME_ACCESS
                            {
                                objectName = QueryObjectName(dupHandle);
                                typeName = QueryObjectType(dupHandle, typeCache);
                                CloseHandle(dupHandle);
                            }
                            CloseHandle(hProcess);
                        }
                    }
                    catch { }

                    result.Add(new HandleInfo
                    {
                        ProcessId = pid,
                        Handle = handleVal,
                        TypeName = typeName,
                        ObjectName = objectName,
                        GrantedAccess = grantedAccess
                    });
                }
            }
            finally { Marshal.FreeHGlobal(buffer); }

            return result;
        }

        private static string QueryObjectName(IntPtr handle)
        {
            IntPtr buf = Marshal.AllocHGlobal(1024);
            try
            {
                int status = NtQueryObject(handle, OBJECT_NAME_INFORMATION, buf, 1024, out int retLen);
                if (status != 0) return "";
                // UNICODE_STRING: Length(2), MaxLen(2), Padding(4), Buffer(8)
                int len = Marshal.ReadInt16(buf, 0);
                IntPtr strPtr = Marshal.ReadIntPtr(buf, 8);
                if (strPtr == IntPtr.Zero || len == 0) return "";
                return Marshal.PtrToStringUni(strPtr, len / 2);
            }
            catch { return ""; }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private static string QueryObjectType(IntPtr handle, Dictionary<IntPtr, string> cache)
        {
            IntPtr buf = Marshal.AllocHGlobal(512);
            try
            {
                int status = NtQueryObject(handle, OBJECT_TYPE_INFORMATION, buf, 512, out int retLen);
                if (status != 0) return "Unknown";
                int len = Marshal.ReadInt16(buf, 0);
                IntPtr strPtr = Marshal.ReadIntPtr(buf, 8);
                if (strPtr == IntPtr.Zero || len == 0) return "Unknown";
                return Marshal.PtrToStringUni(strPtr, len / 2);
            }
            catch { return "Unknown"; }
            finally { Marshal.FreeHGlobal(buf); }
        }
    }
}
