using System;
using System.Runtime.InteropServices;

namespace KsDumperClient.Utility
{
    public static class MarshalUtility
    {
        [DllImport("ntdll.dll", EntryPoint = "RtlZeroMemory", SetLastError = false)]
        private static extern void RtlZeroMemory(IntPtr dest, int size);

        public static IntPtr CopyStructToMemory<T>(T obj) where T : struct
        {
            IntPtr unmanagedAddress = AllocEmptyStruct<T>();
            Marshal.StructureToPtr(obj, unmanagedAddress, true);

            return unmanagedAddress;
        }

        public static IntPtr AllocEmptyStruct<T>() where T : struct
        {
            int structSize = Marshal.SizeOf<T>();
            IntPtr structPointer = AllocZeroFilled(Marshal.SizeOf<T>());

            return structPointer;
        }

        public static IntPtr AllocZeroFilled(int size)
        {
            IntPtr allocatedPointer = Marshal.AllocHGlobal(size);
            RtlZeroMemory(allocatedPointer, size);

            return allocatedPointer;
        }

        public static T GetStructFromMemory<T>(IntPtr unmanagedAddress, bool freeMemory = true) where T : struct
        {
            T structObj = Marshal.PtrToStructure<T>(unmanagedAddress);

            if (freeMemory)
            {
                Marshal.FreeHGlobal(unmanagedAddress);
            }
            return structObj;
        }
    }
}
