using System;
using System.Runtime.InteropServices;

namespace KsDumperClient.Utility
{
    /// <summary>
    /// Safe wrapper for unmanaged memory allocations that guarantees cleanup via IDisposable.
    /// Usage: using (var mem = new SafeBuffer(256)) { ... mem.Ptr ... }
    /// </summary>
    public struct SafeBuffer : IDisposable
    {
        public IntPtr Ptr { get; private set; }
        public int Size { get; private set; }

        public SafeBuffer(int size)
        {
            Size = size;
            Ptr = Marshal.AllocHGlobal(size);
        }

        public void Zero()
        {
            if (Ptr != IntPtr.Zero)
            {
                for (int i = 0; i < Size; i++)
                    Marshal.WriteByte(Ptr, i, 0);
            }
        }

        public byte[] ToArray()
        {
            if (Ptr == IntPtr.Zero || Size <= 0) return new byte[0];
            byte[] result = new byte[Size];
            Marshal.Copy(Ptr, result, 0, Size);
            return result;
        }

        public void Dispose()
        {
            if (Ptr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Ptr);
                Ptr = IntPtr.Zero;
            }
        }
    }
}
