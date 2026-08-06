using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    /// <summary>
    /// Abstract base class for all ReClass memory node types.
    /// Each node represents a typed view of a region of process memory.
    /// </summary>
    public abstract class MemoryNode
    {
        public string Name { get; set; }
        public int Offset { get; set; }
        public MemoryNode Parent { get; set; }
        public List<MemoryNode> Children { get; set; }
        public bool IsExpanded { get; set; }
        public byte[] RawBytes { get; set; }

        public abstract int ByteSize { get; }
        public abstract string TypeName { get; }
        public abstract Color DisplayColor { get; }

        public ulong ResolvedAddress
        {
            get
            {
                if (Parent == null)
                    return (ulong)Offset;
                return Parent.GetChildAddress(this);
            }
        }

        public virtual ulong GetChildAddress(MemoryNode child)
        {
            return ResolvedAddress + (ulong)child.Offset;
        }

        public abstract string FormatValue();
        public abstract byte[] ParseInput(string input);

        public string FormatHex()
        {
            if (RawBytes == null || RawBytes.Length == 0)
            {
                int charCount = ByteSize * 3 - 1;
                return charCount > 0 ? new string('?', charCount) : "??";
            }

            var sb = new StringBuilder(ByteSize * 3);
            int count = Math.Min(RawBytes.Length, ByteSize);
            for (int i = 0; i < count; i++)
            {
                if (i > 0) sb.Append(' ');
                sb.Append(RawBytes[i].ToString("X2"));
            }
            return sb.ToString();
        }

        public virtual bool ReadMemory(IMemoryReader driver, int pid, ulong baseAddr)
        {
            if (ByteSize <= 0)
            {
                RawBytes = Array.Empty<byte>();
                return false;
            }

            ulong addr = baseAddr + (ulong)Offset;
            byte[] buffer = new byte[ByteSize];
            IntPtr bufPtr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)ByteSize,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (bufPtr == IntPtr.Zero) { RawBytes = new byte[ByteSize]; return false; }

            try
            {
                if (driver.CopyVirtualMemory(pid, (IntPtr)addr, bufPtr, ByteSize))
                {
                    System.Runtime.InteropServices.Marshal.Copy(bufPtr, buffer, 0, ByteSize);
                    RawBytes = buffer;
                    return true;
                }
                else
                {
                    RawBytes = new byte[ByteSize];
                    return false;
                }
            }
            finally
            {
                WinApi.VirtualFree(bufPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
        }

        public virtual bool WriteMemory(IMemoryReader driver, int pid, ulong baseAddr, byte[] data)
        {
            ulong addr = baseAddr + (ulong)Offset;
            IntPtr bufPtr = System.Runtime.InteropServices.Marshal.AllocHGlobal(data.Length);

            try
            {
                System.Runtime.InteropServices.Marshal.Copy(data, 0, bufPtr, data.Length);
                return driver.WriteVirtualMemory(pid, (IntPtr)addr, bufPtr, data.Length);
            }
            finally
            {
                System.Runtime.InteropServices.Marshal.FreeHGlobal(bufPtr);
            }
        }

        public virtual void RecalculateOffsets()
        {
            if (Children == null) return;
            int offset = 0;
            foreach (var child in Children)
            {
                child.Offset = offset;
                offset += child.ByteSize;
                child.RecalculateOffsets();
            }
        }

        public virtual int TotalByteSize
        {
            get { return ByteSize; }
        }

        public virtual int GetVisibleRowCount()
        {
            int count = 1;
            if (IsExpanded && Children != null)
            {
                foreach (var child in Children)
                    count += child.GetVisibleRowCount();
            }
            return count;
        }

        public string FormatAddress(ulong addr)
        {
            return "0x" + addr.ToString("X16");
        }
    }
}
