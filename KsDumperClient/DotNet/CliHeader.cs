using System;
using System.Text;

namespace KsDumperClient.DotNet
{
    /// <summary>
    /// Parses the CLI header (COM+ 2.0) from a PE file.
    /// Located at the data directory index 14 (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR).
    /// </summary>
    public class CliHeader
    {
        public uint HeaderSize;          // Should be 72
        public ushort MajorRuntimeVersion;
        public ushort MinorRuntimeVersion;
        public uint MetadataRva;
        public uint MetadataSize;
        public uint Flags;
        public uint EntryPointToken;
        public uint ResourcesRva;
        public uint ResourcesSize;
        public uint StrongNameRva;
        public uint StrongNameSize;
        public uint CodeManagerTableRva;
        public uint CodeManagerTableSize;
        public uint VTableFixupsRva;
        public uint VTableFixupsSize;
        public uint ExportAddressTableJumpsRva;
        public uint ExportAddressTableJumpsSize;
        public uint ManagedNativeHeaderRva;
        public uint ManagedNativeHeaderSize;

        // CLI Flags
        public bool IsILOnly => (Flags & 0x01) != 0;
        public bool Is32BitRequired => (Flags & 0x02) != 0;
        public bool IsStrongNameSigned => (Flags & 0x08) != 0;
        public bool HasNativeEntryPoint => (Flags & 0x10) != 0;
        public bool Is32BitPreferred => (Flags & 0x00020000) != 0;

        public static CliHeader Parse(byte[] peBytes)
        {
            if (peBytes == null || peBytes.Length < 64) return null;

            // Check DOS header magic
            if (BitConverter.ToUInt16(peBytes, 0) != 0x5A4D) return null;

            int peOffset = BitConverter.ToInt32(peBytes, 60);
            if (peOffset + 4 > peBytes.Length) return null;
            if (BitConverter.ToUInt32(peBytes, peOffset) != 0x00004550) return null;

            bool is64 = false;
            ushort machine = BitConverter.ToUInt16(peBytes, peOffset + 4);
            if (machine == 0x8664 || machine == 0xAA64) is64 = true;

            ushort magic = BitConverter.ToUInt16(peBytes, peOffset + 24);
            if (magic == 0x20b) is64 = true;

            // Data directory[14] = COM_DESCRIPTOR
            int ddOffset = is64 ? peOffset + 24 + 88 : peOffset + 24 + 72;
            if (ddOffset + 8 > peBytes.Length) return null;

            uint comDirRva = BitConverter.ToUInt32(peBytes, ddOffset);
            uint comDirSize = BitConverter.ToUInt32(peBytes, ddOffset + 4);

            if (comDirRva == 0 || comDirSize == 0) return null;

            // Convert RVA to file offset
            int comDirFileOffset = RvaToFileOffset(peBytes, peOffset, comDirRva, is64);
            if (comDirFileOffset < 0 || comDirFileOffset + 72 > peBytes.Length) return null;

            return ParseAt(peBytes, comDirFileOffset);
        }

        private static CliHeader ParseAt(byte[] data, int offset)
        {
            var h = new CliHeader();
            int p = offset;

            h.HeaderSize = ReadU32(data, ref p);
            h.MajorRuntimeVersion = ReadU16(data, ref p);
            h.MinorRuntimeVersion = ReadU16(data, ref p);
            h.MetadataRva = ReadU32(data, ref p);
            h.MetadataSize = ReadU32(data, ref p);
            h.Flags = ReadU32(data, ref p);
            h.EntryPointToken = ReadU32(data, ref p);
            h.ResourcesRva = ReadU32(data, ref p);
            h.ResourcesSize = ReadU32(data, ref p);
            h.StrongNameRva = ReadU32(data, ref p);
            h.StrongNameSize = ReadU32(data, ref p);
            h.CodeManagerTableRva = ReadU32(data, ref p);
            h.CodeManagerTableSize = ReadU32(data, ref p);
            h.VTableFixupsRva = ReadU32(data, ref p);
            h.VTableFixupsSize = ReadU32(data, ref p);
            h.ExportAddressTableJumpsRva = ReadU32(data, ref p);
            h.ExportAddressTableJumpsSize = ReadU32(data, ref p);
            h.ManagedNativeHeaderRva = ReadU32(data, ref p);
            h.ManagedNativeHeaderSize = ReadU32(data, ref p);

            return h;
        }

        internal static int RvaToFileOffset(byte[] peBytes, int peOffset, uint rva, bool is64)
        {
            // Get number of sections
            int numSections = BitConverter.ToUInt16(peBytes, peOffset + 6);
            ushort optionalHeaderSize = BitConverter.ToUInt16(peBytes, peOffset + 20);
            int sectionTableOffset = peOffset + 24 + optionalHeaderSize;

            for (int i = 0; i < numSections; i++)
            {
                int secOff = sectionTableOffset + i * 40;
                if (secOff + 40 > peBytes.Length) break;

                uint virtualSize = BitConverter.ToUInt32(peBytes, secOff + 8);
                uint virtualAddr = BitConverter.ToUInt32(peBytes, secOff + 12);
                uint rawSize = BitConverter.ToUInt32(peBytes, secOff + 16);
                uint rawPtr = BitConverter.ToUInt32(peBytes, secOff + 20);

                if (rva >= virtualAddr && rva < virtualAddr + virtualSize)
                {
                    return (int)(rawPtr + (rva - virtualAddr));
                }
            }
            return -1;
        }

        internal static uint ReadU32(byte[] data, ref int pos)
        {
            if (pos + 4 > data.Length) { pos += 4; return 0; }
            uint val = BitConverter.ToUInt32(data, pos);
            pos += 4;
            return val;
        }

        internal static ushort ReadU16(byte[] data, ref int pos)
        {
            if (pos + 2 > data.Length) { pos += 2; return 0; }
            ushort val = BitConverter.ToUInt16(data, pos);
            pos += 2;
            return val;
        }

        internal static string ReadUtf8NullTerminated(byte[] data, int pos)
        {
            if (pos < 0 || pos >= data.Length) return "";
            int end = pos;
            while (end < data.Length && data[end] != 0) end++;
            if (end == pos) return "";
            return Encoding.UTF8.GetString(data, pos, end - pos);
        }
    }
}
