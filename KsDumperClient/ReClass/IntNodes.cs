using System;
using System.Drawing;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    public class Int8Node : MemoryNode
    {
        public override int ByteSize => 1;
        public override string TypeName => "int8";
        public override Color DisplayColor => DarkTheme.Success;

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 1) return "?";
            return ((sbyte)RawBytes[0]).ToString();
        }

        public override byte[] ParseInput(string input)
        {
            if (sbyte.TryParse(input.Trim(), out sbyte val))
                return new byte[] { (byte)val };
            return null;
        }
    }

    public class UInt8Node : MemoryNode
    {
        public override int ByteSize => 1;
        public override string TypeName => "uint8";
        public override Color DisplayColor => Color.FromArgb(121, 192, 255);

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 1) return "?";
            return RawBytes[0].ToString();
        }

        public override byte[] ParseInput(string input)
        {
            if (byte.TryParse(input.Trim(), out byte val))
                return new byte[] { val };
            return null;
        }
    }

    public class Int16Node : MemoryNode
    {
        public override int ByteSize => 2;
        public override string TypeName => "int16";
        public override Color DisplayColor => DarkTheme.Success;

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 2) return "?";
            return BitConverter.ToInt16(RawBytes, 0).ToString();
        }

        public override byte[] ParseInput(string input)
        {
            if (short.TryParse(input.Trim(), out short val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class UInt16Node : MemoryNode
    {
        public override int ByteSize => 2;
        public override string TypeName => "uint16";
        public override Color DisplayColor => Color.FromArgb(121, 192, 255);

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 2) return "?";
            return BitConverter.ToUInt16(RawBytes, 0).ToString();
        }

        public override byte[] ParseInput(string input)
        {
            if (ushort.TryParse(input.Trim(), out ushort val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class Int32Node : MemoryNode
    {
        public override int ByteSize => 4;
        public override string TypeName => "int32";
        public override Color DisplayColor => DarkTheme.Success;

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 4) return "?";
            return BitConverter.ToInt32(RawBytes, 0).ToString();
        }

        public override byte[] ParseInput(string input)
        {
            if (int.TryParse(input.Trim(), out int val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class UInt32Node : MemoryNode
    {
        public override int ByteSize => 4;
        public override string TypeName => "uint32";
        public override Color DisplayColor => Color.FromArgb(121, 192, 255);

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 4) return "?";
            return BitConverter.ToUInt32(RawBytes, 0).ToString();
        }

        public override byte[] ParseInput(string input)
        {
            if (uint.TryParse(input.Trim(), out uint val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class Int64Node : MemoryNode
    {
        public override int ByteSize => 8;
        public override string TypeName => "int64";
        public override Color DisplayColor => Color.FromArgb(63, 185, 80);

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 8) return "?";
            return BitConverter.ToInt64(RawBytes, 0).ToString();
        }

        public override byte[] ParseInput(string input)
        {
            if (long.TryParse(input.Trim(), out long val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class UInt64Node : MemoryNode
    {
        public override int ByteSize => 8;
        public override string TypeName => "uint64";
        public override Color DisplayColor => Color.FromArgb(121, 192, 255);

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 8) return "?";
            return BitConverter.ToUInt64(RawBytes, 0).ToString();
        }

        public override byte[] ParseInput(string input)
        {
            if (ulong.TryParse(input.Trim(), out ulong val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }
}
