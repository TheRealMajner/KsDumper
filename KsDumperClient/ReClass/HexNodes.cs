using System;
using System.Drawing;
using System.Text;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    public class Hex8Node : MemoryNode
    {
        public override int ByteSize => 1;
        public override string TypeName => "hex8";
        public override Color DisplayColor => DarkTheme.TextSecondary;

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 1) return "??";
            return RawBytes[0].ToString("X2");
        }

        public override byte[] ParseInput(string input)
        {
            input = input.Trim();
            if (byte.TryParse(input, System.Globalization.NumberStyles.HexNumber, null, out byte val))
                return new byte[] { val };
            return null;
        }
    }

    public class Hex16Node : MemoryNode
    {
        public override int ByteSize => 2;
        public override string TypeName => "hex16";
        public override Color DisplayColor => DarkTheme.TextSecondary;

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 2) return "?? ??";
            return $"{RawBytes[0]:X2} {RawBytes[1]:X2}";
        }

        public override byte[] ParseInput(string input)
        {
            input = input.Replace(" ", "").Trim();
            if (ushort.TryParse(input, System.Globalization.NumberStyles.HexNumber, null, out ushort val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class Hex32Node : MemoryNode
    {
        public override int ByteSize => 4;
        public override string TypeName => "hex32";
        public override Color DisplayColor => DarkTheme.TextSecondary;

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 4) return "?? ?? ?? ??";
            return $"{RawBytes[0]:X2} {RawBytes[1]:X2} {RawBytes[2]:X2} {RawBytes[3]:X2}";
        }

        public override byte[] ParseInput(string input)
        {
            input = input.Replace(" ", "").Trim();
            if (uint.TryParse(input, System.Globalization.NumberStyles.HexNumber, null, out uint val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class Hex64Node : MemoryNode
    {
        public override int ByteSize => 8;
        public override string TypeName => "hex64";
        public override Color DisplayColor => DarkTheme.TextSecondary;

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 8) return "?? ?? ?? ?? ?? ?? ?? ??";
            return $"{RawBytes[0]:X2} {RawBytes[1]:X2} {RawBytes[2]:X2} {RawBytes[3]:X2} {RawBytes[4]:X2} {RawBytes[5]:X2} {RawBytes[6]:X2} {RawBytes[7]:X2}";
        }

        public override byte[] ParseInput(string input)
        {
            input = input.Replace(" ", "").Trim();
            if (ulong.TryParse(input, System.Globalization.NumberStyles.HexNumber, null, out ulong val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }
}
