using System;
using System.Drawing;
using System.Globalization;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    public class FloatNode : MemoryNode
    {
        public override int ByteSize => 4;
        public override string TypeName => "float";
        public override Color DisplayColor => DarkTheme.Warning;

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 4) return "?";
            float val = BitConverter.ToSingle(RawBytes, 0);
            if (float.IsNaN(val)) return "NaN";
            if (float.IsInfinity(val)) return float.IsPositiveInfinity(val) ? "+Inf" : "-Inf";
            return val.ToString("F4", CultureInfo.InvariantCulture);
        }

        public override byte[] ParseInput(string input)
        {
            if (float.TryParse(input.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out float val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class DoubleNode : MemoryNode
    {
        public override int ByteSize => 8;
        public override string TypeName => "double";
        public override Color DisplayColor => Color.FromArgb(210, 153, 34);

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 8) return "?";
            double val = BitConverter.ToDouble(RawBytes, 0);
            if (double.IsNaN(val)) return "NaN";
            if (double.IsInfinity(val)) return double.IsPositiveInfinity(val) ? "+Inf" : "-Inf";
            return val.ToString("F6", CultureInfo.InvariantCulture);
        }

        public override byte[] ParseInput(string input)
        {
            if (double.TryParse(input.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out double val))
                return BitConverter.GetBytes(val);
            return null;
        }
    }

    public class BoolNode : MemoryNode
    {
        public override int ByteSize => 1;
        public override string TypeName => "bool";
        public override Color DisplayColor => Color.FromArgb(188, 140, 255);

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 1) return "?";
            return RawBytes[0] != 0 ? "true" : "false";
        }

        public override byte[] ParseInput(string input)
        {
            input = input.Trim().ToLower();
            if (input == "true" || input == "1")
                return new byte[] { 1 };
            if (input == "false" || input == "0")
                return new byte[] { 0 };
            return null;
        }
    }
}
