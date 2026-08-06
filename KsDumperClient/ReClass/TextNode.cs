using System;
using System.Drawing;
using System.Text;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    /// <summary>
    /// Text node — reads a fixed-length string from memory (ASCII or Unicode).
    /// </summary>
    public class TextNode : MemoryNode
    {
        public int Length { get; set; }
        public bool IsUnicode { get; set; }

        public override int ByteSize => IsUnicode ? Length * 2 : Length;
        public override string TypeName => IsUnicode ? $"wchar[{Length}]" : $"char[{Length}]";
        public override Color DisplayColor => Color.FromArgb(188, 140, 255);

        public TextNode()
        {
            Length = 32;
            IsUnicode = false;
            Name = "text";
        }

        public TextNode(int length, bool unicode = false)
        {
            Length = length;
            IsUnicode = unicode;
            Name = "text";
        }

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length == 0) return "\"\"";

            string text;
            if (IsUnicode)
            {
                int nullPos = -1;
                for (int i = 0; i < RawBytes.Length - 1; i += 2)
                {
                    if (RawBytes[i] == 0 && RawBytes[i + 1] == 0) { nullPos = i; break; }
                }
                int len = nullPos >= 0 ? nullPos : RawBytes.Length;
                text = Encoding.Unicode.GetString(RawBytes, 0, len);
            }
            else
            {
                int nullPos = Array.IndexOf(RawBytes, (byte)0);
                int len = nullPos >= 0 ? nullPos : RawBytes.Length;
                text = Encoding.ASCII.GetString(RawBytes, 0, len);
            }

            // Replace non-printable characters
            var sb = new StringBuilder(text.Length);
            foreach (char c in text)
            {
                if (c >= 32 && c < 127)
                    sb.Append(c);
                else
                    sb.Append('.');
            }

            return "\"" + sb.ToString() + "\"";
        }

        public override byte[] ParseInput(string input)
        {
            // Strip surrounding quotes
            if (input.StartsWith("\"") && input.EndsWith("\""))
                input = input.Substring(1, input.Length - 2);

            if (IsUnicode)
            {
                byte[] encoded = Encoding.Unicode.GetBytes(input);
                byte[] result = new byte[ByteSize];
                Array.Copy(encoded, result, Math.Min(encoded.Length, result.Length));
                return result;
            }
            else
            {
                byte[] encoded = Encoding.ASCII.GetBytes(input);
                byte[] result = new byte[ByteSize];
                Array.Copy(encoded, result, Math.Min(encoded.Length, result.Length));
                return result;
            }
        }
    }
}
