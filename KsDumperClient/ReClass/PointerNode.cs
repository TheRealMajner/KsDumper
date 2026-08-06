using System;
using System.Collections.Generic;
using System.Drawing;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    /// <summary>
    /// Pointer node (8 bytes on x64). Reads the address stored at this memory location
    /// and optionally expands child nodes to show the structure at the pointed-to address.
    /// </summary>
    public class PointerNode : MemoryNode
    {
        public ulong PointedAddress { get; private set; }
        private bool isExpandedOnce;

        public override int ByteSize => 8;
        public override string TypeName => "ptr";
        public override Color DisplayColor => DarkTheme.Accent;

        public PointerNode()
        {
            Children = new List<MemoryNode>();
            // Default child: one Int64Node to show what's at the pointed address
            var defaultChild = new Int64Node { Name = "value", Parent = this };
            Children.Add(defaultChild);
        }

        public override string FormatValue()
        {
            if (RawBytes == null || RawBytes.Length < 8) return "-> ????????????????";
            PointedAddress = BitConverter.ToUInt64(RawBytes, 0);
            if (PointedAddress == 0)
                return "-> NULL";
            return "-> " + FormatAddress(PointedAddress);
        }

        public override byte[] ParseInput(string input)
        {
            input = input.Replace("0x", "").Replace("->", "").Trim();
            if (ulong.TryParse(input, System.Globalization.NumberStyles.HexNumber, null, out ulong val))
                return BitConverter.GetBytes(val);
            return null;
        }

        public override bool ReadMemory(IMemoryReader driver, int pid, ulong baseAddr)
        {
            bool ok = base.ReadMemory(driver, pid, baseAddr);
            if (ok && RawBytes != null && RawBytes.Length >= 8)
            {
                PointedAddress = BitConverter.ToUInt64(RawBytes, 0);

                // If expanded, read children at the pointed-to address
                if (IsExpanded && PointedAddress != 0 && Children != null)
                {
                    foreach (var child in Children)
                    {
                        child.ReadMemory(driver, pid, PointedAddress);
                    }
                }
            }
            return ok;
        }

        public override int GetVisibleRowCount()
        {
            int count = 1;
            if (IsExpanded && PointedAddress != 0 && Children != null)
            {
                foreach (var child in Children)
                    count += child.GetVisibleRowCount();
            }
            return count;
        }

        public void AddChild(MemoryNode node)
        {
            node.Parent = this;
            Children.Add(node);
            RecalculateOffsets();
        }

        public void RemoveChild(MemoryNode node)
        {
            Children.Remove(node);
            RecalculateOffsets();
        }
    }
}
