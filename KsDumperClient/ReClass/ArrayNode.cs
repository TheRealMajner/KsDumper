using System;
using System.Collections.Generic;
using System.Drawing;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    /// <summary>
    /// Array node — N copies of a prototype element node.
    /// </summary>
    public class ArrayNode : MemoryNode
    {
        public MemoryNode ElementPrototype { get; set; }
        public int Count { get; set; }

        public override int ByteSize => ElementPrototype.ByteSize * Count;
        public override string TypeName => $"{ElementPrototype.TypeName}[{Count}]";
        public override Color DisplayColor => ElementPrototype.DisplayColor;

        public override string FormatValue()
        {
            return $"[{Count}]";
        }

        public override byte[] ParseInput(string input)
        {
            return null; // Array nodes are containers, not directly editable
        }

        public ArrayNode()
        {
            Count = 4;
            ElementPrototype = new Int32Node();
            Name = "array";
            Children = new List<MemoryNode>();
            RebuildChildren();
        }

        public ArrayNode(MemoryNode prototype, int count)
        {
            ElementPrototype = prototype;
            Count = count;
            Name = "array";
            Children = new List<MemoryNode>();
            RebuildChildren();
        }

        public void RebuildChildren()
        {
            Children.Clear();
            for (int i = 0; i < Count; i++)
            {
                var element = CreateClone(ElementPrototype);
                element.Name = $"[{i}]";
                element.Offset = i * ElementPrototype.ByteSize;
                element.Parent = this;
                Children.Add(element);
            }
        }

        private MemoryNode CreateClone(MemoryNode source)
        {
            if (source is Int32Node) return new Int32Node();
            if (source is UInt32Node) return new UInt32Node();
            if (source is Int64Node) return new Int64Node();
            if (source is UInt64Node) return new UInt64Node();
            if (source is FloatNode) return new FloatNode();
            if (source is DoubleNode) return new DoubleNode();
            if (source is Hex8Node) return new Hex8Node();
            if (source is Hex16Node) return new Hex16Node();
            if (source is Hex32Node) return new Hex32Node();
            if (source is Hex64Node) return new Hex64Node();
            if (source is BoolNode) return new BoolNode();
            if (source is Int8Node) return new Int8Node();
            if (source is UInt8Node) return new UInt8Node();
            if (source is Int16Node) return new Int16Node();
            if (source is UInt16Node) return new UInt16Node();
            if (source is PointerNode) return new PointerNode();
            if (source is TextNode t) return new TextNode(t.Length, t.IsUnicode);
            // Default fallback
            return new Int32Node();
        }

        public override bool ReadMemory(IMemoryReader driver, int pid, ulong baseAddr)
        {
            bool ok = base.ReadMemory(driver, pid, baseAddr);
            if (IsExpanded && Children != null)
            {
                ulong myAddr = baseAddr + (ulong)Offset;
                foreach (var child in Children)
                {
                    child.ReadMemory(driver, pid, myAddr);
                }
            }
            return ok;
        }

        public override int GetVisibleRowCount()
        {
            int count = 1;
            if (IsExpanded && Children != null)
            {
                foreach (var child in Children)
                    count += child.GetVisibleRowCount();
            }
            return count;
        }
    }
}
