using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    /// <summary>
    /// Class/Struct container node — groups child nodes into a named structure.
    /// Children define the struct layout sequentially.
    /// </summary>
    public class ClassNode : MemoryNode
    {
        public override int ByteSize => Children != null ? Children.Sum(c => c.ByteSize) : 0;
        public override string TypeName => "struct";
        public override Color DisplayColor => DarkTheme.TextPrimary;

        public override string FormatValue()
        {
            return $"{{{(Children != null ? Children.Count : 0)} fields}}";
        }

        public override byte[] ParseInput(string input)
        {
            return null; // Class nodes are containers, not editable
        }

        public ClassNode()
        {
            Name = "MyStruct";
            Children = new List<MemoryNode>();
            IsExpanded = true;
        }

        public ClassNode(string name)
        {
            Name = name;
            Children = new List<MemoryNode>();
            IsExpanded = true;
        }

        public void AddNode(MemoryNode node)
        {
            node.Parent = this;
            Children.Add(node);
            RecalculateOffsets();
        }

        public void InsertNode(int index, MemoryNode node)
        {
            node.Parent = this;
            Children.Insert(index, node);
            RecalculateOffsets();
        }

        public void RemoveNode(MemoryNode node)
        {
            Children.Remove(node);
            RecalculateOffsets();
        }

        public void ReplaceNode(MemoryNode oldNode, MemoryNode newNode)
        {
            int index = Children.IndexOf(oldNode);
            if (index >= 0)
            {
                newNode.Name = oldNode.Name;
                newNode.Parent = this;
                Children[index] = newNode;
                RecalculateOffsets();
            }
        }

        public override bool ReadMemory(IMemoryReader driver, int pid, ulong baseAddr)
        {
            // ClassNode itself doesn't read memory — it delegates to children
            ulong myAddr = baseAddr + (ulong)Offset;
            bool allOk = true;
            if (Children != null)
            {
                foreach (var child in Children)
                {
                    if (!child.ReadMemory(driver, pid, myAddr))
                        allOk = false;
                }
            }
            return allOk;
        }

        public override int GetVisibleRowCount()
        {
            int count = 1; // the class header row
            if (IsExpanded && Children != null)
            {
                foreach (var child in Children)
                    count += child.GetVisibleRowCount();
            }
            return count;
        }

        public override int TotalByteSize => ByteSize;
    }
}
