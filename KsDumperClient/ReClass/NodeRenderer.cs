using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using KsDumperClient.Utility;

namespace KsDumperClient.ReClass
{
    /// <summary>
    /// Custom GDI+ renderer for the ReClass node tree view.
    /// Draws columns: Offset | Address | Hex Bytes | Value | Type Name
    /// </summary>
    public class NodeRenderer
    {
        public const int RowHeight = 20;
        public const int IndentWidth = 16;
        public const int OffsetColumnWidth = 55;
        public const int AddressColumnWidth = 140;
        public const int HexColumnWidth = 200;
        public const int ValueColumnWidth = 200;
        public const int TypeColumnWidth = 100;
        public const int ExpandToggleSize = 10;
        public const int HeaderHeight = 22;

        private readonly Font monoFont;
        private readonly Font uiFont;
        private readonly Font uiFontBold;
        private readonly Brush bgBrush;
        private readonly Brush surfaceBrush;
        private readonly Brush selectedBrush;
        private readonly Brush headerBrush;
        private readonly Pen gridPen;

        public NodeRenderer()
        {
            monoFont = DarkTheme.UIMonoFont;
            uiFont = DarkTheme.UIFont;
            uiFontBold = DarkTheme.UIFontBold;
            bgBrush = new SolidBrush(DarkTheme.Background);
            surfaceBrush = new SolidBrush(DarkTheme.Surface);
            selectedBrush = new SolidBrush(Color.FromArgb(30, 56, 139, 253));
            headerBrush = new SolidBrush(DarkTheme.SurfaceElevated);
            gridPen = new Pen(DarkTheme.BorderSubtle, 1);
        }

        public void DrawHeader(Graphics g, int width)
        {
            g.FillRectangle(headerBrush, 0, 0, width, HeaderHeight);

            int x = 4;
            using (var sf = new StringFormat { LineAlignment = StringAlignment.Center })
            using (var brush = new SolidBrush(DarkTheme.TextSecondary))
            {
                g.DrawString("Offset", uiFontBold, brush, x + IndentWidth, HeaderHeight / 2, sf);
                x += OffsetColumnWidth;
                g.DrawString("Address", uiFontBold, brush, x, HeaderHeight / 2, sf);
                x += AddressColumnWidth;
                g.DrawString("Hex", uiFontBold, brush, x, HeaderHeight / 2, sf);
                x += HexColumnWidth;
                g.DrawString("Value", uiFontBold, brush, x, HeaderHeight / 2, sf);
                x += ValueColumnWidth;
                g.DrawString("Type", uiFontBold, brush, x, HeaderHeight / 2, sf);
            }

            g.DrawLine(gridPen, 0, HeaderHeight - 1, width, HeaderHeight - 1);
        }

        public int Render(Graphics g, MemoryNode root, Rectangle clipRect, int scrollY, int width, MemoryNode selectedNode)
        {
            int y = HeaderHeight - scrollY;
            int totalRows = 0;

            if (root is ClassNode classNode)
            {
                y = RenderNode(g, classNode, clipRect, scrollY, width, y, 0, selectedNode, ref totalRows);
            }
            else
            {
                y = RenderNode(g, root, clipRect, scrollY, width, y, 0, selectedNode, ref totalRows);
            }

            return totalRows;
        }

        private int RenderNode(Graphics g, MemoryNode node, Rectangle clipRect, int scrollY, int width, int y, int indent, MemoryNode selectedNode, ref int totalRows)
        {
            // Skip rows above visible area
            if (y + RowHeight < HeaderHeight)
            {
                totalRows++;
                if (node.IsExpanded && node.Children != null)
                {
                    foreach (var child in node.Children)
                        y = RenderNode(g, child, clipRect, scrollY, width, y, indent + 1, selectedNode, ref totalRows);
                }
                return y;
            }

            // Skip rows below visible area
            if (y > clipRect.Bottom)
                return y;

            totalRows++;

            // Row background
            bool isSelected = (node == selectedNode);
            g.FillRectangle(isSelected ? selectedBrush : bgBrush, 0, y, width, RowHeight);

            // Alternate row shading
            if (!isSelected && totalRows % 2 == 0)
            {
                using (var altBrush = new SolidBrush(Color.FromArgb(18, 22, 28)))
                    g.FillRectangle(altBrush, 0, y, width, RowHeight);
            }

            using (var sf = new StringFormat { LineAlignment = StringAlignment.Center, Trimming = StringTrimming.EllipsisCharacter })
            {
                int x = 4;

                // Expand toggle for container nodes
                bool hasChildren = node.Children != null && node.Children.Count > 0;
                if (hasChildren)
                {
                    int toggleX = x + indent * IndentWidth;
                    int toggleY = y + (RowHeight - ExpandToggleSize) / 2;
                    DrawExpandToggle(g, toggleX, toggleY, node.IsExpanded);
                }

                // Offset column
                using (var offsetBrush = new SolidBrush(DarkTheme.TextMuted))
                {
                    string offsetText = "0x" + node.Offset.ToString("X");
                    g.DrawString(offsetText, monoFont, offsetBrush,
                        new RectangleF(x + indent * IndentWidth + (hasChildren ? ExpandToggleSize + 2 : 0), y,
                            OffsetColumnWidth - indent * IndentWidth - (hasChildren ? ExpandToggleSize + 2 : 0), RowHeight), sf);
                }
                x += OffsetColumnWidth;

                // Address column
                using (var addrBrush = new SolidBrush(DarkTheme.TextSecondary))
                {
                    g.DrawString(node.FormatAddress(node.ResolvedAddress), monoFont, addrBrush,
                        new RectangleF(x, y, AddressColumnWidth, RowHeight), sf);
                }
                x += AddressColumnWidth;

                // Hex column
                using (var hexBrush = new SolidBrush(DarkTheme.TextSecondary))
                {
                    g.DrawString(node.FormatHex(), monoFont, hexBrush,
                        new RectangleF(x, y, HexColumnWidth, RowHeight), sf);
                }
                x += HexColumnWidth;

                // Value column (colored by type)
                using (var valueBrush = new SolidBrush(node.DisplayColor))
                {
                    g.DrawString(node.FormatValue(), monoFont, valueBrush,
                        new RectangleF(x, y, ValueColumnWidth, RowHeight), sf);
                }
                x += ValueColumnWidth;

                // Type column + Name
                using (var typeBrush = new SolidBrush(DarkTheme.TextMuted))
                using (var nameBrush = new SolidBrush(DarkTheme.TextPrimary))
                {
                    string typeText = node.TypeName;
                    string nameText = string.IsNullOrEmpty(node.Name) ? "" : $" {node.Name}";
                    g.DrawString(typeText, uiFont, typeBrush,
                        new RectangleF(x, y, TypeColumnWidth, RowHeight), sf);
                    g.DrawString(nameText, uiFont, nameBrush,
                        new RectangleF(x + TypeColumnWidth, y, 200, RowHeight), sf);
                }
            }

            // Grid line
            g.DrawLine(gridPen, 0, y + RowHeight - 1, width, y + RowHeight - 1);

            y += RowHeight;

            // Render children if expanded
            if (node.IsExpanded && node.Children != null)
            {
                foreach (var child in node.Children)
                    y = RenderNode(g, child, clipRect, scrollY, width, y, indent + 1, selectedNode, ref totalRows);
            }

            return y;
        }

        private void DrawExpandToggle(Graphics g, int x, int y, bool expanded)
        {
            using (var pen = new Pen(DarkTheme.TextSecondary, 1.5f))
            {
                if (expanded)
                {
                    // Down-pointing triangle
                    g.DrawLine(pen, x, y + 2, x + ExpandToggleSize / 2, y + ExpandToggleSize - 2);
                    g.DrawLine(pen, x + ExpandToggleSize / 2, y + ExpandToggleSize - 2, x + ExpandToggleSize, y + 2);
                    g.DrawLine(pen, x, y + 2, x + ExpandToggleSize, y + 2);
                }
                else
                {
                    // Right-pointing triangle
                    g.DrawLine(pen, x + 2, y, x + ExpandToggleSize - 2, y + ExpandToggleSize / 2);
                    g.DrawLine(pen, x + ExpandToggleSize - 2, y + ExpandToggleSize / 2, x + 2, y + ExpandToggleSize);
                    g.DrawLine(pen, x + 2, y, x + 2, y + ExpandToggleSize);
                }
            }
        }

        /// <summary>
        /// Hit-test: returns which node was clicked and which column.
        /// </summary>
        public HitTestResult HitTest(MemoryNode root, Point mousePos, int scrollY)
        {
            var result = new HitTestResult();

            if (mousePos.Y < HeaderHeight)
            {
                result.Area = HitArea.Header;
                return result;
            }

            int y = HeaderHeight - scrollY;
            HitTestNode(root, mousePos, y, 0, ref result);
            return result;
        }

        private int HitTestNode(MemoryNode node, Point mousePos, int y, int indent, ref HitTestResult result)
        {
            // Check if this row contains the mouse
            if (mousePos.Y >= y && mousePos.Y < y + RowHeight)
            {
                result.Node = node;
                result.RowY = y;

                int x = 4 + indent * IndentWidth;
                bool hasChildren = node.Children != null && node.Children.Count > 0;

                // Check toggle area
                if (hasChildren && mousePos.X >= x && mousePos.X < x + ExpandToggleSize + 2)
                {
                    result.Area = HitArea.Toggle;
                    return y;
                }

                x += OffsetColumnWidth;

                if (mousePos.X < x)
                    result.Area = HitArea.Offset;
                else if (mousePos.X < x + AddressColumnWidth)
                    result.Area = HitArea.Address;
                else if (mousePos.X < x + AddressColumnWidth + HexColumnWidth)
                    result.Area = HitArea.Hex;
                else if (mousePos.X < x + AddressColumnWidth + HexColumnWidth + ValueColumnWidth)
                    result.Area = HitArea.Value;
                else
                    result.Area = HitArea.TypeName;

                return y;
            }

            y += RowHeight;

            // Check children
            if (node.IsExpanded && node.Children != null)
            {
                foreach (var child in node.Children)
                {
                    y = HitTestNode(child, mousePos, y, indent + 1, ref result);
                    if (result.Node != null)
                        return y;
                }
            }

            return y;
        }

        public int GetTotalHeight(MemoryNode root)
        {
            if (root == null) return HeaderHeight;
            return HeaderHeight + root.GetVisibleRowCount() * RowHeight;
        }
    }

    public enum HitArea
    {
        None, Header, Toggle, Offset, Address, Hex, Value, TypeName
    }

    public class HitTestResult
    {
        public MemoryNode Node { get; set; }
        public HitArea Area { get; set; }
        public int RowY { get; set; }
    }
}
