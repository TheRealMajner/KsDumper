using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Memory Map Visualizer - shows a visual representation of process memory layout
    /// with color-coded regions (committed, reserved, free, guard, image, mapped, private).
    /// </summary>
    public class MemoryMapVisualizer : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private Panel mapPanel;
        private ListView regionList;
        private RichTextBox detailsBox;
        private Button refreshBtn;
        private CheckBox showFreeCheck;
        private CheckBox showReservedCheck;
        private PictureBox legendBox;

        private struct MemoryRegion
        {
            public ulong BaseAddress;
            public ulong Size;
            public uint Protect;
            public uint State;
            public uint Type;
            public float Entropy;
        }

        private List<MemoryRegion> regions;
        private List<Rectangle> squarePositions; // For mouse hit-testing
        private string statsText = "";

        // Colors for region types
        private static readonly Color ColorCommitted = Color.FromArgb(63, 185, 80);
        private static readonly Color ColorReserved = Color.FromArgb(88, 166, 255);
        private static readonly Color ColorFree = Color.FromArgb(30, 35, 42);
        private static readonly Color ColorImage = Color.FromArgb(210, 153, 34);
        private static readonly Color ColorMapped = Color.FromArgb(180, 140, 255);
        private static readonly Color ColorPrivate = Color.FromArgb(63, 185, 80);
        private static readonly Color ColorGuard = Color.FromArgb(248, 81, 73);
        private static readonly Color ColorNoAccess = Color.FromArgb(110, 118, 129);

        public MemoryMapVisualizer(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            regions = new List<MemoryRegion>();
            squarePositions = new List<Rectangle>();
            InitializeComponent();
            RefreshMap();
        }

        private void InitializeComponent()
        {
            Text = $"Memory Map - {processName} (PID: {processId})";
            Size = new Size(1100, 750);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar — buttons and checkboxes only (no stats label to prevent text overflow)
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 6, 8, 4) };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshMap();
            refreshBtn.Margin = new Padding(2, 0, 12, 0);
            showFreeCheck = new DarkCheckBox { Text = "Show Free", AutoSize = true, Checked = false, Margin = new Padding(4, 2, 12, 0) };
            showFreeCheck.CheckedChanged += (s, e) => RefreshMap();
            showReservedCheck = new DarkCheckBox { Text = "Show Reserved", AutoSize = true, Checked = true, Margin = new Padding(4, 2, 12, 0) };
            showReservedCheck.CheckedChanged += (s, e) => RefreshMap();

            toolbar.Controls.AddRange(new Control[] { refreshBtn, showFreeCheck, showReservedCheck });

            // Legend
            legendBox = new PictureBox { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface };
            legendBox.Paint += LegendBox_Paint;

            // Main split: map (top) + list/details (bottom)
            var mainSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 250 };
            mainSplit.Panel1.BackColor = DarkTheme.Background;
            mainSplit.Panel2.BackColor = DarkTheme.Background;

            // Memory map visualization panel
            mapPanel = new Panel { Dock = DockStyle.Fill, BackColor = DarkTheme.Background, AutoScroll = true };
            mapPanel.Paint += MapPanel_Paint;
            mapPanel.MouseClick += MapPanel_MouseClick;
            mainSplit.Panel1.Controls.Add(mapPanel);

            // Bottom split: region list (left) + details (right)
            var bottomSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 500 };
            bottomSplit.Panel1.BackColor = DarkTheme.Background;
            bottomSplit.Panel2.BackColor = DarkTheme.Background;

            // Region list
            regionList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            regionList.Columns.Add("Base Address", 130);
            regionList.Columns.Add("End Address", 130);
            regionList.Columns.Add("Size", 80);
            regionList.Columns.Add("State", 80);
            regionList.Columns.Add("Protect", 120);
            regionList.Columns.Add("Type", 80);
            regionList.Columns.Add("Entropy", 60);
            regionList.Resize += (s, e) => { if (regionList.Columns.Count > 0) regionList.Columns[regionList.Columns.Count - 1].Width = -2; };
            regionList.SelectedIndexChanged += RegionList_SelectedIndexChanged;
            bottomSplit.Panel1.Controls.Add(regionList);

            // Details
            detailsBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };
            bottomSplit.Panel2.Controls.Add(detailsBox);

            mainSplit.Panel2.Controls.Add(bottomSplit);

            Controls.Add(mainSplit);
            Controls.Add(legendBox);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshMap()
        {
            regions.Clear();
            regionList.Items.Clear();

            try
            {
                var rawRegions = driver.EnumRegions(processId);

                ulong totalCommitted = 0, totalReserved = 0, totalFree = 0;
                ulong totalImage = 0, totalMapped = 0, totalPrivate = 0;
                int committedCount = 0, imageCount = 0;

                foreach (var (baseAddr, size, protect, state, type) in rawRegions)
                {
                    if (state == 0x10000 && !showFreeCheck.Checked) continue; // MEM_FREE
                    if (state == 0x2000 && !showReservedCheck.Checked) continue; // MEM_RESERVE

                    float entropy = 0;
                    if (state == 0x1000 && size <= 0x100000) // Only calculate for committed regions < 1MB
                    {
                        entropy = CalculateRegionEntropy(baseAddr, (int)Math.Min(size, 0x10000));
                    }

                    var region = new MemoryRegion
                    {
                        BaseAddress = baseAddr,
                        Size = size,
                        Protect = protect,
                        State = state,
                        Type = type,
                        Entropy = entropy
                    };
                    regions.Add(region);

                    // Stats
                    if (state == 0x1000) { totalCommitted += size; committedCount++; }
                    else if (state == 0x2000) totalReserved += size;
                    else if (state == 0x10000) totalFree += size;

                    if (type == 0x1000000) { totalImage += size; imageCount++; }
                    else if (type == 0x40000) totalMapped += size;
                    else if (type == 0x20000) totalPrivate += size;

                    // Add to list
                    var lvi = new ListViewItem($"0x{baseAddr:X}");
                    lvi.SubItems.Add($"0x{baseAddr + size:X}");
                    lvi.SubItems.Add(FormatSize(size));
                    lvi.SubItems.Add(FormatState(state));
                    lvi.SubItems.Add(FormatProtect(protect));
                    lvi.SubItems.Add(FormatType(type));
                    lvi.SubItems.Add(entropy > 0 ? $"{entropy:F2}" : "-");

                    lvi.ForeColor = GetRegionColor(state, protect, type);
                    lvi.Tag = region;
                    regionList.Items.Add(lvi);
                }

                statsText = $"Regions: {regions.Count} | Committed: {FormatSize(totalCommitted)} ({committedCount}) | Image: {FormatSize(totalImage)} ({imageCount}) | Reserved: {FormatSize(totalReserved)}";
                mapPanel.Invalidate();
                legendBox.Invalidate();
            }
            catch (Exception ex)
            {
                detailsBox.Text = $"Error: {ex.Message}";
            }
        }

        private float CalculateRegionEntropy(ulong address, int size)
        {
            IntPtr buf = IntPtr.Zero;
            try
            {
                byte[] data = new byte[size];
                buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (buf == IntPtr.Zero) return 0;
                if (driver.CopyVirtualMemory(processId, (IntPtr)address, buf, size))
                {
                    Marshal.Copy(buf, data, 0, size);
                    return (float)EntropyCalculator.CalculateEntropy(data);
                }
            }
            catch { }
            finally
            {
                if (buf != IntPtr.Zero) WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
            return 0;
        }

        private void MapPanel_Paint(object sender, PaintEventArgs e)
        {
            var g = e.Graphics;
            squarePositions.Clear();

            if (regions.Count == 0)
            {
                using (var brush = new SolidBrush(DarkTheme.TextMuted))
                    g.DrawString("No regions to display", DarkTheme.UIFont, brush, 20, 20);
                return;
            }

            int panelWidth = mapPanel.ClientSize.Width - 10;
            int panelHeight = mapPanel.ClientSize.Height - 10;
            if (panelWidth <= 0 || panelHeight <= 0) return;

            // Calculate square size to fit as many as possible
            int cols = Math.Max(1, panelWidth / 12); // Start with 12px squares
            int squareSize = Math.Max(4, Math.Min(16, panelWidth / cols - 1));
            int gap = squareSize > 6 ? 1 : 0;
            int step = squareSize + gap;

            // Recalculate columns with actual step
            cols = Math.Max(1, panelWidth / step);

            int x = 5;
            int y = 5;

            // Pre-create brushes for performance
            using (var guardPen = new Pen(ColorGuard, 1))
            using (var fontMono = new Font("Consolas", 6.5f))
            {
                for (int i = 0; i < regions.Count; i++)
                {
                    var r = regions[i];

                    // Wrap to next row
                    if (x + squareSize > panelWidth)
                    {
                        x = 5;
                        y += step;
                    }

                    // Stop if we'd go off screen
                    if (y + squareSize > panelHeight + 50)
                    {
                        // Fill remaining positions with empty rects for hit-test consistency
                        for (int j = i; j < regions.Count; j++)
                            squarePositions.Add(Rectangle.Empty);
                        break;
                    }

                    Color color = GetRegionColor(r.State, r.Protect, r.Type);

                    // Adjust brightness based on entropy
                    if (r.Entropy > 0)
                    {
                        int brightness = (int)(160 + r.Entropy / 8.0 * 95);
                        brightness = Math.Min(255, brightness);
                        color = Color.FromArgb(brightness, color);
                    }

                    var rect = new Rectangle(x, y, squareSize, squareSize);
                    squarePositions.Add(rect);

                    // Draw square
                    using (var brush = new SolidBrush(color))
                        g.FillRectangle(brush, rect);

                    // Guard pages get a red border
                    if ((r.Protect & 0x100) != 0)
                        g.DrawRectangle(guardPen, rect);

                    // Draw tooltip-style address for larger squares on hover (handled in MouseMove)
                    // For squares >= 10px, draw a single char indicator
                    if (squareSize >= 10)
                    {
                        string indicator = "";
                        if (r.State == 0x10000) indicator = "F";
                        else if (r.State == 0x2000) indicator = "R";
                        else if (r.Type == 0x1000000) indicator = "I";
                        else if (r.Type == 0x40000) indicator = "M";
                        else if ((r.Protect & 0x40) != 0) indicator = "X";

                        if (!string.IsNullOrEmpty(indicator))
                        {
                            using (var textBrush = new SolidBrush(Color.FromArgb(200, Color.White)))
                                g.DrawString(indicator, fontMono, textBrush, x + 1, y);
                        }
                    }

                    x += step;
                }
            }
        }

        private void MapPanel_MouseClick(object sender, MouseEventArgs e)
        {
            if (regions.Count == 0 || squarePositions.Count == 0) return;

            for (int i = 0; i < Math.Min(regions.Count, squarePositions.Count); i++)
            {
                if (squarePositions[i].Contains(e.Location))
                {
                    // Select this region in the list
                    if (i < regionList.Items.Count)
                    {
                        regionList.Items[i].Selected = true;
                        regionList.Items[i].EnsureVisible();
                    }
                    break;
                }
            }
        }

        private void LegendBox_Paint(object sender, PaintEventArgs e)
        {
            var g = e.Graphics;
            int x = 10;
            var items = new (Color color, string label)[]
            {
                (ColorCommitted, "Committed"),
                (ColorImage, "Image"),
                (ColorMapped, "Mapped"),
                (ColorReserved, "Reserved"),
                (ColorFree, "Free"),
                (ColorGuard, "Guard"),
                (ColorNoAccess, "NoAccess"),
            };

            foreach (var (color, label) in items)
            {
                using (var brush = new SolidBrush(color))
                    g.FillRectangle(brush, x, 8, 14, 14);
                using (var textBrush = new SolidBrush(DarkTheme.TextSecondary))
                    g.DrawString(label, DarkTheme.UIFontSmall, textBrush, x + 18, 8);
                x += 85;
            }

            // Draw stats text on the right side
            if (!string.IsNullOrEmpty(statsText))
            {
                using (var statsBrush = new SolidBrush(DarkTheme.Accent))
                {
                    var statsSize = g.MeasureString(statsText, DarkTheme.UIFontSmall);
                    float statsX = legendBox.ClientSize.Width - statsSize.Width - 10;
                    if (statsX > x + 10) // Only draw if there's room
                        g.DrawString(statsText, DarkTheme.UIFontSmall, statsBrush, statsX, 8);
                }
            }
        }

        private void RegionList_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (regionList.SelectedItems.Count == 0) { detailsBox.Clear(); return; }
            if (regionList.SelectedItems[0].Tag is MemoryRegion r)
            {
                detailsBox.Clear();
                detailsBox.SelectionColor = DarkTheme.Accent;
                detailsBox.AppendText("Memory Region Details\n");
                detailsBox.SelectionColor = DarkTheme.TextSecondary;
                detailsBox.AppendText(new string('═', 50) + "\n\n");

                detailsBox.SelectionColor = DarkTheme.TextPrimary;
                detailsBox.AppendText($"  Base Address:  0x{r.BaseAddress:X}\n");
                detailsBox.AppendText($"  End Address:   0x{r.BaseAddress + r.Size:X}\n");
                detailsBox.AppendText($"  Size:          {FormatSize(r.Size)} ({r.Size:N0} bytes)\n");
                detailsBox.AppendText($"  State:         {FormatState(r.State)} (0x{r.State:X})\n");
                detailsBox.AppendText($"  Protection:    {FormatProtect(r.Protect)} (0x{r.Protect:X})\n");
                detailsBox.AppendText($"  Type:          {FormatType(r.Type)} (0x{r.Type:X})\n");

                if (r.Entropy > 0)
                {
                    detailsBox.SelectionColor = EntropyCalculator.EntropyColor(r.Entropy);
                    detailsBox.AppendText($"  Entropy:       {r.Entropy:F4} bits/byte ({EntropyCalculator.EntropyLabel(r.Entropy)})\n");
                }

                // Protection details
                detailsBox.SelectionColor = DarkTheme.TextSecondary;
                detailsBox.AppendText("\n  Protection flags:\n");
                detailsBox.SelectionColor = DarkTheme.TextPrimary;
                if ((r.Protect & 0x01) != 0) detailsBox.AppendText("    PAGE_NOACCESS\n");
                if ((r.Protect & 0x02) != 0) detailsBox.AppendText("    PAGE_READONLY\n");
                if ((r.Protect & 0x04) != 0) detailsBox.AppendText("    PAGE_READWRITE\n");
                if ((r.Protect & 0x08) != 0) detailsBox.AppendText("    PAGE_WRITECOPY\n");
                if ((r.Protect & 0x10) != 0) detailsBox.AppendText("    PAGE_EXECUTE\n");
                if ((r.Protect & 0x20) != 0) detailsBox.AppendText("    PAGE_EXECUTE_READ\n");
                if ((r.Protect & 0x40) != 0) detailsBox.AppendText("    PAGE_EXECUTE_READWRITE\n");
                if ((r.Protect & 0x80) != 0) detailsBox.AppendText("    PAGE_EXECUTE_WRITECOPY\n");
                if ((r.Protect & 0x100) != 0) detailsBox.AppendText("    PAGE_GUARD\n");
                if ((r.Protect & 0x200) != 0) detailsBox.AppendText("    PAGE_NOCACHE\n");
                if ((r.Protect & 0x400) != 0) detailsBox.AppendText("    PAGE_WRITECOMBINE\n");
            }
        }

        // ==================== Formatting ====================

        private Color GetRegionColor(uint state, uint protect, uint type)
        {
            if (state == 0x10000) return ColorFree;
            if (state == 0x2000) return ColorReserved;
            if ((protect & 0x100) != 0) return ColorGuard; // Guard
            if ((protect & 0x01) != 0) return ColorNoAccess;
            if (type == 0x1000000) return ColorImage;
            if (type == 0x40000) return ColorMapped;
            if (type == 0x20000) return ColorPrivate;
            return ColorCommitted;
        }

        private string FormatSize(ulong bytes)
        {
            if (bytes >= 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
            if (bytes >= 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
            if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes} B";
        }

        private string FormatState(uint state)
        {
            if (state == 0x1000) return "COMMIT";
            if (state == 0x2000) return "RESERVE";
            if (state == 0x10000) return "FREE";
            return $"0x{state:X}";
        }

        private string FormatProtect(uint p)
        {
            var parts = new List<string>();
            if ((p & 0x01) != 0) parts.Add("NOACCESS");
            if ((p & 0x02) != 0) parts.Add("R");
            if ((p & 0x04) != 0) parts.Add("RW");
            if ((p & 0x08) != 0) parts.Add("WCOPY");
            if ((p & 0x10) != 0) parts.Add("X");
            if ((p & 0x20) != 0) parts.Add("RX");
            if ((p & 0x40) != 0) parts.Add("RWX");
            if ((p & 0x80) != 0) parts.Add("XRWC");
            if ((p & 0x100) != 0) parts.Add("GUARD");
            if ((p & 0x200) != 0) parts.Add("NC");
            if ((p & 0x400) != 0) parts.Add("WCB");
            return parts.Count > 0 ? string.Join("|", parts) : "NONE";
        }

        private string FormatType(uint t)
        {
            if (t == 0x20000) return "PRIVATE";
            if (t == 0x40000) return "MAPPED";
            if (t == 0x1000000) return "IMAGE";
            return t == 0 ? "-" : $"0x{t:X}";
        }

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
