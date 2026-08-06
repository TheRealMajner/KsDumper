using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// PE Compare window - compares a dumped PE (from memory) with the original on-disk file
    /// and highlights differences in headers, sections, and code.
    /// </summary>
    public class PECompareWindow : Form
    {
        private TextBox diskPathBox;
        private TextBox memoryPathBox;
        private Button browseDiskBtn;
        private Button browseMemoryBtn;
        private Button compareBtn;
        private RichTextBox resultBox;
        private ListView diffList;
        private Label statsLbl;

        private struct Difference
        {
            public string Section;
            public ulong Offset;
            public byte DiskByte;
            public byte MemoryByte;
            public string Description;
        }

        public PECompareWindow()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = "PE Compare - Disk vs Memory";
            Size = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(800, 500);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Top panel - file selection
            var topPanel = new Panel { Dock = DockStyle.Top, Height = 100, BackColor = DarkTheme.Surface, Padding = new Padding(8) };

            var row1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row1.Controls.Add(MakeLabel("On Disk:"));
            diskPathBox = CreateTextBox(400);
            row1.Controls.Add(diskPathBox);
            browseDiskBtn = CreateButton("Browse...", 80);
            browseDiskBtn.Click += (s, e) =>
            {
                using (var ofd = new OpenFileDialog())
                {
                    ofd.Filter = "PE Files|*.exe;*.dll;*.sys|All Files|*.*";
                    if (ofd.ShowDialog() == DialogResult.OK) diskPathBox.Text = ofd.FileName;
                }
            };
            row1.Controls.Add(browseDiskBtn);

            var row2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row2.Controls.Add(MakeLabel("Dumped:"));
            memoryPathBox = CreateTextBox(400);
            row2.Controls.Add(memoryPathBox);
            browseMemoryBtn = CreateButton("Browse...", 80);
            browseMemoryBtn.Click += (s, e) =>
            {
                using (var ofd = new OpenFileDialog())
                {
                    ofd.Filter = "PE Files|*.exe;*.dll;*.sys|All Files|*.*";
                    if (ofd.ShowDialog() == DialogResult.OK) memoryPathBox.Text = ofd.FileName;
                }
            };
            row2.Controls.Add(browseMemoryBtn);

            var row3 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            compareBtn = CreateButton("Compare", 80);
            compareBtn.Click += Compare_Click;
            statsLbl = new Label { Text = "", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            row3.Controls.Add(compareBtn);
            row3.Controls.Add(statsLbl);

            topPanel.Controls.Add(row3);
            topPanel.Controls.Add(row2);
            topPanel.Controls.Add(row1);

            // Split: diff list + result details
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 350 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            // Diff list
            diffList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont
            };
            diffList.Columns.Add("Section", 100);
            diffList.Columns.Add("Offset", 100);
            diffList.Columns.Add("Disk", 80);
            diffList.Columns.Add("Memory", 80);
            diffList.Columns.Add("Description", 400);
            diffList.Resize += (s, e) => { if (diffList.Columns.Count > 0) diffList.Columns[diffList.Columns.Count - 1].Width = -2; };

            // Result details
            resultBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            split.Panel1.Controls.Add(diffList);
            split.Panel2.Controls.Add(resultBox);

            Controls.Add(split);
            Controls.Add(topPanel);
            DarkTheme.ApplyTo(this);
        }

        private async void Compare_Click(object sender, EventArgs e)
        {
            string diskPath = diskPathBox.Text.Trim();
            string memPath = memoryPathBox.Text.Trim();

            if (!File.Exists(diskPath)) { MessageBox.Show("Disk file not found", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }
            if (!File.Exists(memPath)) { MessageBox.Show("Dumped file not found", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error); return; }

            compareBtn.Enabled = false;
            statsLbl.Text = "Comparing...";
            diffList.Items.Clear();
            resultBox.Clear();

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    byte[] diskBytes = File.ReadAllBytes(diskPath);
                    byte[] memBytes = File.ReadAllBytes(memPath);

                    var diffs = new List<Difference>();
                    var sb = new StringBuilder();

                    // Validate both are PEs
                    if (diskBytes.Length < 64 || BitConverter.ToUInt16(diskBytes, 0) != 0x5A4D)
                    {
                        this.SafeInvoke(() => resultBox.Text = "Disk file is not a valid PE");
                        return;
                    }
                    if (memBytes.Length < 64 || BitConverter.ToUInt16(memBytes, 0) != 0x5A4D)
                    {
                        this.SafeInvoke(() => resultBox.Text = "Dumped file is not a valid PE");
                        return;
                    }

                    int diskLfane = BitConverter.ToInt32(diskBytes, 60);
                    int memLfane = BitConverter.ToInt32(memBytes, 60);

                    // Compare DOS headers
                    CompareRegion(diskBytes, memBytes, 0, Math.Min(64, Math.Min(diskBytes.Length, memBytes.Length)), "DOS Header", diffs);

                    // Compare PE headers
                    if (diskLfane > 0 && memLfane > 0)
                    {
                        int peCompareLen = Math.Min(512, Math.Min(diskBytes.Length - diskLfane, memBytes.Length - memLfane));
                        if (peCompareLen > 0)
                            CompareRegion(diskBytes, memBytes, diskLfane, peCompareLen, "PE Header", diffs, memLfane - diskLfane);
                    }

                    // Compare sections
                    ushort diskNumSections = BitConverter.ToUInt16(diskBytes, diskLfane + 6);
                    ushort memNumSections = memLfane + 6 < memBytes.Length ? BitConverter.ToUInt16(memBytes, memLfane + 6) : (ushort)0;

                    ushort diskOptHdrSize = BitConverter.ToUInt16(diskBytes, diskLfane + 20);
                    int diskSecTableOff = diskLfane + 24 + diskOptHdrSize;
                    ushort memOptHdrSize = memLfane + 20 < memBytes.Length ? BitConverter.ToUInt16(memBytes, memLfane + 20) : (ushort)0;
                    int memSecTableOff = memLfane + 24 + memOptHdrSize;

                    sb.AppendLine("PE Compare Report");
                    sb.AppendLine(new string('═', 60));
                    sb.AppendLine($"  Disk file:   {Path.GetFileName(diskPath)} ({diskBytes.Length:N0} bytes)");
                    sb.AppendLine($"  Dumped file: {Path.GetFileName(memPath)} ({memBytes.Length:N0} bytes)");
                    sb.AppendLine($"  Disk sections: {diskNumSections}  |  Dumped sections: {memNumSections}");
                    sb.AppendLine();

                    if (diskNumSections != memNumSections)
                    {
                        diffs.Add(new Difference { Section = "Headers", Offset = (ulong)(diskLfane + 6), DiskByte = (byte)diskNumSections, MemoryByte = (byte)memNumSections, Description = $"Section count mismatch: disk={diskNumSections}, memory={memNumSections}" });
                    }

                    // Compare each section's raw data
                    int sectionsToCompare = Math.Min(diskNumSections, memNumSections);
                    for (int i = 0; i < sectionsToCompare; i++)
                    {
                        int diskSecOff = diskSecTableOff + i * 40;
                        int memSecOff = memSecTableOff + i * 40;
                        if (diskSecOff + 40 > diskBytes.Length || memSecOff + 40 > memBytes.Length) break;

                        string diskName = Encoding.ASCII.GetString(diskBytes, diskSecOff, 8).TrimEnd('\0');
                        string memName = Encoding.ASCII.GetString(memBytes, memSecOff, 8).TrimEnd('\0');

                        uint diskRawPtr = BitConverter.ToUInt32(diskBytes, diskSecOff + 20);
                        uint diskRawSize = BitConverter.ToUInt32(diskBytes, diskSecOff + 16);
                        uint memRawPtr = BitConverter.ToUInt32(memBytes, memSecOff + 20);
                        uint memRawSize = BitConverter.ToUInt32(memBytes, memSecOff + 16);

                        sb.AppendLine($"  [{diskName}] Disk: 0x{diskRawPtr:X}/0x{diskRawSize:X}  Memory: 0x{memRawPtr:X}/0x{memRawSize:X}");

                        if (diskName != memName)
                        {
                            diffs.Add(new Difference { Section = "Section Table", Offset = (ulong)diskSecOff, DiskByte = 0, MemoryByte = 0, Description = $"Section name mismatch: '{diskName}' vs '{memName}'" });
                            continue;
                        }

                        // Compare raw data
                        int compareSize = (int)Math.Min(diskRawSize, memRawSize);
                        compareSize = (int)Math.Min(compareSize, Math.Min(diskBytes.Length - diskRawPtr, memBytes.Length - memRawPtr));
                        if (compareSize <= 0) continue;

                        int sectionDiffs = 0;
                        for (int j = 0; j < compareSize; j++)
                        {
                            if (diskBytes[diskRawPtr + j] != memBytes[memRawPtr + j])
                            {
                                sectionDiffs++;
                                if (diffs.Count < 10000) // Cap diffs
                                {
                                    diffs.Add(new Difference
                                    {
                                        Section = diskName,
                                        Offset = (ulong)j,
                                        DiskByte = diskBytes[diskRawPtr + j],
                                        MemoryByte = memBytes[memRawPtr + j],
                                        Description = $"Byte differs at section offset 0x{j:X}"
                                    });
                                }
                            }
                        }

                        double diffPct = compareSize > 0 ? (double)sectionDiffs / compareSize * 100.0 : 0;
                        sb.AppendLine($"    Diffs: {sectionDiffs:N0} / {compareSize:N0} bytes ({diffPct:F2}%)");

                        if (diffPct > 50)
                            sb.AppendLine($"    ⚠ MAJOR: Section heavily modified");
                        else if (diffPct > 10)
                            sb.AppendLine($"    ⚠ Section significantly modified");
                        else if (diffPct > 0)
                            sb.AppendLine($"    Minor modifications");
                        else
                            sb.AppendLine($"    ✓ Identical");
                    }

                    sb.AppendLine();
                    sb.AppendLine($"Total differences: {diffs.Count:N0}");

                    this.SafeInvoke(() =>
                    {
                        foreach (var diff in diffs)
                        {
                            var lvi = new ListViewItem(diff.Section);
                            lvi.SubItems.Add($"0x{diff.Offset:X}");
                            lvi.SubItems.Add($"0x{diff.DiskByte:X2}");
                            lvi.SubItems.Add($"0x{diff.MemoryByte:X2}");
                            lvi.SubItems.Add(diff.Description);

                            if (diff.Description.Contains("MAJOR"))
                                lvi.ForeColor = DarkTheme.Error;
                            else if (diff.Description.Contains("mismatch"))
                                lvi.ForeColor = DarkTheme.Warning;
                            else
                                lvi.ForeColor = DarkTheme.TextPrimary;

                            diffList.Items.Add(lvi);
                        }

                        resultBox.Text = sb.ToString();
                        statsLbl.Text = $"Differences: {diffs.Count:N0}";
                        statsLbl.ForeColor = diffs.Count > 0 ? DarkTheme.Warning : DarkTheme.Success;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        resultBox.Text = $"Error: {ex.Message}";
                        statsLbl.Text = "Error";
                        statsLbl.ForeColor = DarkTheme.Error;
                    });
                }
            });

            compareBtn.Enabled = true;
        }

        private void CompareRegion(byte[] disk, byte[] mem, int diskOff, int len, string section, List<Difference> diffs, int memOffsetDelta = 0)
        {
            int memOff = diskOff + memOffsetDelta;
            for (int i = 0; i < len; i++)
            {
                int dOff = diskOff + i;
                int mOff = memOff + i;
                if (dOff >= disk.Length || mOff >= mem.Length) break;

                if (disk[dOff] != mem[mOff])
                {
                    if (diffs.Count < 10000)
                    {
                        diffs.Add(new Difference
                        {
                            Section = section,
                            Offset = (ulong)i,
                            DiskByte = disk[dOff],
                            MemoryByte = mem[mOff],
                            Description = $"{section} byte differs at offset 0x{i:X}"
                        });
                    }
                }
            }
        }

        // ==================== UI Helpers ====================

        private TextBox CreateTextBox(int width) => new TextBox { Width = width, Margin = new Padding(2, 0, 4, 0), BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.FixedSingle, Font = DarkTheme.UIFont };
        private Label MakeLabel(string text) => new Label { Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
        private Button CreateButton(string text, int width) { var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(btn); return btn; }
    }
}
