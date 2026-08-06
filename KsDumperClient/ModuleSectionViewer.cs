using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Module Section Viewer - shows detailed PE section information for any loaded module
    /// including headers, characteristics, entropy, and raw data preview.
    /// </summary>
    public class ModuleSectionViewer : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ComboBox moduleCombo;
        private ListView sectionList;
        private RichTextBox detailsBox;
        private RichTextBox hexView;
        private Button refreshBtn;
        private Button viewHexBtn;
        private Label statsLbl;

        public ModuleSectionViewer(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            LoadModules();
        }

        private void InitializeComponent()
        {
            Text = $"Module Sections - {processName} (PID: {processId})";
            Size = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            toolbar.Controls.Add(MakeLabel("Module:"));
            moduleCombo = new DarkComboBox { Width = 300 };
            moduleCombo.SelectedIndexChanged += (s, e) => LoadSections();
            toolbar.Controls.Add(moduleCombo);
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => LoadModules();
            viewHexBtn = CreateButton("View Hex", 80);
            viewHexBtn.Click += ViewHex_Click;
            statsLbl = new Label { Text = "", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.AddRange(new Control[] { refreshBtn, viewHexBtn, statsLbl });

            // Main split: sections (top) + details/hex (bottom)
            var mainSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 300 };
            mainSplit.Panel1.BackColor = DarkTheme.Background;
            mainSplit.Panel2.BackColor = DarkTheme.Background;

            sectionList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            sectionList.Columns.Add("Name", 80);
            sectionList.Columns.Add("VirtAddr", 100);
            sectionList.Columns.Add("VirtSize", 100);
            sectionList.Columns.Add("RawSize", 100);
            sectionList.Columns.Add("RawOff", 100);
            sectionList.Columns.Add("Characteristics", 200);
            sectionList.Columns.Add("Entropy", 70);
            sectionList.Resize += (s, e) => { if (sectionList.Columns.Count > 0) sectionList.Columns[sectionList.Columns.Count - 1].Width = -2; };
            sectionList.SelectedIndexChanged += SectionList_SelectedIndexChanged;

            // Bottom split: details (left) + hex (right)
            var bottomSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 400 };
            bottomSplit.Panel1.BackColor = DarkTheme.Background;
            bottomSplit.Panel2.BackColor = DarkTheme.Background;

            detailsBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            hexView = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both, WordWrap = false };

            bottomSplit.Panel1.Controls.Add(detailsBox);
            bottomSplit.Panel2.Controls.Add(hexView);
            mainSplit.Panel1.Controls.Add(sectionList);
            mainSplit.Panel2.Controls.Add(bottomSplit);

            Controls.Add(mainSplit);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void LoadModules()
        {
            moduleCombo.Items.Clear();
            try
            {
                if (driver.GetModuleSummaryList(processId, out var modules) && modules != null)
                {
                    foreach (var mod in modules)
                        moduleCombo.Items.Add($"{mod.ModuleName} (0x{mod.BaseAddress:X}, {mod.ImageSize / 1024}KB)");
                    if (moduleCombo.Items.Count > 0) moduleCombo.SelectedIndex = 0;
                    statsLbl.Text = $"Modules: {modules.Length}";
                }
            }
            catch (Exception ex) { detailsBox.Text = $"Error: {ex.Message}"; }
        }

        private void LoadSections()
        {
            sectionList.Items.Clear();
            detailsBox.Clear();
            hexView.Clear();

            if (moduleCombo.SelectedIndex < 0) return;

            try
            {
                if (driver.GetModuleSummaryList(processId, out var modules) && modules != null)
                {
                    var mod = modules[moduleCombo.SelectedIndex];
                    ulong baseAddr = mod.BaseAddress;

                    // Read PE headers
                    byte[] headers = new byte[0x1000];
                    IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)0x1000,
                        WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) return;
                    if (!driver.CopyVirtualMemory(processId, (IntPtr)baseAddr, buf, 0x1000))
                    {
                        WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                        return;
                    }
                    Marshal.Copy(buf, headers, 0, 0x1000);
                    WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);

                    if (BitConverter.ToUInt16(headers, 0) != 0x5A4D) return;
                    int e_lfanew = BitConverter.ToInt32(headers, 60);
                    if (e_lfanew + 24 > headers.Length) return;
                    if (BitConverter.ToUInt32(headers, e_lfanew) != 0x00004550) return;

                    ushort numSections = BitConverter.ToUInt16(headers, e_lfanew + 6);
                    ushort optHdrSize = BitConverter.ToUInt16(headers, e_lfanew + 20);
                    int secTableOff = e_lfanew + 24 + optHdrSize;

                    ushort magic = BitConverter.ToUInt16(headers, e_lfanew + 24);
                    bool is64 = magic == 0x20b;

                    // Show PE summary
                    detailsBox.SelectionColor = DarkTheme.Accent;
                    detailsBox.AppendText($"{mod.ModuleName}\n");
                    detailsBox.SelectionColor = DarkTheme.TextSecondary;
                    detailsBox.AppendText(new string('═', 50) + "\n\n");
                    detailsBox.SelectionColor = DarkTheme.TextPrimary;
                    detailsBox.AppendText($"  Base:      0x{baseAddr:X}\n");
                    detailsBox.AppendText($"  Type:      {(is64 ? "PE32+ (x64)" : "PE32 (x86)")}\n");
                    detailsBox.AppendText($"  Sections:  {numSections}\n");
                    detailsBox.AppendText($"  ImageSize: {mod.ImageSize / 1024}KB\n\n");

                    // Parse sections
                    double totalEntropy = 0;
                    int sectionCount = 0;

                    for (int i = 0; i < numSections; i++)
                    {
                        int secOff = secTableOff + i * 40;
                        if (secOff + 40 > headers.Length) break;

                        string name = Encoding.ASCII.GetString(headers, secOff, 8).TrimEnd('\0');
                        uint virtSize = BitConverter.ToUInt32(headers, secOff + 8);
                        uint virtAddr = BitConverter.ToUInt32(headers, secOff + 12);
                        uint rawSize = BitConverter.ToUInt32(headers, secOff + 16);
                        uint rawOff = BitConverter.ToUInt32(headers, secOff + 20);
                        uint chars = BitConverter.ToUInt32(headers, secOff + 36);

                        // Calculate entropy for this section
                        float entropy = 0;
                        if (rawSize > 0 && rawSize <= 0x100000)
                        {
                            byte[] secData = new byte[(int)Math.Min(rawSize, 0x10000)];
                            IntPtr secBuf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)secData.Length,
                                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                            if (secBuf != IntPtr.Zero)
                            {
                                if (driver.CopyVirtualMemory(processId, (IntPtr)(baseAddr + virtAddr), secBuf, secData.Length))
                                {
                                    Marshal.Copy(secBuf, secData, 0, secData.Length);
                                    entropy = (float)EntropyCalculator.CalculateEntropy(secData);
                                    totalEntropy += entropy;
                                    sectionCount++;
                                }
                                WinApi.VirtualFree(secBuf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                            }
                        }

                        // Parse characteristics
                        var flags = new List<string>();
                        if ((chars & 0x00000020) != 0) flags.Add("CODE");
                        if ((chars & 0x00000040) != 0) flags.Add("INIT_DATA");
                        if ((chars & 0x00000080) != 0) flags.Add("UNINIT");
                        if ((chars & 0x20000000) != 0) flags.Add("EXEC");
                        if ((chars & 0x40000000) != 0) flags.Add("READ");
                        if ((chars & 0x80000000u) != 0) flags.Add("WRITE");

                        var lvi = new ListViewItem(name);
                        lvi.SubItems.Add($"0x{virtAddr:X}");
                        lvi.SubItems.Add($"0x{virtSize:X}");
                        lvi.SubItems.Add($"0x{rawSize:X}");
                        lvi.SubItems.Add($"0x{rawOff:X}");
                        lvi.SubItems.Add(string.Join(", ", flags));
                        lvi.SubItems.Add(entropy > 0 ? $"{entropy:F2}" : "-");

                        // Color by entropy
                        if (entropy > 6.5) lvi.ForeColor = DarkTheme.Error;
                        else if (entropy > 5.0) lvi.ForeColor = DarkTheme.Warning;
                        else if (entropy > 3.0) lvi.ForeColor = Color.FromArgb(88, 166, 255);
                        else if (entropy > 0) lvi.ForeColor = DarkTheme.Success;
                        else lvi.ForeColor = DarkTheme.TextMuted;

                        lvi.Tag = (baseAddr + virtAddr, virtSize, rawSize);
                        sectionList.Items.Add(lvi);
                    }

                    if (sectionCount > 0)
                    {
                        double avgEntropy = totalEntropy / sectionCount;
                        detailsBox.SelectionColor = EntropyCalculator.EntropyColor(avgEntropy);
                        detailsBox.AppendText($"  Avg Entropy: {avgEntropy:F2} ({EntropyCalculator.EntropyLabel(avgEntropy)})\n");
                    }

                    statsLbl.Text = $"Sections: {numSections} | {mod.ModuleName}";
                }
            }
            catch (Exception ex) { detailsBox.Text = $"Error: {ex.Message}"; }
        }

        private void SectionList_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (sectionList.SelectedItems.Count == 0) return;
            var item = sectionList.SelectedItems[0];

            detailsBox.Clear();
            detailsBox.SelectionColor = DarkTheme.Accent;
            detailsBox.AppendText($"Section: {item.Text}\n");
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText(new string('═', 50) + "\n\n");

            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            detailsBox.AppendText($"  Virtual Address:  {item.SubItems[1].Text}\n");
            detailsBox.AppendText($"  Virtual Size:     {item.SubItems[2].Text}\n");
            detailsBox.AppendText($"  Raw Size:         {item.SubItems[3].Text}\n");
            detailsBox.AppendText($"  Raw Offset:       {item.SubItems[4].Text}\n");
            detailsBox.AppendText($"  Characteristics:  {item.SubItems[5].Text}\n");
            detailsBox.AppendText($"  Entropy:          {item.SubItems[6].Text}\n");

            // Show hex preview
            if (item.Tag is ValueTuple<ulong, uint, uint> secInfo)
            {
                ulong addr = secInfo.Item1;
                uint size = Math.Min(secInfo.Item2, 0x200); // Preview first 512 bytes

                byte[] data = new byte[(int)size];
                IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)(int)size,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (buf == IntPtr.Zero) return;
                if (driver.CopyVirtualMemory(processId, (IntPtr)addr, buf, (int)size))
                {
                    Marshal.Copy(buf, data, 0, (int)size);

                    hexView.Clear();
                    var sb = new StringBuilder();
                    for (int off = 0; off < data.Length; off += 16)
                    {
                        sb.Append($"{addr + (ulong)off:X8}  ");
                        for (int j = 0; j < 16; j++)
                        {
                            if (off + j < data.Length)
                                sb.Append($"{data[off + j]:X2} ");
                            else
                                sb.Append("   ");
                            if (j == 7) sb.Append(" ");
                        }
                        sb.Append(" |");
                        for (int j = 0; j < 16 && off + j < data.Length; j++)
                        {
                            byte b = data[off + j];
                            sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
                        }
                        sb.AppendLine("|");
                    }
                    hexView.Text = sb.ToString();
                }
                WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
        }

        private void ViewHex_Click(object sender, EventArgs e)
        {
            if (sectionList.SelectedItems.Count > 0)
                SectionList_SelectedIndexChanged(sender, e);
        }

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
    }
}
