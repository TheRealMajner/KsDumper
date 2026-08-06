using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class PEViewerWindow : Form
    {
        private TabControl tabControl;
        private ListView sectionList;
        private RichTextBox headerView;
        private RichTextBox hexView;
        private TreeView importTree;
        private ListView exportList;
        private TreeView resourceTree;
        private byte[] fileBytes;
        private string fileName;

        public PEViewerWindow(string filePath = null)
        {
            InitializeComponent();
            if (filePath != null && File.Exists(filePath))
                LoadFile(filePath);
        }

        private void InitializeComponent()
        {
            Text = "PE Viewer";
            Size = new Size(1100, 750);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(900, 600);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            var openBtn = CreateButton("Open File...", 90);
            openBtn.Click += Open_Click;
            var openProcBtn = CreateButton("From Process...", 100);
            toolbar.Controls.AddRange(new Control[] { openBtn, openProcBtn });

            // Tabs
            tabControl = new TabControl { Dock = DockStyle.Fill, Font = DarkTheme.UIFont, Padding = new Point(10, 5), BackColor = DarkTheme.Background };

            // DOS Header tab
            var dosPage = new TabPage("DOS Header") { BackColor = DarkTheme.Background };
            headerView = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both, WordWrap = false };
            dosPage.Controls.Add(headerView);

            // Sections tab
            var secPage = new TabPage("Sections") { BackColor = DarkTheme.Background };
            sectionList = CreateListView();
            sectionList.Columns.Add("Name", 80);
            sectionList.Columns.Add("VirtAddr", 90);
            sectionList.Columns.Add("VirtSize", 90);
            sectionList.Columns.Add("RawSize", 90);
            sectionList.Columns.Add("RawOffset", 90);
            sectionList.Columns.Add("Entropy", 70);
            sectionList.Columns.Add("Characteristics", 200);
            sectionList.DoubleClick += Section_DoubleClick;
            secPage.Controls.Add(sectionList);

            // Imports tab
            var impPage = new TabPage("Imports") { BackColor = DarkTheme.Background };
            importTree = new TreeView { Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIMonoFont, ShowLines = true, HideSelection = false };
            impPage.Controls.Add(importTree);

            // Exports tab
            var expPage = new TabPage("Exports") { BackColor = DarkTheme.Background };
            exportList = CreateListView();
            exportList.Columns.Add("Name", 250);
            exportList.Columns.Add("Ordinal", 70);
            exportList.Columns.Add("RVA", 100);
            exportList.Columns.Add("Forwarded", 200);
            expPage.Controls.Add(exportList);

            // Resources tab
            var resPage = new TabPage("Resources") { BackColor = DarkTheme.Background };
            resourceTree = new TreeView { Dock = DockStyle.Fill, BorderStyle = BorderStyle.None, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont, ShowLines = true };
            resPage.Controls.Add(resourceTree);

            // Hex Viewer tab
            var hexPage = new TabPage("Hex Viewer") { BackColor = DarkTheme.Background };
            hexView = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both, WordWrap = false };
            hexPage.Controls.Add(hexView);

            // Entropy tab
            var entPage = new TabPage("Entropy") { BackColor = DarkTheme.Background };
            var entView = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            entPage.Controls.Add(entView);

            tabControl.TabPages.AddRange(new[] { dosPage, secPage, impPage, expPage, resPage, hexPage, entPage });
            tabControl.Selected += Tab_Selected;

            Controls.Add(tabControl);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void Open_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog())
            {
                ofd.Filter = "PE Files|*.exe;*.dll;*.sys;*.ocx|All Files|*.*";
                if (ofd.ShowDialog() == DialogResult.OK) LoadFile(ofd.FileName);
            }
        }

        private void LoadFile(string path)
        {
            try
            {
                fileBytes = File.ReadAllBytes(path);
                fileName = Path.GetFileName(path);
                Text = $"PE Viewer - {fileName}";
                ParsePE();
            }
            catch (Exception ex) { MessageBox.Show($"Error: {ex.Message}", "PE Viewer", MessageBoxButtons.OK, MessageBoxIcon.Error); }
        }

        private void ParsePE()
        {
            if (fileBytes == null || fileBytes.Length < 64) return;

            // DOS Header
            var sb = new StringBuilder();
            sb.AppendLine("IMAGE_DOS_HEADER");
            sb.AppendLine(new string('=', 50));
            sb.AppendLine($"  e_magic    = 0x{BitConverter.ToUInt16(fileBytes, 0):X4}  (MZ)");
            sb.AppendLine($"  e_lfanew   = 0x{BitConverter.ToInt32(fileBytes, 60):X8}");
            headerView.Text = sb.ToString();

            int e_lfanew = BitConverter.ToInt32(fileBytes, 60);
            if (e_lfanew + 24 > fileBytes.Length) return;

            uint peSig = BitConverter.ToUInt32(fileBytes, e_lfanew);
            if (peSig != 0x00004550) return;

            ushort machine = BitConverter.ToUInt16(fileBytes, e_lfanew + 4);
            ushort numSections = BitConverter.ToUInt16(fileBytes, e_lfanew + 6);
            uint timeDateStamp = BitConverter.ToUInt32(fileBytes, e_lfanew + 8);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(fileBytes, e_lfanew + 20);
            ushort characteristics = BitConverter.ToUInt16(fileBytes, e_lfanew + 22);
            int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

            bool is64 = false;
            if (sizeOfOptHdr > 0)
            {
                ushort magic = BitConverter.ToUInt16(fileBytes, e_lfanew + 24);
                is64 = magic == 0x20b;
            }

            // Sections
            sectionList.Items.Clear();
            for (int s = 0; s < numSections; s++)
            {
                int secOff = sectionTableOff + s * 40;
                if (secOff + 40 > fileBytes.Length) break;

                string secName = Encoding.ASCII.GetString(fileBytes, secOff, 8).TrimEnd('\0');
                uint vSize = BitConverter.ToUInt32(fileBytes, secOff + 8);
                uint vAddr = BitConverter.ToUInt32(fileBytes, secOff + 12);
                uint rawSize = BitConverter.ToUInt32(fileBytes, secOff + 16);
                uint rawPtr = BitConverter.ToUInt32(fileBytes, secOff + 20);
                uint chars = BitConverter.ToUInt32(fileBytes, secOff + 36);

                double entropy = 0;
                if (rawSize > 0 && rawPtr + rawSize <= fileBytes.Length)
                {
                    byte[] secData = new byte[rawSize];
                    Array.Copy(fileBytes, rawPtr, secData, 0, (int)rawSize);
                    entropy = EntropyCalculator.CalculateEntropy(secData);
                }

                var flags = new List<string>();
                if ((chars & 0x20) != 0) flags.Add("CODE");
                if ((chars & 0x40) != 0) flags.Add("INIT_DATA");
                if ((chars & 0x80) != 0) flags.Add("UNINIT_DATA");
                if ((chars & 0x20000000) != 0) flags.Add("EXEC");
                if ((chars & 0x40000000) != 0) flags.Add("READ");
                if ((chars & 0x80000000u) != 0) flags.Add("WRITE");

                var lvi = new ListViewItem(secName);
                lvi.SubItems.Add($"0x{vAddr:X}");
                lvi.SubItems.Add($"0x{vSize:X}");
                lvi.SubItems.Add($"0x{rawSize:X}");
                lvi.SubItems.Add($"0x{rawPtr:X}");
                lvi.SubItems.Add($"{entropy:F2}");
                lvi.SubItems.Add(string.Join(", ", flags));
                lvi.ForeColor = EntropyCalculator.EntropyColor(entropy);
                lvi.Tag = (rawPtr, rawSize);
                sectionList.Items.Add(lvi);
            }

            // Imports
            ParseImports(e_lfanew, sizeOfOptHdr, is64);

            // Exports
            ParseExports(e_lfanew, sizeOfOptHdr, is64);
        }

        private void ParseImports(int e_lfanew, ushort sizeOfOptHdr, bool is64)
        {
            importTree.Nodes.Clear();
            int dataDirBase = is64 ? 112 : 96;
            if (e_lfanew + 24 + dataDirBase + 12 > fileBytes.Length) return;

            uint importDirRVA = BitConverter.ToUInt32(fileBytes, e_lfanew + 24 + dataDirBase + 8);
            if (importDirRVA == 0) return;

            uint importFileOff = RvaToFileOffset(importDirRVA);
            if (importFileOff == 0 || importFileOff + 20 > fileBytes.Length) return;

            int pos = (int)importFileOff;
            while (pos + 20 <= fileBytes.Length)
            {
                uint nameRVA = BitConverter.ToUInt32(fileBytes, pos + 12);
                uint firstThunk = BitConverter.ToUInt32(fileBytes, pos + 16);
                uint origFirstThunk = BitConverter.ToUInt32(fileBytes, pos);

                if (nameRVA == 0 && firstThunk == 0) break;

                string dllName = ReadStringAtRVA(nameRVA) ?? "unknown";
                var dllNode = importTree.Nodes.Add(dllName);
                dllNode.ForeColor = DarkTheme.Accent;

                uint thunkRVA = origFirstThunk != 0 ? origFirstThunk : firstThunk;
                int thunkSize = is64 ? 8 : 4;

                for (int t = 0; t < 4096; t++)
                {
                    uint thunkOff = RvaToFileOffset(thunkRVA + (uint)(t * thunkSize));
                    if (thunkOff == 0 || thunkOff + thunkSize > fileBytes.Length) break;

                    ulong thunkVal = is64 ? BitConverter.ToUInt64(fileBytes, (int)thunkOff) : BitConverter.ToUInt32(fileBytes, (int)thunkOff);
                    if (thunkVal == 0) break;

                    bool isOrdinal = is64 ? (thunkVal & 0x8000000000000000) != 0 : (thunkVal & 0x80000000) != 0;
                    string funcName;
                    if (isOrdinal)
                        funcName = $"Ordinal #{thunkVal & 0xFFFF}";
                    else
                    {
                        uint hintRVA = (uint)(thunkVal & 0x7FFFFFFF);
                        funcName = ReadHintName(hintRVA) ?? "unknown";
                    }
                    var funcNode = dllNode.Nodes.Add(funcName);
                    funcNode.ForeColor = DarkTheme.TextPrimary;
                }

                pos += 20;
            }
        }

        private void ParseExports(int e_lfanew, ushort sizeOfOptHdr, bool is64)
        {
            exportList.Items.Clear();
            int dataDirBase = is64 ? 112 : 96;
            if (e_lfanew + 24 + dataDirBase + 4 > fileBytes.Length) return;

            uint exportDirRVA = BitConverter.ToUInt32(fileBytes, e_lfanew + 24 + dataDirBase);
            if (exportDirRVA == 0) return;

            uint exportFileOff = RvaToFileOffset(exportDirRVA);
            if (exportFileOff == 0 || exportFileOff + 40 > fileBytes.Length) return;

            int numFuncs = BitConverter.ToInt32(fileBytes, (int)exportFileOff + 20);
            int numNames = BitConverter.ToInt32(fileBytes, (int)exportFileOff + 24);
            uint funcTableRVA = BitConverter.ToUInt32(fileBytes, (int)exportFileOff + 28);
            uint nameTableRVA = BitConverter.ToUInt32(fileBytes, (int)exportFileOff + 32);
            uint ordinalTableRVA = BitConverter.ToUInt32(fileBytes, (int)exportFileOff + 36);

            for (int i = 0; i < numNames && i < 10000; i++)
            {
                uint nameOff = RvaToFileOffset(BitConverter.ToUInt32(fileBytes, (int)(RvaToFileOffset(nameTableRVA) + i * 4)));
                string name = nameOff > 0 ? ReadStringAtFileOffset(nameOff) : "?";

                ushort ordinal = BitConverter.ToUInt16(fileBytes, (int)(RvaToFileOffset(ordinalTableRVA) + i * 2));
                uint funcRVA = BitConverter.ToUInt32(fileBytes, (int)(RvaToFileOffset(funcTableRVA) + ordinal * 4));

                var lvi = new ListViewItem(name ?? "?");
                lvi.SubItems.Add(ordinal.ToString());
                lvi.SubItems.Add($"0x{funcRVA:X}");
                lvi.SubItems.Add(""); // Forwarded
                exportList.Items.Add(lvi);
            }
        }

        private void Section_DoubleClick(object sender, EventArgs e)
        {
            if (sectionList.SelectedItems.Count == 0) return;
            var (rawPtr, rawSize) = ((uint, uint))sectionList.SelectedItems[0].Tag;
            ShowHexView(rawPtr, (int)Math.Min(rawSize, 0x10000));
            tabControl.SelectedTab = tabControl.TabPages["Hex Viewer"] ?? tabControl.TabPages[5];
        }

        private void Tab_Selected(object sender, TabControlEventArgs e)
        {
            if (e.TabPageIndex == 6 && fileBytes != null) // Entropy tab
            {
                var entView = (RichTextBox)e.TabPage.Controls[0];
                if (entView.TextLength == 0) GenerateEntropyReport(entView);
            }
        }

        private void ShowHexView(uint offset, int size)
        {
            hexView.Clear();
            var sb = new StringBuilder();
            int end = Math.Min((int)offset + size, fileBytes.Length);

            for (int i = (int)offset; i < end; i += 16)
            {
                sb.Append($"{i:X8}  ");
                for (int j = 0; j < 16; j++)
                {
                    if (i + j < end) sb.Append($"{fileBytes[i + j]:X2} ");
                    else sb.Append("   ");
                    if (j == 7) sb.Append(" ");
                }
                sb.Append(" |");
                for (int j = 0; j < 16 && i + j < end; j++)
                {
                    byte b = fileBytes[i + j];
                    sb.Append(b >= 0x20 && b < 0x7F ? (char)b : '.');
                }
                sb.AppendLine("|");
            }
            hexView.Text = sb.ToString();
        }

        private void GenerateEntropyReport(RichTextBox view)
        {
            view.Clear();

            // Overall entropy
            double overallEntropy = EntropyCalculator.CalculateEntropy(fileBytes);

            view.SelectionColor = DarkTheme.Accent;
            view.AppendText("Section Entropy Analysis\n");
            view.SelectionColor = DarkTheme.TextSecondary;
            view.AppendText(new string('═', 70) + "\n\n");

            view.SelectionColor = DarkTheme.TextPrimary;
            view.AppendText($"  Overall file entropy: {overallEntropy:F4} bits/byte (max 8.0)\n");
            view.SelectionColor = EntropyCalculator.EntropyColor(overallEntropy);
            view.AppendText($"  Interpretation: {EntropyCalculator.EntropyLabel(overallEntropy)}\n\n");

            // Visual bar graph header
            view.SelectionColor = DarkTheme.TextSecondary;
            view.AppendText("  Section          Entropy  │");
            view.AppendText("████████████████████████████████████████│\n");
            view.AppendText("                           │");
            view.AppendText("0       2       4       6       8      │\n");
            view.AppendText("  " + new string('─', 27) + "┼" + new string('─', 41) + "\n");

            // Per-section entropy bars
            foreach (ListViewItem item in sectionList.Items)
            {
                if (item.SubItems.Count <= 5) continue;
                string sectionName = item.Text;
                string entropyStr = item.SubItems[5].Text;
                if (!double.TryParse(entropyStr, out double entropy)) continue;

                // Section name (padded to 16 chars)
                string paddedName = sectionName.PadRight(16).Substring(0, 16);
                view.SelectionColor = DarkTheme.TextPrimary;
                view.AppendText($"  {paddedName} {entropy:F4}  │");

                // Bar: 40 chars wide, representing 0-8 bits/byte
                int barLength = (int)(entropy / 8.0 * 40);
                barLength = Math.Max(0, Math.Min(40, barLength));

                // Color the bar based on entropy level
                string bar = "";
                for (int i = 0; i < 40; i++)
                {
                    if (i < barLength)
                    {
                        // Filled portion
                        double pos = (double)i / 40.0 * 8.0;
                        if (pos < 3.0) view.SelectionColor = Color.FromArgb(63, 185, 80); // Green
                        else if (pos < 5.0) view.SelectionColor = Color.FromArgb(88, 166, 255); // Blue
                        else if (pos < 6.5) view.SelectionColor = Color.FromArgb(210, 153, 34); // Yellow
                        else view.SelectionColor = Color.FromArgb(248, 81, 73); // Red
                        view.AppendText("█");
                    }
                    else
                    {
                        view.SelectionColor = DarkTheme.TextMuted;
                        view.AppendText("░");
                    }
                }
                view.SelectionColor = DarkTheme.TextSecondary;
                view.AppendText("│\n");
            }

            view.AppendText("  " + new string('─', 27) + "┴" + new string('─', 41) + "\n\n");

            // Analysis summary
            view.SelectionColor = DarkTheme.TextSecondary;
            view.AppendText("  Analysis:\n");

            var packedSections = new List<string>();
            var codeSections = new List<string>();
            foreach (ListViewItem item in sectionList.Items)
            {
                if (item.SubItems.Count <= 5) continue;
                if (double.TryParse(item.SubItems[5].Text, out double ent))
                {
                    if (ent > 6.5) packedSections.Add($"{item.Text} ({ent:F2})");
                    if (ent > 3.0 && ent < 5.5) codeSections.Add(item.Text);
                }
            }

            view.SelectionColor = DarkTheme.TextPrimary;
            if (packedSections.Count > 0)
            {
                view.SelectionColor = DarkTheme.Warning;
                view.AppendText($"  ⚠ High entropy sections (possible encryption/packing):\n");
                view.SelectionColor = Color.FromArgb(248, 81, 73);
                foreach (var s in packedSections)
                    view.AppendText($"    • {s}\n");
            }

            if (codeSections.Count > 0)
            {
                view.SelectionColor = DarkTheme.Success;
                view.AppendText($"  ✓ Normal code sections: {string.Join(", ", codeSections)}\n");
            }

            if (overallEntropy > 7.0)
            {
                view.SelectionColor = DarkTheme.Error;
                view.AppendText($"\n  ⚠ CRITICAL: Overall entropy {overallEntropy:F2} indicates the entire file is likely encrypted or compressed.\n");
            }
            else if (overallEntropy > 6.5)
            {
                view.SelectionColor = DarkTheme.Warning;
                view.AppendText($"\n  ⚠ WARNING: Overall entropy {overallEntropy:F2} suggests the file may be packed.\n");
            }
            else if (overallEntropy < 1.0)
            {
                view.SelectionColor = DarkTheme.TextMuted;
                view.AppendText($"\n  ℹ Very low entropy ({overallEntropy:F2}): file contains mostly empty/zero data.\n");
            }
        }

        // ==================== PE Helpers ====================

        private uint RvaToFileOffset(uint rva)
        {
            if (fileBytes == null || fileBytes.Length < 64) return 0;
            int e_lfanew = BitConverter.ToInt32(fileBytes, 60);
            ushort numSections = BitConverter.ToUInt16(fileBytes, e_lfanew + 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(fileBytes, e_lfanew + 20);
            int sectionTableOff = e_lfanew + 24 + sizeOfOptHdr;

            for (int s = 0; s < numSections; s++)
            {
                int secOff = sectionTableOff + s * 40;
                if (secOff + 40 > fileBytes.Length) break;
                uint vAddr = BitConverter.ToUInt32(fileBytes, secOff + 12);
                uint vSize = BitConverter.ToUInt32(fileBytes, secOff + 8);
                uint rawPtr = BitConverter.ToUInt32(fileBytes, secOff + 20);
                uint rawSize = BitConverter.ToUInt32(fileBytes, secOff + 16);

                if (rva >= vAddr && rva < vAddr + vSize)
                    return rawPtr + (rva - vAddr);
            }
            return 0;
        }

        private string ReadStringAtRVA(uint rva)
        {
            uint off = RvaToFileOffset(rva);
            return off > 0 ? ReadStringAtFileOffset(off) : null;
        }

        private string ReadStringAtFileOffset(uint off)
        {
            if (off >= fileBytes.Length) return null;
            int end = (int)off;
            while (end < fileBytes.Length && end < off + 256 && fileBytes[end] != 0) end++;
            return end > off ? Encoding.ASCII.GetString(fileBytes, (int)off, end - (int)off) : null;
        }

        private string ReadHintName(uint rva)
        {
            uint off = RvaToFileOffset(rva);
            if (off == 0 || off + 2 >= fileBytes.Length) return null;
            return ReadStringAtFileOffset(off + 2); // Skip 2-byte hint
        }

        // ==================== UI Helpers ====================

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private ListView CreateListView()
        {
            var lv = new ListView { View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None, Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont };
            lv.Resize += (s, e) => { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; };
            lv.HandleCreated += (s, e) => { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; };
            return lv;
        }
    }
}
