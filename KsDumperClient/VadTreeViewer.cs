using System;
using System.Drawing;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class VadTreeViewer : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView vadList;
        private Button refreshBtn;
        private Button exportBtn;
        private Label statsLbl;

        public VadTreeViewer(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"VAD Tree - {processName} (PID: {processId})";
            Size = new Size(1000, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 6, 8, 4) };

            refreshBtn = CreateButton("Refresh VAD Tree", 140);
            refreshBtn.Click += Refresh_Click;
            toolbar.Controls.Add(refreshBtn);

            exportBtn = CreateButton("Export CSV", 100);
            exportBtn.Click += Export_Click;
            exportBtn.Enabled = false;
            toolbar.Controls.Add(exportBtn);

            statsLbl = new Label { Text = "Click Refresh to enumerate VAD tree", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.Add(statsLbl);

            vadList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont
            };
            vadList.Columns.Add("Start Address", 140);
            vadList.Columns.Add("End Address", 140);
            vadList.Columns.Add("Size", 80);
            vadList.Columns.Add("Protection", 100);
            vadList.Columns.Add("Flags", 80);
            vadList.Columns.Add("Commit Charge", 100);
            vadList.Columns.Add("Type", 80);

            Controls.Add(vadList);
            Controls.Add(toolbar);

            DarkTheme.ApplyTo(this);
        }

        private async void Refresh_Click(object sender, EventArgs e)
        {
            refreshBtn.Enabled = false;
            exportBtn.Enabled = false;
            vadList.Items.Clear();
            statsLbl.Text = "Enumerating VAD tree...";

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var (vadCount, vads) = driver.EnumVadTree(processId);

                    this.SafeInvoke(() =>
                    {
                        if (vadCount > 0)
                        {
                            ulong totalSize = 0;
                            int committedCount = 0;

                            foreach (var vad in vads)
                            {
                                ulong size = vad.EndAddress - vad.StartAddress;
                                totalSize += size;

                                var lvi = new ListViewItem($"0x{vad.StartAddress:X}");
                                lvi.SubItems.Add($"0x{vad.EndAddress:X}");
                                lvi.SubItems.Add(FormatSize(size));
                                lvi.SubItems.Add(FormatProtection(vad.Protection));
                                lvi.SubItems.Add($"0x{vad.Flags:X}");
                                lvi.SubItems.Add(vad.CommitCharge.ToString());
                                lvi.SubItems.Add(FormatVadType(vad.Flags));

                                // Color-code by protection
                                if ((vad.Protection & 0x40) != 0) // RWX
                                    lvi.ForeColor = DarkTheme.Error;
                                else if ((vad.Protection & 0x20) != 0) // RX
                                    lvi.ForeColor = DarkTheme.Warning;
                                else if ((vad.Protection & 0x04) != 0) // RW
                                    lvi.ForeColor = DarkTheme.Success;
                                else
                                    lvi.ForeColor = DarkTheme.TextMuted;

                                if (vad.CommitCharge > 0) committedCount++;
                                vadList.Items.Add(lvi);
                            }

                            statsLbl.Text = $"VAD entries: {vadCount} | Total: {FormatSize(totalSize)} | Committed: {committedCount}";
                            exportBtn.Enabled = true;
                        }
                        else
                        {
                            statsLbl.Text = "No VAD entries found (requires kernel driver)";
                        }
                        refreshBtn.Enabled = true;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        statsLbl.Text = $"Error: {ex.Message}";
                        refreshBtn.Enabled = true;
                    });
                }
            });
        }

        private void Export_Click(object sender, EventArgs e)
        {
            using (var sfd = new SaveFileDialog())
            {
                sfd.Filter = "CSV Files|*.csv|All Files|*.*";
                sfd.FileName = $"{processName}_vad_tree.csv";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        using (var w = new System.IO.StreamWriter(sfd.FileName))
                        {
                            w.WriteLine("StartAddress,EndAddress,Size,Protection,Flags,CommitCharge,Type");
                            foreach (ListViewItem lvi in vadList.Items)
                            {
                                w.WriteLine($"{lvi.SubItems[0].Text},{lvi.SubItems[1].Text},{lvi.SubItems[2].Text},{lvi.SubItems[3].Text},{lvi.SubItems[4].Text},{lvi.SubItems[5].Text},{lvi.SubItems[6].Text}");
                            }
                        }
                        MessageBox.Show("Exported successfully", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        private string FormatSize(ulong bytes)
        {
            if (bytes >= 1024 * 1024 * 1024) return $"{bytes / (1024.0 * 1024 * 1024):F1} GB";
            if (bytes >= 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
            if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes} B";
        }

        private string FormatProtection(uint p)
        {
            var parts = new System.Collections.Generic.List<string>();
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
            return parts.Count > 0 ? string.Join("|", parts) : "NONE";
        }

        private string FormatVadType(uint flags)
        {
            if ((flags & 0x1000000) != 0) return "IMAGE";
            if ((flags & 0x40000) != 0) return "MAPPED";
            if ((flags & 0x20000) != 0) return "PRIVATE";
            return "UNKNOWN";
        }

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }
    }
}
