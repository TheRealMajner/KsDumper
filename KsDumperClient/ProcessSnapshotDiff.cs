using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Process Snapshot Diff - takes two memory snapshots and compares them
    /// to find changed values, useful for finding game values, health, etc.
    /// </summary>
    public class ProcessSnapshotDiff : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView diffList;
        private Button snapshot1Btn;
        private Button snapshot2Btn;
        private Button compareBtn;
        private Button clearBtn;
        private ComboBox valueTypeCombo;
        private NumericUpDown regionSizeBox;
        private Label statsLbl;
        private RichTextBox logBox;

        private Dictionary<ulong, byte[]> snapshot1;
        private Dictionary<ulong, byte[]> snapshot2;

        private struct DiffEntry
        {
            public ulong Address;
            public byte[] OldValue;
            public byte[] NewValue;
            public string OldFormatted;
            public string NewFormatted;
            public string Region;
        }

        public ProcessSnapshotDiff(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            snapshot1 = new Dictionary<ulong, byte[]>();
            snapshot2 = new Dictionary<ulong, byte[]>();
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"Snapshot Diff - {processName} (PID: {processId})";
            Size = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(8) };

            var row1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row1.Controls.Add(MakeLabel("Value Type:"));
            valueTypeCombo = new DarkComboBox { Width = 100 };
            valueTypeCombo.Items.AddRange(new object[] { "Byte", "Int16", "Int32", "Int64", "Float", "Double" });
            valueTypeCombo.SelectedIndex = 2;
            row1.Controls.Add(valueTypeCombo);
            row1.Controls.Add(MakeLabel("Region Size (KB):"));
            regionSizeBox = new DarkNumericUpDown { Width = 80, Minimum = 4, Maximum = 65536, Value = 4096 };
            row1.Controls.Add(regionSizeBox);

            var row2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            snapshot1Btn = CreateButton("Take Snapshot 1", 120);
            snapshot1Btn.Click += Snapshot1_Click;
            snapshot2Btn = CreateButton("Take Snapshot 2", 120);
            snapshot2Btn.Enabled = false;
            snapshot2Btn.Click += Snapshot2_Click;
            compareBtn = CreateButton("Compare", 80);
            compareBtn.Enabled = false;
            compareBtn.Click += Compare_Click;
            clearBtn = CreateButton("Clear", 60);
            clearBtn.Click += (s, e) => { diffList.Items.Clear(); snapshot1.Clear(); snapshot2.Clear(); snapshot1Btn.Enabled = true; snapshot2Btn.Enabled = false; compareBtn.Enabled = false; statsLbl.Text = "Ready"; logBox.Clear(); };
            statsLbl = new Label { Text = "Take Snapshot 1 to begin", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            row2.Controls.AddRange(new Control[] { snapshot1Btn, snapshot2Btn, compareBtn, clearBtn, statsLbl });

            toolbar.Controls.Add(row2);
            toolbar.Controls.Add(row1);

            diffList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            diffList.Columns.Add("Address", 130);
            diffList.Columns.Add("Old Value", 150);
            diffList.Columns.Add("New Value", 150);
            diffList.Columns.Add("Delta", 100);
            diffList.Columns.Add("Old Hex", 150);
            diffList.Columns.Add("New Hex", 150);
            diffList.Resize += (s, e) => { if (diffList.Columns.Count > 0) diffList.Columns[diffList.Columns.Count - 1].Width = -2; };

            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 100, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(diffList);
            Controls.Add(logPanel);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private async void Snapshot1_Click(object sender, EventArgs e)
        {
            snapshot1Btn.Enabled = false;
            statsLbl.Text = "Taking snapshot 1...";
            logBox.Clear();

            await Task.Run(() =>
            {
                try
                {
                    snapshot1 = TakeSnapshot();
                    this.SafeInvoke(() =>
                    {
                        statsLbl.Text = $"Snapshot 1: {snapshot1.Count:N0} regions ({snapshot1.Count * (int)regionSizeBox.Value:N0} KB)";
                        logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Snapshot 1 taken: {snapshot1.Count:N0} regions\n");
                        snapshot1Btn.Enabled = false;
                        snapshot2Btn.Enabled = true;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Snapshot 1 error: {ex.Message}\n");
                        snapshot1Btn.Enabled = true;
                    });
                }
            });
        }

        private async void Snapshot2_Click(object sender, EventArgs e)
        {
            snapshot2Btn.Enabled = false;
            statsLbl.Text = "Taking snapshot 2...";

            await Task.Run(() =>
            {
                try
                {
                    snapshot2 = TakeSnapshot();
                    this.SafeInvoke(() =>
                    {
                        statsLbl.Text = $"Snapshot 2: {snapshot2.Count:N0} regions | Ready to compare";
                        logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Snapshot 2 taken: {snapshot2.Count:N0} regions\n");
                        snapshot2Btn.Enabled = false;
                        compareBtn.Enabled = true;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Snapshot 2 error: {ex.Message}\n");
                        snapshot2Btn.Enabled = true;
                    });
                }
            });
        }

        private async void Compare_Click(object sender, EventArgs e)
        {
            compareBtn.Enabled = false;
            diffList.Items.Clear();
            statsLbl.Text = "Comparing...";

            await Task.Run(() =>
            {
                try
                {
                    var diffs = new List<DiffEntry>();
                    int valueType = valueTypeCombo.SelectedIndex;
                    int valueSize = new[] { 1, 2, 4, 8, 4, 8 }[valueType];

                    foreach (var kvp in snapshot1)
                    {
                        if (!snapshot2.ContainsKey(kvp.Key)) continue;

                        byte[] oldData = kvp.Value;
                        byte[] newData = snapshot2[kvp.Key];
                        int len = Math.Min(oldData.Length, newData.Length);

                        for (int off = 0; off <= len - valueSize; off += valueSize)
                        {
                            bool changed = false;
                            for (int b = 0; b < valueSize; b++)
                            {
                                if (oldData[off + b] != newData[off + b]) { changed = true; break; }
                            }

                            if (changed)
                            {
                                byte[] oldVal = new byte[valueSize];
                                byte[] newVal = new byte[valueSize];
                                Array.Copy(oldData, off, oldVal, 0, valueSize);
                                Array.Copy(newData, off, newVal, 0, valueSize);

                                diffs.Add(new DiffEntry
                                {
                                    Address = kvp.Key + (ulong)off,
                                    OldValue = oldVal,
                                    NewValue = newVal,
                                    OldFormatted = FormatValue(oldVal, valueType),
                                    NewFormatted = FormatValue(newVal, valueType),
                                    Region = $"0x{kvp.Key:X}"
                                });

                                if (diffs.Count >= 50000) break;
                            }
                        }
                        if (diffs.Count >= 50000) break;
                    }

                    this.SafeInvoke(() =>
                    {
                    foreach (var diff in diffs)
                    {
                        var lvi = new ListViewItem($"0x{diff.Address:X}");
                        lvi.SubItems.Add(diff.OldFormatted);
                        lvi.SubItems.Add(diff.NewFormatted);

                        // Calculate delta for numeric types
                        string delta = "";
                        if (valueType == 2) // Int32
                        {
                            int oldV = BitConverter.ToInt32(diff.OldValue, 0);
                            int newV = BitConverter.ToInt32(diff.NewValue, 0);
                            int d = newV - oldV;
                            delta = d >= 0 ? $"+{d}" : d.ToString();
                            lvi.ForeColor = d > 0 ? DarkTheme.Success : DarkTheme.Error;
                        }
                        else if (valueType == 3) // Int64
                        {
                            long oldV = BitConverter.ToInt64(diff.OldValue, 0);
                            long newV = BitConverter.ToInt64(diff.NewValue, 0);
                            long d = newV - oldV;
                            delta = d >= 0 ? $"+{d}" : d.ToString();
                            lvi.ForeColor = d > 0 ? DarkTheme.Success : DarkTheme.Error;
                        }
                        else if (valueType == 4) // Float
                        {
                            float oldV = BitConverter.ToSingle(diff.OldValue, 0);
                            float newV = BitConverter.ToSingle(diff.NewValue, 0);
                            float d = newV - oldV;
                            delta = d >= 0 ? $"+{d:G7}" : d.ToString("G7");
                            lvi.ForeColor = d > 0 ? DarkTheme.Success : DarkTheme.Error;
                        }
                        else
                        {
                            lvi.ForeColor = DarkTheme.Warning;
                        }

                        lvi.SubItems.Add(delta);
                        lvi.SubItems.Add(BitConverter.ToString(diff.OldValue).Replace("-", " "));
                        lvi.SubItems.Add(BitConverter.ToString(diff.NewValue).Replace("-", " "));
                        diffList.Items.Add(lvi);
                    }

                    statsLbl.Text = $"Differences: {diffs.Count:N0}";
                    statsLbl.ForeColor = diffs.Count > 0 ? DarkTheme.Accent : DarkTheme.Success;
                    logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Comparison complete: {diffs.Count:N0} differences found\n");
                    snapshot1Btn.Enabled = true;
                    snapshot2Btn.Enabled = false;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] Compare error: {ex.Message}\n");
                        statsLbl.Text = "Compare failed";
                        compareBtn.Enabled = true;
                    });
                }
            });
        }

        private Dictionary<ulong, byte[]> TakeSnapshot()
        {
            var result = new Dictionary<ulong, byte[]>();
            int regionSize = (int)regionSizeBox.Value * 1024;
            var regions = driver.EnumRegions(processId);

            foreach (var (baseAddr, regSize, protect, state, type) in regions)
            {
                if (state != 0x1000) continue; // MEM_COMMIT
                if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0) continue;

                int size = Math.Min((int)regionSize, (int)regSize);
                byte[] data = new byte[size];
                IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (buf == IntPtr.Zero) continue;
                try
                {
                    if (driver.CopyVirtualMemory(processId, (IntPtr)baseAddr, buf, size))
                    {
                        Marshal.Copy(buf, data, 0, size);
                        result[baseAddr] = data;
                    }
                }
                finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
            }
            return result;
        }

        private string FormatValue(byte[] data, int valueType)
        {
            try
            {
                switch (valueType)
                {
                    case 0: return data[0].ToString();
                    case 1: return BitConverter.ToInt16(data, 0).ToString();
                    case 2: return BitConverter.ToInt32(data, 0).ToString();
                    case 3: return BitConverter.ToInt64(data, 0).ToString();
                    case 4: return BitConverter.ToSingle(data, 0).ToString("G7");
                    case 5: return BitConverter.ToDouble(data, 0).ToString("G15");
                    default: return BitConverter.ToString(data).Replace("-", " ");
                }
            }
            catch { return "?"; }
        }

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
    }
}
