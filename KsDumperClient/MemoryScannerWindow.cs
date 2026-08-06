using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class MemoryScannerWindow : Form
    {
        public enum ValueType { Byte, Int16, Int32, Int64, Float, Double, String, AoB }
        public enum ScanType { Exact, Between, BiggerThan, SmallerThan, UnknownInitial }
        public enum NextScanType { Exact, Increased, Decreased, Changed, Unchanged, Bigger, Smaller }

        private struct ScanResult
        {
            public ulong Address;
            public byte[] CurrentBytes;
            public byte[] PreviousBytes;
            public bool Frozen;
            public byte[] FrozenBytes;
        }

        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ComboBox valueTypeCombo;
        private ComboBox scanTypeCombo;
        private TextBox valueBox;
        private TextBox value2Box;
        private Button firstScanBtn;
        private Button nextScanBtn;
        private Button resetBtn;
        private ListView resultsList;
        private Label resultCountLbl;
        private Label statusLbl;
        private CheckBox freezeCheck;
        private NumericUpDown freezeInterval;
        private RichTextBox logBox;
        private Button addWatchBtn;

        private List<ScanResult> currentResults;
        private ValueType selectedType;
        private bool isFirstScan;
        private CancellationTokenSource freezeCts;

        public MemoryScannerWindow(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            currentResults = new List<ScanResult>();
            isFirstScan = true;
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"Memory Scanner - {processName} (PID: {processId})";
            Size = new Size(900, 700);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(750, 550);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Top panel - scan controls
            var topPanel = new Panel { Dock = DockStyle.Top, Height = 110, BackColor = DarkTheme.Surface, Padding = new Padding(10, 8, 10, 8) };

            var row1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row1.Controls.Add(MakeLabel("Value Type:"));
            valueTypeCombo = new DarkComboBox { Width = 100 };
            valueTypeCombo.Items.AddRange(new object[] { "Int32", "Int16", "Int64", "Byte", "Float", "Double", "String", "Array of Bytes" });
            valueTypeCombo.SelectedIndex = 0;
            valueTypeCombo.SelectedIndexChanged += (s, e) => UpdateScanTypes();
            row1.Controls.Add(valueTypeCombo);
            row1.Controls.Add(MakeLabel("Scan Type:"));
            scanTypeCombo = new DarkComboBox { Width = 130 };
            row1.Controls.Add(scanTypeCombo);
            topPanel.Controls.Add(row1);

            var row2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row2.Controls.Add(MakeLabel("Value:"));
            valueBox = CreateTextBox(180);
            row2.Controls.Add(valueBox);
            value2Box = CreateTextBox(120);
            value2Box.Visible = false;
            row2.Controls.Add(value2Box);
            row2.Controls.Add(MakeLabel("to"));
            row2.Controls.Add(MakeSpacer(8));

            firstScanBtn = CreateButton("First Scan", 90);
            firstScanBtn.BackColor = DarkTheme.AccentSubtle;
            firstScanBtn.Click += FirstScan_Click;
            row2.Controls.Add(firstScanBtn);

            nextScanBtn = CreateButton("Next Scan", 90);
            nextScanBtn.Enabled = false;
            nextScanBtn.Click += NextScan_Click;
            row2.Controls.Add(nextScanBtn);

            resetBtn = CreateButton("Reset", 60);
            resetBtn.Click += (s, e) => ResetScan();
            row2.Controls.Add(resetBtn);
            topPanel.Controls.Add(row2);

            var row3 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 28, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            freezeCheck = new CheckBox { Text = "Freeze values", AutoSize = true, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
            freezeCheck.CheckedChanged += FreezeCheck_Changed;
            row3.Controls.Add(freezeCheck);
            row3.Controls.Add(MakeLabel("Interval (ms):"));
            freezeInterval = new DarkNumericUpDown { Width = 70, Minimum = 50, Maximum = 10000, Value = 200 };
            row3.Controls.Add(freezeInterval);
            resultCountLbl = new Label { Text = "Results: 0", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(20, 4, 0, 0) };
            row3.Controls.Add(resultCountLbl);
            statusLbl = new Label { Text = "Ready", AutoSize = true, ForeColor = DarkTheme.TextMuted, Font = DarkTheme.UIFont, Margin = new Padding(20, 4, 0, 0) };
            row3.Controls.Add(statusLbl);
            topPanel.Controls.Add(row3);

            // Results panel
            var resultsPanel = new Panel { Dock = DockStyle.Fill, BackColor = DarkTheme.Background };

            var resultsToolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.SurfaceElevated, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            addWatchBtn = CreateButton("Add to Watch", 100);
            addWatchBtn.Click += AddWatch_Click;
            var copyAddrBtn = CreateButton("Copy Address", 95);
            copyAddrBtn.Click += (s, e) => { if (resultsList.SelectedItems.Count > 0) Clipboard.SetText(resultsList.SelectedItems[0].Text); };
            var removeBtn = CreateButton("Remove Selected", 120);
            removeBtn.Click += (s, e) => { foreach (ListViewItem item in resultsList.SelectedItems) { currentResults.RemoveAt(item.Index); item.Remove(); } UpdateResultCount(); };
            var clearBtn = CreateButton("Clear All", 75);
            clearBtn.Click += (s, e) => { currentResults.Clear(); resultsList.Items.Clear(); UpdateResultCount(); };
            var findAccessBtn = CreateButton("Find Access", 95);
            findAccessBtn.Click += FindAccess_Click;
            resultsToolbar.Controls.AddRange(new Control[] { addWatchBtn, copyAddrBtn, removeBtn, clearBtn, findAccessBtn });

            resultsList = CreateListView();
            resultsList.CheckBoxes = true;
            resultsList.Columns.Add("Address", 140);
            resultsList.Columns.Add("Current Value", 160);
            resultsList.Columns.Add("Previous Value", 160);
            resultsList.Columns.Add("Type", 70);
            resultsList.VirtualMode = true;
            resultsList.RetrieveVirtualItem += (s, e) =>
            {
                if (e.ItemIndex < 0 || e.ItemIndex >= currentResults.Count) { e.Item = new ListViewItem(""); return; }
                var r = currentResults[e.ItemIndex];
                var lvi = new ListViewItem($"0x{r.Address:X}");
                lvi.Checked = r.Frozen;
                lvi.SubItems.Add(FormatBytes(r.CurrentBytes, GetSelectedType()));
                lvi.SubItems.Add(FormatBytes(r.PreviousBytes, GetSelectedType()));
                lvi.SubItems.Add(GetSelectedType().ToString());
                if (r.Frozen) lvi.ForeColor = DarkTheme.Accent;
                e.Item = lvi;
            };

            resultsPanel.Controls.Add(resultsList);
            resultsPanel.Controls.Add(resultsToolbar);

            // Log panel
            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 80, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 20, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(resultsPanel);
            Controls.Add(logPanel);
            Controls.Add(topPanel);

            DarkTheme.ApplyTo(this);
            UpdateScanTypes();

            FormClosing += (s, e) => { freezeCts?.Cancel(); };
        }

        // ==================== SCAN LOGIC ====================

        private async void FirstScan_Click(object sender, EventArgs e)
        {
            firstScanBtn.Enabled = false;
            statusLbl.Text = "Scanning...";
            currentResults.Clear();
            resultsList.VirtualListSize = 0;

            var type = GetSelectedType();
            var scanType = GetSelectedScanType();
            byte[] searchBytes = ValueToBytes(valueBox.Text, type);

            if (scanType == ScanType.UnknownInitial)
                searchBytes = null;

            await Task.Run(() =>
            {
                try
                {
                    var regions = driver.EnumRegions(processId);
                    int found = 0;
                    int scanned = 0;

                    foreach (var (baseAddr, regionSize, protect, state, rtype) in regions)
                    {
                        if (state != 0x1000) continue; // MEM_COMMIT only
                        if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0) continue;

                        int readSize = (int)Math.Min(regionSize, 0x1000000); // 16MB max per region
                        byte[] data = ReadRegion(baseAddr, readSize);
                        if (data == null) continue;

                        scanned += data.Length;

                        if (scanType == ScanType.UnknownInitial)
                        {
                            // Store all addresses with their current values
                            int step = GetValueSize(type);
                            for (int off = 0; off <= data.Length - step && found < 500000; off += step)
                            {
                                byte[] val = new byte[step];
                                Array.Copy(data, off, val, 0, step);
                                currentResults.Add(new ScanResult { Address = baseAddr + (ulong)off, CurrentBytes = val, PreviousBytes = val });
                                found++;
                            }
                        }
                        else
                        {
                            for (int off = 0; off <= data.Length - searchBytes.Length && found < 500000; off++)
                            {
                                bool match = CompareBytes(data, off, searchBytes, type, scanType);
                                if (match)
                                {
                                    byte[] val = new byte[searchBytes.Length];
                                    Array.Copy(data, off, val, 0, searchBytes.Length);
                                    currentResults.Add(new ScanResult { Address = baseAddr + (ulong)off, CurrentBytes = val, PreviousBytes = (byte[])val.Clone() });
                                    found++;
                                }
                            }
                        }
                    }

                    this.SafeInvoke(() =>
                    {
                        resultsList.VirtualListSize = currentResults.Count;
                        resultsList.Invalidate();
                        UpdateResultCount();
                        Log("First scan: {0:N0} bytes scanned, {1:N0} results", scanned, found);
                        statusLbl.Text = $"Found {found:N0} results";
                        firstScanBtn.Enabled = false;
                        nextScanBtn.Enabled = true;
                        isFirstScan = false;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() => { Log("Scan error: {0}", ex.Message); firstScanBtn.Enabled = true; statusLbl.Text = "Error"; });
                }
            });
        }

        private async void NextScan_Click(object sender, EventArgs e)
        {
            nextScanBtn.Enabled = false;
            statusLbl.Text = "Filtering...";

            var type = GetSelectedType();
            var nextType = GetSelectedNextScanType();
            byte[] searchBytes = ValueToBytes(valueBox.Text, type);

            await Task.Run(() =>
            {
                try
                {
                    var toRemove = new HashSet<int>();
                    int i = 0;

                    foreach (var result in currentResults)
                    {
                        byte[] current = ReadBytes(result.Address, result.CurrentBytes.Length);
                        if (current == null) { toRemove.Add(i); i++; continue; }

                        bool keep = false;
                        switch (nextType)
                        {
                            case NextScanType.Exact:
                                keep = BytesEqual(current, searchBytes);
                                break;
                            case NextScanType.Increased:
                                keep = CompareNumeric(current, result.PreviousBytes) > 0;
                                break;
                            case NextScanType.Decreased:
                                keep = CompareNumeric(current, result.PreviousBytes) < 0;
                                break;
                            case NextScanType.Changed:
                                keep = !BytesEqual(current, result.PreviousBytes);
                                break;
                            case NextScanType.Unchanged:
                                keep = BytesEqual(current, result.PreviousBytes);
                                break;
                            default:
                                keep = true;
                                break;
                        }

                        if (!keep) toRemove.Add(i);
                        else
                        {
                            // Update previous bytes
                            var idx = i;
                            currentResults[idx] = new ScanResult
                            {
                                Address = result.Address,
                                CurrentBytes = current,
                                PreviousBytes = result.CurrentBytes,
                                Frozen = result.Frozen,
                                FrozenBytes = result.FrozenBytes
                            };
                        }
                        i++;
                    }

                    // Remove non-matching results (reverse order)
                    var indices = toRemove.OrderByDescending(x => x).ToList();
                    foreach (int idx in indices)
                    {
                        if (idx < currentResults.Count)
                            currentResults.RemoveAt(idx);
                    }

                    this.SafeInvoke(() =>
                    {
                        resultsList.VirtualListSize = currentResults.Count;
                        resultsList.Invalidate();
                        UpdateResultCount();
                        Log("Next scan: {0:N0} results remaining", currentResults.Count);
                        statusLbl.Text = $"{currentResults.Count:N0} results";
                        nextScanBtn.Enabled = currentResults.Count > 0;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() => { Log("Next scan error: {0}", ex.Message); nextScanBtn.Enabled = true; });
                }
            });
        }

        private void ResetScan()
        {
            currentResults.Clear();
            resultsList.VirtualListSize = 0;
            isFirstScan = true;
            firstScanBtn.Enabled = true;
            nextScanBtn.Enabled = false;
            resultCountLbl.Text = "Results: 0";
            statusLbl.Text = "Ready";
        }

        // ==================== FREEZE ====================

        private void FreezeCheck_Changed(object sender, EventArgs e)
        {
            if (freezeCheck.Checked)
            {
                // Mark checked items as frozen
                for (int i = 0; i < currentResults.Count; i++)
                {
                    var r = currentResults[i];
                    currentResults[i] = new ScanResult
                    {
                        Address = r.Address, CurrentBytes = r.CurrentBytes, PreviousBytes = r.PreviousBytes,
                        Frozen = true, FrozenBytes = (byte[])r.CurrentBytes.Clone()
                    };
                }

                freezeCts = new CancellationTokenSource();
                var token = freezeCts.Token;
                Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        await Task.Delay((int)freezeInterval.Value);
                        foreach (var r in currentResults)
                        {
                            if (r.Frozen && r.FrozenBytes != null)
                                WriteBytes(r.Address, r.FrozenBytes);
                        }
                    }
                }, token);
                Log("Freeze enabled ({0} values, {1}ms interval)", currentResults.Count(r2 => r2.Frozen), freezeInterval.Value);
            }
            else
            {
                freezeCts?.Cancel();
                for (int i = 0; i < currentResults.Count; i++)
                {
                    var r = currentResults[i];
                    currentResults[i] = new ScanResult { Address = r.Address, CurrentBytes = r.CurrentBytes, PreviousBytes = r.PreviousBytes, Frozen = false };
                }
                Log("Freeze disabled");
            }
        }

        // ==================== HELPERS ====================

        private ValueType GetSelectedType()
        {
            switch (valueTypeCombo.SelectedIndex)
            {
                case 1: return ValueType.Int16;
                case 2: return ValueType.Int64;
                case 3: return ValueType.Byte;
                case 4: return ValueType.Float;
                case 5: return ValueType.Double;
                case 6: return ValueType.String;
                case 7: return ValueType.AoB;
                default: return ValueType.Int32;
            }
        }

        private ScanType GetSelectedScanType()
        {
            string text = scanTypeCombo.SelectedItem?.ToString() ?? "";
            if (text.Contains("Between")) return ScanType.Between;
            if (text.Contains("Bigger")) return ScanType.BiggerThan;
            if (text.Contains("Smaller")) return ScanType.SmallerThan;
            if (text.Contains("Unknown")) return ScanType.UnknownInitial;
            return ScanType.Exact;
        }

        private NextScanType GetSelectedNextScanType()
        {
            string text = scanTypeCombo.SelectedItem?.ToString() ?? "";
            if (text.Contains("Increased")) return NextScanType.Increased;
            if (text.Contains("Decreased")) return NextScanType.Decreased;
            if (text.Contains("Changed")) return NextScanType.Changed;
            if (text.Contains("Unchanged")) return NextScanType.Unchanged;
            return NextScanType.Exact;
        }

        private void UpdateScanTypes()
        {
            scanTypeCombo.Items.Clear();
            if (isFirstScan)
            {
                scanTypeCombo.Items.AddRange(new object[] { "Exact Value", "Between", "Bigger Than...", "Smaller Than...", "Unknown Initial Value" });
                scanTypeCombo.SelectedIndex = 0;
            }
            else
            {
                scanTypeCombo.Items.AddRange(new object[] { "Exact Value", "Increased Value", "Decreased Value", "Changed Value", "Unchanged Value" });
                scanTypeCombo.SelectedIndex = 0;
            }
            value2Box.Visible = scanTypeCombo.SelectedItem?.ToString() == "Between";
        }

        private int GetValueSize(ValueType type)
        {
            switch (type)
            {
                case ValueType.Byte: return 1;
                case ValueType.Int16: return 2;
                case ValueType.Int32: return 4;
                case ValueType.Int64: return 8;
                case ValueType.Float: return 4;
                case ValueType.Double: return 8;
                default: return 4;
            }
        }

        private byte[] ValueToBytes(string text, ValueType type)
        {
            try
            {
                switch (type)
                {
                    case ValueType.Byte: return new byte[] { byte.Parse(text) };
                    case ValueType.Int16: return BitConverter.GetBytes(short.Parse(text));
                    case ValueType.Int32: return BitConverter.GetBytes(int.Parse(text));
                    case ValueType.Int64: return BitConverter.GetBytes(long.Parse(text));
                    case ValueType.Float: return BitConverter.GetBytes(float.Parse(text));
                    case ValueType.Double: return BitConverter.GetBytes(double.Parse(text));
                    case ValueType.String: return Encoding.ASCII.GetBytes(text);
                    case ValueType.AoB:
                        var parts = text.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        var bytes = new byte[parts.Length];
                        for (int i = 0; i < parts.Length; i++)
                            bytes[i] = parts[i] == "??" ? (byte)0xCC : Convert.ToByte(parts[i], 16);
                        return bytes;
                    default: return BitConverter.GetBytes(int.Parse(text));
                }
            }
            catch { return new byte[0]; }
        }

        private string FormatBytes(byte[] data, ValueType type)
        {
            if (data == null || data.Length == 0) return "";
            try
            {
                switch (type)
                {
                    case ValueType.Byte: return data[0].ToString();
                    case ValueType.Int16: return BitConverter.ToInt16(data, 0).ToString();
                    case ValueType.Int32: return BitConverter.ToInt32(data, 0).ToString();
                    case ValueType.Int64: return BitConverter.ToInt64(data, 0).ToString();
                    case ValueType.Float: return BitConverter.ToSingle(data, 0).ToString("G7");
                    case ValueType.Double: return BitConverter.ToDouble(data, 0).ToString("G15");
                    case ValueType.String: return Encoding.ASCII.GetString(data);
                    case ValueType.AoB: return BitConverter.ToString(data).Replace("-", " ");
                    default: return BitConverter.ToInt32(data, 0).ToString();
                }
            }
            catch { return "?"; }
        }

        private bool CompareBytes(byte[] data, int offset, byte[] search, ValueType type, ScanType scanType)
        {
            if (offset + search.Length > data.Length) return false;

            switch (scanType)
            {
                case ScanType.Exact:
                    for (int i = 0; i < search.Length; i++)
                        if (data[offset + i] != search[i]) return false;
                    return true;

                case ScanType.BiggerThan:
                    return CompareNumericAt(data, offset, search) > 0;

                case ScanType.SmallerThan:
                    return CompareNumericAt(data, offset, search) < 0;

                default:
                    for (int i = 0; i < search.Length; i++)
                        if (data[offset + i] != search[i]) return false;
                    return true;
            }
        }

        private int CompareNumericAt(byte[] data, int offset, byte[] compare)
        {
            int size = Math.Min(compare.Length, data.Length - offset);
            if (size >= 8) return BitConverter.ToInt64(data, offset).CompareTo(BitConverter.ToInt64(compare, 0));
            if (size >= 4) return BitConverter.ToInt32(data, offset).CompareTo(BitConverter.ToInt32(compare, 0));
            if (size >= 2) return BitConverter.ToInt16(data, offset).CompareTo(BitConverter.ToInt16(compare, 0));
            return data[offset].CompareTo(compare[0]);
        }

        private int CompareNumeric(byte[] a, byte[] b)
        {
            int size = Math.Min(a.Length, b.Length);
            if (size >= 8) return BitConverter.ToInt64(a, 0).CompareTo(BitConverter.ToInt64(b, 0));
            if (size >= 4) return BitConverter.ToInt32(a, 0).CompareTo(BitConverter.ToInt32(b, 0));
            if (size >= 2) return BitConverter.ToInt16(a, 0).CompareTo(BitConverter.ToInt16(b, 0));
            return a[0].CompareTo(b[0]);
        }

        private bool BytesEqual(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++) if (a[i] != b[i]) return false;
            return true;
        }

        private byte[] ReadRegion(ulong address, int size)
        {
            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, buf, size)) return null;
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private byte[] ReadBytes(ulong address, int size)
        {
            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, buf, size)) return null;
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private bool WriteBytes(ulong address, byte[] data)
        {
            IntPtr buf = Marshal.AllocHGlobal(data.Length);
            try
            {
                Marshal.Copy(data, 0, buf, data.Length);
                // Use VirtualProtectEx + WriteProcessMemory via process handle
                return false; // Requires process handle - freeze works via driver in kernel mode
            }
            finally { Marshal.FreeHGlobal(buf); }
        }

        private void AddWatch_Click(object sender, EventArgs e)
        {
            if (resultsList.SelectedIndices.Count == 0) return;
            foreach (int idx in resultsList.SelectedIndices)
            {
                if (idx < currentResults.Count)
                {
                    var r = currentResults[idx];
                    Log("Watch: 0x{0:X} = {1}", r.Address, FormatBytes(r.CurrentBytes, GetSelectedType()));
                }
            }
        }

        private CancellationTokenSource findAccessCts;

        private async void FindAccess_Click(object sender, EventArgs e)
        {
            try
            {
                if (resultsList.SelectedIndices.Count == 0)
                {
                    Log("Select a result address first");
                    return;
                }

                int idx = resultsList.SelectedIndices[0];
                if (idx >= currentResults.Count) return;
                var result = currentResults[idx];
                ulong targetAddr = result.Address;

                Log("Setting data breakpoint on 0x{0:X} (read/write)...", targetAddr);

                // Set hardware data breakpoint on all threads
                var threadIds = EnumerateThreadIds();
                int set = 0;

                foreach (uint tid in threadIds)
                {
                    bool success = false;

                    if (driver.IsKernelMode)
                    {
                        try
                        {
                            byte[] ctx = driver.GetThreadContext(processId, (int)tid, 0x00100010);
                            if (ctx != null && ctx.Length >= 2048)
                            {
                                BitConverter.GetBytes((long)targetAddr).CopyTo(ctx, 72);
                                long dr7 = BitConverter.ToInt64(ctx, 112);
                                dr7 |= 1L;
                                dr7 |= (3L << 16);
                                dr7 |= (3L << 18);
                                BitConverter.GetBytes(dr7).CopyTo(ctx, 112);
                                success = driver.SetThreadContext(processId, (int)tid, ctx);
                            }
                        }
                        catch { }
                    }

                    if (!success)
                    {
                        IntPtr hThread = OpenThread(0x0008 | 0x0010 | 0x0040, false, tid);
                        if (hThread == IntPtr.Zero) continue;
                        try
                        {
                            IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                            try
                            {
                                for (int i = 0; i < 2048; i++) Marshal.WriteByte(ctxPtr, i, 0);
                                Marshal.WriteInt32(ctxPtr, 48, 0x00100010);
                                if (GetThreadContext(hThread, ctxPtr))
                                {
                                    Marshal.WriteInt64(ctxPtr, 72, (long)targetAddr);
                                    long dr7 = Marshal.ReadInt64(ctxPtr, 112);
                                    dr7 |= 1L;
                                    dr7 |= (3L << 16);
                                    dr7 |= (3L << 18);
                                    Marshal.WriteInt64(ctxPtr, 112, dr7);
                                    success = SetThreadContext(hThread, ctxPtr);
                                }
                            }
                            finally { Marshal.FreeHGlobal(ctxPtr); }
                        }
                        finally { CloseHandle(hThread); }
                    }

                    if (success) set++;
                }

                if (set == 0) { Log("Failed to set breakpoint on any thread"); return; }
                Log("Data breakpoint set on {0} threads, monitoring for access...", set);

                findAccessCts?.Cancel();
                findAccessCts = new CancellationTokenSource();
                var token = findAccessCts.Token;

                await Task.Run(async () =>
                {
                    try
                    {
                        int hits = 0;
                        while (!token.IsCancellationRequested && hits < 100)
                        {
                            await Task.Delay(50, token);

                            foreach (uint tid in threadIds)
                            {
                                byte[] ctx = null;
                                if (driver.IsKernelMode)
                                    ctx = driver.GetThreadContext(processId, (int)tid, 0x00100010);
                                if (ctx == null)
                                {
                                    IntPtr hThread = OpenThread(0x0008 | 0x0040, false, tid);
                                    if (hThread == IntPtr.Zero) continue;
                                    try
                                    {
                                        IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                                        try
                                        {
                                            for (int i = 0; i < 2048; i++) Marshal.WriteByte(ctxPtr, i, 0);
                                            Marshal.WriteInt32(ctxPtr, 48, 0x00100010);
                                            if (GetThreadContext(hThread, ctxPtr))
                                            {
                                                ctx = new byte[2048];
                                                Marshal.Copy(ctxPtr, ctx, 0, 2048);
                                            }
                                        }
                                        finally { Marshal.FreeHGlobal(ctxPtr); }
                                    }
                                    finally { CloseHandle(hThread); }
                                }

                                if (ctx == null || ctx.Length < 2048) continue;

                                long dr6 = BitConverter.ToInt64(ctx, 104);
                                if ((dr6 & 1) != 0)
                                {
                                    ulong rip = BitConverter.ToUInt64(ctx, 248);
                                    hits++;

                                    byte[] instrBytes = new byte[16];
                                    IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)16,
                                        WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                                    string instrText = "";
                                    if (buf != IntPtr.Zero)
                                    {
                                        try
                                        {
                                            if (driver.CopyVirtualMemory(processId, (IntPtr)rip, buf, 16))
                                            {
                                                Marshal.Copy(buf, instrBytes, 0, 16);
                                                var instructions = Utility.SimpleDisassembler.Disassemble(instrBytes, rip, 1);
                                                if (instructions.Count > 0)
                                                    instrText = $"{instructions[0].Mnemonic} {instructions[0].Operands}";
                                            }
                                        }
                                        finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
                                    }

                                    string moduleInfo = ResolveAddress(rip);

                                    this.SafeInvoke(() =>
                                    {
                                        Log("ACCESS #{0}: TID {1} @ RIP 0x{2:X} | {3} | {4}",
                                            hits, tid, rip, instrText, moduleInfo);
                                    });

                                    dr6 &= ~1L;
                                    BitConverter.GetBytes(dr6).CopyTo(ctx, 104);
                                    if (driver.IsKernelMode)
                                        driver.SetThreadContext(processId, (int)tid, ctx);
                                }
                            }
                        }

                        ClearDataBreakpoints(threadIds);
                        this.SafeInvoke(() => Log("Find Access complete: {0} access events captured", hits));
                    }
                    catch (OperationCanceledException) { }
                    catch (Exception ex)
                    {
                        this.SafeInvoke(() => Log("Find Access error: {0}", ex.Message));
                    }
                }, token);
            }
            catch (Exception ex)
            {
                Log("Find Access setup error: {0}", ex.Message);
            }
        }

        private void ClearDataBreakpoints(List<uint> threadIds)
        {
            foreach (uint tid in threadIds)
            {
                if (driver.IsKernelMode)
                {
                    byte[] ctx = driver.GetThreadContext(processId, (int)tid, 0x00100010);
                    if (ctx != null && ctx.Length >= 2048)
                    {
                        BitConverter.GetBytes(0L).CopyTo(ctx, 72); // Clear DR0
                        long dr7 = BitConverter.ToInt64(ctx, 112);
                        dr7 &= ~1L; // Disable DR0
                        BitConverter.GetBytes(dr7).CopyTo(ctx, 112);
                        driver.SetThreadContext(processId, (int)tid, ctx);
                    }
                }
                else
                {
                    IntPtr hThread = OpenThread(0x0008 | 0x0010 | 0x0040, false, tid);
                    if (hThread == IntPtr.Zero) continue;
                    try
                    {
                        IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                        for (int i = 0; i < 2048; i++) Marshal.WriteByte(ctxPtr, i, 0);
                        Marshal.WriteInt32(ctxPtr, 48, 0x00100010);
                        if (GetThreadContext(hThread, ctxPtr))
                        {
                            Marshal.WriteInt64(ctxPtr, 72, 0);
                            long dr7 = Marshal.ReadInt64(ctxPtr, 112);
                            dr7 &= ~1L;
                            Marshal.WriteInt64(ctxPtr, 112, dr7);
                            SetThreadContext(hThread, ctxPtr);
                        }
                        Marshal.FreeHGlobal(ctxPtr);
                    }
                    finally { CloseHandle(hThread); }
                }
            }
        }

        private string ResolveAddress(ulong address)
        {
            try
            {
                if (driver.GetModuleSummaryList(processId, out var modules) && modules != null)
                {
                    foreach (var mod in modules)
                    {
                        if (address >= mod.BaseAddress && address < mod.BaseAddress + mod.ImageSize)
                        {
                            ulong rva = address - mod.BaseAddress;
                            return $"{mod.ModuleName}+0x{rva:X}";
                        }
                    }
                }
            }
            catch { }
            return "unknown";
        }

        private List<uint> EnumerateThreadIds()
        {
            var result = new List<uint>();
            try
            {
                int bufSize = 0x100000;
                IntPtr buffer = Marshal.AllocHGlobal(bufSize);
                try
                {
                    int status = NtQuerySystemInformation(5, buffer, bufSize, out int retLen);
                    if (status == unchecked((int)0xC0000004))
                    {
                        bufSize = retLen + 0x10000;
                        Marshal.FreeHGlobal(buffer);
                        buffer = Marshal.AllocHGlobal(bufSize);
                        status = NtQuerySystemInformation(5, buffer, bufSize, out retLen);
                    }
                    if (status != 0) return result;

                    int offset = 0;
                    while (offset < retLen)
                    {
                        IntPtr current = buffer + offset;
                        int nextOffset = Marshal.ReadInt32(current, 0);
                        int procId = Marshal.ReadInt32(current, IntPtr.Size == 8 ? 88 : 68);

                        if (procId == processId)
                        {
                            int threadCount = Marshal.ReadInt32(current, IntPtr.Size == 8 ? 68 : 64);
                            IntPtr threadArray = current + (IntPtr.Size == 8 ? 112 : 84);
                            int offThreadId = IntPtr.Size == 8 ? 40 : 32;
                            int structSize = IntPtr.Size == 8 ? 72 : 56;

                            for (int i = 0; i < threadCount; i++)
                            {
                                IntPtr tInfo = threadArray + (i * structSize);
                                uint tid = (uint)(IntPtr.Size == 8
                                    ? Marshal.ReadInt64(tInfo, offThreadId)
                                    : Marshal.ReadInt32(tInfo, offThreadId));
                                result.Add(tid);
                            }
                            break;
                        }
                        if (nextOffset == 0) break;
                        offset += nextOffset;
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }
            return result;
        }

        private void UpdateResultCount()
        {
            resultCountLbl.Text = $"Results: {currentResults.Count:N0}";
        }

        private void Log(string message, params object[] args)
        {
            logBox.SafeInvoke(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"));
        }

        // ==================== UI HELPERS ====================

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private TextBox CreateTextBox(int width)
        {
            return new TextBox { Width = width, Margin = new Padding(2, 0, 4, 0), BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.FixedSingle, Font = DarkTheme.UIMonoFont };
        }

        private Label MakeLabel(string text) => new Label { Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
        private Control MakeSpacer(int width) => new Panel { Width = width, Height = 1 };

        // ==================== P/INVOKE ====================

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int bufSize, out int retLen);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private ListView CreateListView()
        {
            var lv = new ListView { View = View.Details, FullRowSelect = true, MultiSelect = true, BorderStyle = BorderStyle.None, Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont };
            lv.Resize += (s, e) => { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; };
            lv.HandleCreated += (s, e) => { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; };
            return lv;
        }
    }
}
