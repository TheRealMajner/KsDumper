using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
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
    /// <summary>
    /// Live string dumper that monitors a process over time and captures strings
    /// as they are decrypted/exposed in memory. Periodically scans all committed
    /// readable memory regions and collects new strings that weren't seen before.
    /// </summary>
    public class LiveStringDumpWindow : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView stringList;
        private RichTextBox logBox;
        private Button startBtn;
        private Button stopBtn;
        private Button exportBtn;
        private Button clearBtn;
        private NumericUpDown intervalBox;
        private NumericUpDown minLengthBox;
        private CheckBox asciiCheck;
        private CheckBox unicodeCheck;
        private Label statsLbl;
        private Label statusLbl;
        private ProgressBar progressBar;

        private CancellationTokenSource cts;
        private bool isRunning;
        private readonly HashSet<string> knownStrings;
        private readonly List<StringEntry> allStrings;
        private readonly object syncLock;
        private int scanCount;

        private struct StringEntry
        {
            public ulong Address;
            public string Value;
            public bool IsUnicode;
            public DateTime FirstSeen;
            public int ScanNumber;
            public string Region;
        }

        public LiveStringDumpWindow(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            knownStrings = new HashSet<string>();
            allStrings = new List<StringEntry>();
            syncLock = new object();
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"Live String Dump - {processName} (PID: {processId})";
            Size = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(800, 500);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Top toolbar - two rows with explicit layout
            var toolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(8) };

            // Row 1: Buttons (y=8)
            int y1 = 8;
            startBtn = CreateButton("Start Monitoring", 120);
            startBtn.Location = new Point(8, y1);
            startBtn.Click += Start_Click;
            stopBtn = CreateButton("Stop", 60);
            stopBtn.Location = new Point(134, y1);
            stopBtn.Enabled = false;
            stopBtn.Click += Stop_Click;
            exportBtn = CreateButton("Export...", 70);
            exportBtn.Location = new Point(200, y1);
            exportBtn.Click += Export_Click;
            clearBtn = CreateButton("Clear", 60);
            clearBtn.Location = new Point(276, y1);
            clearBtn.Click += Clear_Click;

            // Row 2: Settings + status (y=40)
            int y2 = 42;
            int x2 = 8;
            var intervalLbl = MakeLabel("Interval (s):");
            intervalLbl.Location = new Point(x2, y2);
            toolbar.Controls.Add(intervalLbl);
            x2 += intervalLbl.PreferredWidth + 4;

            intervalBox = new DarkNumericUpDown { Width = 50, Minimum = 1, Maximum = 30, Value = 2 };
            intervalBox.Location = new Point(x2, y2 - 2);
            x2 += 56;

            var minLenLbl = MakeLabel("Min Len:");
            minLenLbl.Location = new Point(x2, y2);
            toolbar.Controls.Add(minLenLbl);
            x2 += minLenLbl.PreferredWidth + 4;

            minLengthBox = new DarkNumericUpDown { Width = 50, Minimum = 3, Maximum = 50, Value = 6 };
            minLengthBox.Location = new Point(x2, y2 - 2);
            x2 += 56;

            asciiCheck = new DarkCheckBox { Text = "ASCII", AutoSize = true, Checked = true };
            asciiCheck.Location = new Point(x2, y2);
            x2 += 60;

            unicodeCheck = new DarkCheckBox { Text = "Unicode", AutoSize = true, Checked = true };
            unicodeCheck.Location = new Point(x2, y2);
            x2 += 74;

            statsLbl = new Label { Text = "Strings: 0 | Scans: 0", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold };
            statsLbl.Location = new Point(x2 + 8, y2);
            x2 += statsLbl.PreferredWidth + 24;

            statusLbl = new Label { Text = "Ready", AutoSize = true, ForeColor = DarkTheme.TextMuted, Font = DarkTheme.UIFont };
            statusLbl.Location = new Point(x2 + 8, y2);

            toolbar.Controls.AddRange(new Control[] { startBtn, stopBtn, exportBtn, clearBtn,
                intervalBox, minLengthBox, asciiCheck, unicodeCheck, statsLbl, statusLbl });

            // Progress bar
            progressBar = new ProgressBar { Dock = DockStyle.Top, Height = 4, Style = ProgressBarStyle.Marquee, Visible = false };

            // String list
            stringList = new ListView
            {
                View = View.Details, FullRowSelect = true, MultiSelect = true,
                BorderStyle = BorderStyle.None, Dock = DockStyle.Fill,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont, VirtualMode = true
            };
            stringList.Columns.Add("#", 50);
            stringList.Columns.Add("Address", 130);
            stringList.Columns.Add("Type", 60);
            stringList.Columns.Add("Scan", 50);
            stringList.Columns.Add("Value", 500);
            stringList.RetrieveVirtualItem += (s, e) =>
            {
                List<StringEntry> snapshot;
                lock (syncLock) snapshot = new List<StringEntry>(allStrings);
                if (e.ItemIndex < 0 || e.ItemIndex >= snapshot.Count) { e.Item = new ListViewItem(""); return; }
                var entry = snapshot[e.ItemIndex];
                var lvi = new ListViewItem((e.ItemIndex + 1).ToString());
                lvi.SubItems.Add($"0x{entry.Address:X}");
                lvi.SubItems.Add(entry.IsUnicode ? "UTF-16" : "ASCII");
                lvi.SubItems.Add($"#{entry.ScanNumber}");
                string display = entry.Value.Length > 200 ? entry.Value.Substring(0, 200) + "..." : entry.Value;
                lvi.SubItems.Add(display);

                if (entry.IsUnicode) lvi.ForeColor = Color.FromArgb(180, 140, 255);
                else lvi.ForeColor = DarkTheme.TextPrimary;
                e.Item = lvi;
            };
            stringList.Resize += (s, e) => { if (stringList.Columns.Count > 0) stringList.Columns[stringList.Columns.Count - 1].Width = -2; };

            // Log panel
            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 120, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(stringList);
            Controls.Add(logPanel);
            Controls.Add(progressBar);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);

            FormClosing += (s, e) => { cts?.Cancel(); };
        }

        // ==================== Event Handlers ====================

        private async void Start_Click(object sender, EventArgs e)
        {
            if (isRunning) return;
            isRunning = true;
            startBtn.Enabled = false;
            stopBtn.Enabled = true;
            progressBar.Visible = true;
            statusLbl.Text = "Monitoring...";
            statusLbl.ForeColor = DarkTheme.Success;

            int interval = (int)intervalBox.Value;
            int minLength = (int)minLengthBox.Value;
            bool scanAscii = asciiCheck.Checked;
            bool scanUnicode = unicodeCheck.Checked;

            Log("Starting live string dump (interval: {0}s, min length: {1})", interval, minLength);
            Log("Mode: {0}{1}", scanAscii ? "ASCII " : "", scanUnicode ? "Unicode" : "");

            cts = new CancellationTokenSource();
            var token = cts.Token;

            await Task.Run(async () =>
            {
                scanCount = 0;

                while (!token.IsCancellationRequested)
                {
                    scanCount++;
                    int newCount = 0;

                    try
                    {
                        this.SafeInvoke(() => statusLbl.Text = $"Scanning... (scan #{scanCount})");

                        // Use driver's DumpLiveStrings for kernel-mode scanning (best coverage)
                        if (driver.IsKernelMode)
                        {
                            var strings = driver.DumpLiveStrings(processId, minLength);
                            foreach (var (addr, isUnicode, value) in strings)
                            {
                                if (!scanAscii && !isUnicode) continue;
                                if (!scanUnicode && isUnicode) continue;
                                if (IsGarbageString(value)) continue;

                                bool isNew;
                                lock (syncLock)
                                {
                                    isNew = knownStrings.Add(value);
                                    if (isNew)
                                    {
                                        allStrings.Add(new StringEntry
                                        {
                                            Address = addr,
                                            Value = value,
                                            IsUnicode = isUnicode,
                                            FirstSeen = DateTime.Now,
                                            ScanNumber = scanCount,
                                            Region = ""
                                        });
                                    }
                                }
                                if (isNew) newCount++;
                            }
                        }
                        else
                        {
                            // User-mode fallback: enumerate regions and scan each
                            var regions = driver.EnumRegions(processId);
                            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
                            {
                                if (token.IsCancellationRequested) break;
                                if (state != 0x1000) continue; // MEM_COMMIT only
                                if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0) continue;

                                int size = (int)Math.Min(regionSize, 0x100000);
                                IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                                if (buf == IntPtr.Zero) continue;
                                try
                                {
                                    if (!driver.CopyVirtualMemory(processId, (IntPtr)baseAddr, buf, size))
                                        continue;

                                    byte[] data = new byte[size];
                                    Marshal.Copy(buf, data, 0, size);

                                    // Scan ASCII
                                    if (scanAscii)
                                    {
                                        int runStart = -1;
                                        for (int i = 0; i < size; i++)
                                        {
                                            bool printable = data[i] >= 0x20 && data[i] < 0x7F;
                                            if (printable) { if (runStart < 0) runStart = i; }
                                            else
                                            {
                                                if (runStart >= 0)
                                                {
                                                    int len = i - runStart;
                                                    if (len >= minLength)
                                                    {
                                                        string val = Encoding.ASCII.GetString(data, runStart, len);
                                                        bool isNew;
                                                        lock (syncLock)
                                                        {
                                                            isNew = knownStrings.Add(val);
                                                            if (isNew)
                                                            {
                                                                allStrings.Add(new StringEntry
                                                                {
                                                                    Address = baseAddr + (ulong)runStart,
                                                                    Value = val,
                                                                    IsUnicode = false,
                                                                    FirstSeen = DateTime.Now,
                                                                    ScanNumber = scanCount,
                                                                    Region = $"0x{baseAddr:X}"
                                                                });
                                                            }
                                                        }
                                                        if (isNew) newCount++;
                                                    }
                                                    runStart = -1;
                                                }
                                            }
                                        }
                                    }

                                    // Scan Unicode
                                    if (scanUnicode)
                                    {
                                        int runStart = -1;
                                        int charCount = 0;
                                        for (int i = 0; i < size - 1; i += 2)
                                        {
                                            ushort ch = BitConverter.ToUInt16(data, i);
                                            bool printable = ch >= 0x20 && ch < 0x7F;
                                            if (printable) { if (runStart < 0) { runStart = i; charCount = 0; } charCount++; }
                                            else
                                            {
                                                if (charCount >= minLength)
                                                {
                                                    string val = Encoding.Unicode.GetString(data, runStart, charCount * 2);
                                                    bool isNew;
                                                    lock (syncLock)
                                                    {
                                                        isNew = knownStrings.Add(val);
                                                        if (isNew)
                                                        {
                                                            allStrings.Add(new StringEntry
                                                            {
                                                                Address = baseAddr + (ulong)runStart,
                                                                Value = val,
                                                                IsUnicode = true,
                                                                FirstSeen = DateTime.Now,
                                                                ScanNumber = scanCount,
                                                                Region = $"0x{baseAddr:X}"
                                                            });
                                                        }
                                                    }
                                                    if (isNew) newCount++;
                                                }
                                                runStart = -1;
                                                charCount = 0;
                                            }
                                        }
                                    }
                                }
                                finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
                            }
                        }

                        this.SafeInvoke(() =>
                        {
                            stringList.VirtualListSize = allStrings.Count;
                            stringList.Invalidate();
                            int total;
                            lock (syncLock) total = allStrings.Count;
                            statsLbl.Text = $"Strings: {total:N0} | Scans: {scanCount} | New: {newCount}";

                            if (newCount > 0)
                                Log("Scan #{0}: {1} new strings ({2} total)", scanCount, newCount, allStrings.Count);
                        });
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception ex)
                    {
                        this.SafeInvoke(() => Log("Scan error: {0}", ex.Message));
                    }

                    try { await Task.Delay(interval * 1000, token); }
                    catch (OperationCanceledException) { break; }
                }

                this.SafeInvoke(() =>
                {
                    int total;
                    lock (syncLock) total = allStrings.Count;
                    Log("Live string dump complete: {0} scans, {1} unique strings captured", scanCount, total);
                    statusLbl.Text = $"Complete ({total:N0} strings)";
                    statusLbl.ForeColor = DarkTheme.TextMuted;
                });
            }, token);

            isRunning = false;
            startBtn.Enabled = true;
            stopBtn.Enabled = false;
            progressBar.Visible = false;
        }

        private void Stop_Click(object sender, EventArgs e)
        {
            cts?.Cancel();
            isRunning = false;
            startBtn.Enabled = true;
            stopBtn.Enabled = false;
            progressBar.Visible = false;
            statusLbl.Text = "Stopped";
            statusLbl.ForeColor = DarkTheme.TextMuted;
            Log("Monitoring stopped by user");
        }

        private void Export_Click(object sender, EventArgs e)
        {
            List<StringEntry> snapshot;
            lock (syncLock) snapshot = new List<StringEntry>(allStrings);

            if (snapshot.Count == 0) { Log("No strings to export"); return; }

            using (var sfd = new SaveFileDialog())
            {
                sfd.FileName = $"{processName}_strings_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
                sfd.Filter = "Text Files|*.txt|CSV|*.csv|All Files|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        using (var w = new StreamWriter(sfd.FileName, false, Encoding.UTF8))
                        {
                            w.WriteLine($"// KsDumper - Live String Dump");
                            w.WriteLine($"// Process: {processName} (PID: {processId})");
                            w.WriteLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                            w.WriteLine($"// Total: {snapshot.Count:N0} unique strings across {scanCount} scans");
                            w.WriteLine($"// Format: [SCAN#] [ADDRESS] [TYPE] VALUE");
                            w.WriteLine();

                            foreach (var entry in snapshot)
                            {
                                string escaped = entry.Value
                                    .Replace("\\", "\\\\")
                                    .Replace("\"", "\\\"")
                                    .Replace("\r", "\\r")
                                    .Replace("\n", "\\n")
                                    .Replace("\t", "\\t");
                                w.WriteLine($"[#{entry.ScanNumber}] [0x{entry.Address:X}] [{(entry.IsUnicode ? "UTF16" : "ASCII")}] \"{escaped}\"");
                            }
                        }
                        Log("Exported {0} strings to {1}", snapshot.Count, sfd.FileName);
                    }
                    catch (Exception ex) { Log("Export error: {0}", ex.Message); }
                }
            }
        }

        private void Clear_Click(object sender, EventArgs e)
        {
            lock (syncLock)
            {
                allStrings.Clear();
                knownStrings.Clear();
            }
            scanCount = 0;
            stringList.VirtualListSize = 0;
            stringList.Invalidate();
            statsLbl.Text = "Strings: 0 | Scans: 0";
            Log("Cleared all strings");
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        // ==================== UI Helpers ====================

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private Label MakeLabel(string text) => new Label { Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };

        private static bool IsGarbageString(string s)
        {
            if (string.IsNullOrEmpty(s) || s.Length < 4) return true;

            int alpha = 0, digits = 0, nonLatin = 0, control = 0;
            int total = s.Length;

            foreach (char c in s)
            {
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) alpha++;
                else if (c >= '0' && c <= '9') digits++;
                else if (c > 0x2FFF) nonLatin++;
                else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') control++;
            }

            if (nonLatin > total * 0.3) return true;
            if (control > total * 0.3) return true;
            if ((double)(alpha + digits) / total < 0.4) return true;
            if (total < 10 && alpha < 3) return true;

            if (s.Contains("://") || s.Contains(":\\") || s.Contains("./")) return false;
            if (s.EndsWith(".dll") || s.EndsWith(".exe") || s.EndsWith(".sys") || s.EndsWith(".cfg")) return false;

            int letterRun = 0;
            foreach (char c in s)
            {
                if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) { letterRun++; if (letterRun >= 3) return false; }
                else letterRun = 0;
            }
            return true;
        }
    }
}
