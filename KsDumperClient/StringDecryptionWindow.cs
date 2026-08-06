using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class StringDecryptionWindow : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;
        private readonly ModuleSummary[] modules;

        private TabControl tabControl;
        private ListView resultsList;
        private RichTextBox logBox;
        private Label statusLbl;

        // File Scanner controls
        private TextBox filePathBox;
        private TextBox imageBaseBox;
        private Button scanFileBtn;

        // Live Monitor controls
        private ComboBox moduleCombo;
        private NumericUpDown intervalBox;
        private Button startMonitorBtn;
        private Button stopMonitorBtn;
        private Button clearMonitorBtn;
        private Label monitorStatusLbl;

        // Breakpoint controls
        private CheckedListBox breakpointList;
        private Button attachDbgBtn;
        private Button startCaptureBtn;
        private Button stopCaptureBtn;
        private Label bpStatusLbl;

        private LiveStringMonitor liveMonitor;
        private BreakpointStringCapture bpCapture;

        public StringDecryptionWindow(IMemoryReader driver, int processId, string processName, ModuleSummary[] modules = null)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            this.modules = modules ?? new ModuleSummary[0];
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"String Scanner - {processName} (PID: {processId})";
            Size = new Size(1100, 800);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(900, 600);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = Utility.AppIcon.Get(); } catch { }

            // Top bar
            var topPanel = new Panel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface };
            statusLbl = new Label
            {
                Text = $"Process: {processName} (PID: {processId})  |  Modules: {modules.Length}",
                Location = new Point(12, 10), AutoSize = true,
                ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFontBold
            };
            topPanel.Controls.Add(statusLbl);

            // Bottom results panel
            var resultsPanel = new Panel { Dock = DockStyle.Bottom, Height = 280, BackColor = DarkTheme.Surface };
            var resultsToolbar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.SurfaceElevated,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(8, 4, 8, 4)
            };

            var exportBtn = CreateButton("Export...", 70);
            exportBtn.Click += Export_Click;
            var copyBtn = CreateButton("Copy All", 65);
            copyBtn.Click += (s, e) =>
            {
                var sb = new System.Text.StringBuilder();
                foreach (ListViewItem item in resultsList.Items)
                    sb.AppendLine($"{item.Text}\t{item.SubItems[1].Text}\t{item.SubItems[2].Text}\t{item.SubItems[3].Text}");
                if (sb.Length > 0) Clipboard.SetText(sb.ToString());
            };
            var clearResultsBtn = CreateButton("Clear", 55);
            clearResultsBtn.Click += (s, e) => resultsList.Items.Clear();
            var resultsLabel = new Label
            {
                Text = "Results:", AutoSize = true, ForeColor = DarkTheme.TextSecondary,
                Font = DarkTheme.UIFontBold, Margin = new Padding(12, 6, 0, 0)
            };

            resultsToolbar.Controls.AddRange(new Control[] { exportBtn, copyBtn, clearResultsBtn, resultsLabel });

            resultsList = CreateListView();
            resultsList.Columns.Add("Address", 130);
            resultsList.Columns.Add("Decrypted String", 380);
            resultsList.Columns.Add("Method", 140);
            resultsList.Columns.Add("Category", 90);
            resultsList.Columns.Add("Source", 100);

            resultsPanel.Controls.Add(resultsList);
            resultsPanel.Controls.Add(resultsToolbar);

            // Log panel
            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 100, BackColor = DarkTheme.Surface };
            var logLabel = new Label
            {
                Text = "   Log", Dock = DockStyle.Top, Height = 22,
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold,
                TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated
            };
            logBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            // Tab control
            tabControl = new TabControl { Dock = DockStyle.Fill, Font = DarkTheme.UIFont, Padding = new Point(10, 5) };

            // ========== FILE SCANNER TAB ==========
            var filePage = new TabPage("File Scanner") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };

            var fileToolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(12, 8, 12, 8) };

            var fileRow1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            fileRow1.Controls.Add(MakeLabel("File:"));
            filePathBox = CreateTextBox(500);
            fileRow1.Controls.Add(filePathBox);
            var browseBtn = CreateButton("Browse...", 80);
            browseBtn.Click += Browse_Click;
            fileRow1.Controls.Add(browseBtn);
            fileToolbar.Controls.Add(fileRow1);

            var fileRow2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            fileRow2.Controls.Add(MakeLabel("Image Base:"));
            imageBaseBox = CreateTextBox(140);
            imageBaseBox.Text = "0x140000000";
            imageBaseBox.Font = DarkTheme.UIMonoFont;
            fileRow2.Controls.Add(imageBaseBox);
            scanFileBtn = CreateButton("Scan File", 90);
            scanFileBtn.BackColor = DarkTheme.AccentSubtle;
            scanFileBtn.Click += ScanFile_Click;
            fileRow2.Controls.Add(scanFileBtn);
            var scanFolderBtn = CreateButton("Scan Folder...", 100);
            scanFolderBtn.Click += ScanFolder_Click;
            fileRow2.Controls.Add(scanFolderBtn);
            fileToolbar.Controls.Add(fileRow2);

            var fileLog = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Background,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            filePage.Controls.Add(fileLog);
            filePage.Controls.Add(fileToolbar);

            // ========== LIVE MONITOR TAB ==========
            var monitorPage = new TabPage("Live Monitor") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };

            var monitorToolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(12, 8, 12, 8) };

            var monRow1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            monRow1.Controls.Add(MakeLabel("Module:"));
            moduleCombo = new DarkComboBox { Width = 250 };
            moduleCombo.Items.Add("-- Full Process --");
            foreach (var mod in modules)
                moduleCombo.Items.Add($"{mod.ModuleName} (0x{mod.BaseAddress:X})");
            moduleCombo.SelectedIndex = 0;
            monRow1.Controls.Add(moduleCombo);
            monRow1.Controls.Add(MakeLabel("Interval (s):"));
            intervalBox = new DarkNumericUpDown { Width = 60, Minimum = 1, Maximum = 60, Value = 2 };
            monRow1.Controls.Add(intervalBox);
            monitorToolbar.Controls.Add(monRow1);

            var monRow2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            startMonitorBtn = CreateButton("Start Monitoring", 120);
            startMonitorBtn.BackColor = DarkTheme.AccentSubtle;
            startMonitorBtn.Click += StartMonitor_Click;
            stopMonitorBtn = CreateButton("Stop", 60);
            stopMonitorBtn.Enabled = false;
            stopMonitorBtn.Click += StopMonitor_Click;
            clearMonitorBtn = CreateButton("Clear History", 100);
            clearMonitorBtn.Click += (s, e) => { liveMonitor?.ClearHistory(); monitorStatusLbl.Text = "Cleared"; };
            monitorStatusLbl = new Label { Text = "Idle", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFont, Margin = new Padding(16, 6, 0, 0) };
            monRow2.Controls.AddRange(new Control[] { startMonitorBtn, stopMonitorBtn, clearMonitorBtn, monitorStatusLbl });
            monitorToolbar.Controls.Add(monRow2);

            var monitorLog = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Background,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            monitorPage.Controls.Add(monitorLog);
            monitorPage.Controls.Add(monitorToolbar);

            // ========== BREAKPOINT CAPTURE TAB ==========
            var bpPage = new TabPage("Breakpoint Capture") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };

            var bpToolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(12, 8, 12, 8) };

            var bpRow1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            attachDbgBtn = CreateButton("Attach Debugger", 120);
            attachDbgBtn.Click += AttachDebugger_Click;
            var autoDetectBtn = CreateButton("Auto-Detect Functions", 140);
            autoDetectBtn.Click += AutoDetect_Click;
            var addManualBtn = CreateButton("Add Breakpoint...", 120);
            addManualBtn.Click += AddManualBP_Click;
            bpRow1.Controls.AddRange(new Control[] { attachDbgBtn, autoDetectBtn, addManualBtn });
            bpToolbar.Controls.Add(bpRow1);

            var bpRow2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            startCaptureBtn = CreateButton("Start Capture", 100);
            startCaptureBtn.BackColor = DarkTheme.AccentSubtle;
            startCaptureBtn.Enabled = false;
            startCaptureBtn.Click += StartCapture_Click;
            stopCaptureBtn = CreateButton("Stop", 60);
            stopCaptureBtn.Enabled = false;
            stopCaptureBtn.Click += StopCapture_Click;
            bpStatusLbl = new Label { Text = "Not attached", AutoSize = true, ForeColor = DarkTheme.Warning, Font = DarkTheme.UIFont, Margin = new Padding(16, 6, 0, 0) };
            bpRow2.Controls.AddRange(new Control[] { startCaptureBtn, stopCaptureBtn, bpStatusLbl });
            bpToolbar.Controls.Add(bpRow2);

            breakpointList = new CheckedListBox
            {
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIMonoFont, BorderStyle = BorderStyle.None,
                CheckOnClick = true
            };

            bpPage.Controls.Add(breakpointList);
            bpPage.Controls.Add(bpToolbar);

            // Add tabs
            tabControl.TabPages.AddRange(new[] { filePage, monitorPage, bpPage });

            // Assembly order (dock stacking)
            Controls.Add(tabControl);
            Controls.Add(logPanel);
            Controls.Add(resultsPanel);
            Controls.Add(topPanel);

            DarkTheme.ApplyTo(this);

            // Wire events
            liveMonitor = new LiveStringMonitor(driver, processId);
            liveMonitor.OnStringDetected += sa =>
            {
                try { this.SafeInvoke(new Action(() => AddResult(sa.Address, sa.Value, "Live", sa.IsUnicode ? "Unicode" : "ASCII", sa.Source))); } catch { }
            };
            liveMonitor.OnLog += msg =>
            {
                try { this.SafeInvoke(new Action(() => monitorLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}\n"))); } catch { }
            };
            liveMonitor.OnScanComplete += newCount =>
            {
                try { this.SafeInvoke(new Action(() =>
                {
                    monitorStatusLbl.Text = $"Scanning... ({liveMonitor.TotalStringsFound} strings, {liveMonitor.ScanCount} scans)";
                })); } catch { }
            };

            // Auto-expand last column
            resultsList.Resize += (s, e) => { if (resultsList.Columns.Count > 0) resultsList.Columns[resultsList.Columns.Count - 1].Width = -2; };

            FormClosing += (s, e) =>
            {
                try { liveMonitor?.Dispose(); } catch { }
                try { bpCapture?.Dispose(); } catch { }
            };
        }

        // ========== File Scanner Events ==========

        private void Browse_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog())
            {
                ofd.Filter = "PE Files|*.exe;*.dll;*.sys|Executables|*.exe|Libraries|*.dll|Drivers|*.sys|All Files|*.*";
                ofd.Title = "Select PE file to scan";
                if (ofd.ShowDialog() == DialogResult.OK)
                    filePathBox.Text = ofd.FileName;
            }
        }

        private async void ScanFile_Click(object sender, EventArgs e)
        {
            string path = filePathBox.Text.Trim();
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                Log("Select a valid file path first");
                return;
            }

            ulong imageBase = 0;
            if (!string.IsNullOrEmpty(imageBaseBox.Text))
            {
                string hex = imageBaseBox.Text.Replace("0x", "").Replace("0X", "");
                ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out imageBase);
            }

            scanFileBtn.Enabled = false;
            Log("Scanning file: {0}", Path.GetFileName(path));
            statusLbl.Text = "Scanning file...";

            await Task.Run(() =>
            {
                try
                {
                    var result = FileStringScanner.ScanFileBytes(
                        File.ReadAllBytes(path), Path.GetFileName(path), imageBase,
                        msg => this.SafeInvoke(new Action(() => Log(msg))));

                    this.SafeInvoke(new Action(() =>
                    {
                        foreach (var ds in result.Strings)
                            AddResult(ds.Address, ds.Decrypted, ds.Method, ds.Category, "File");
                        foreach (var ss in result.StackStrings)
                            AddResult(ss.Address, ss.Value, "Stack String", "Code", "File");
                        foreach (var (addr, val) in result.UnicodeStrings)
                            AddResult(addr, val, "Unicode", "String", "File");
                        foreach (var p in result.Patterns)
                            AddResult(p.Address, p.Description, p.PatternName, "Pattern", "File");

                        Log("File scan complete: {0}", result.Summary);
                        statusLbl.Text = $"File scan: {result.Strings.Count + result.StackStrings.Count} strings found";
                        scanFileBtn.Enabled = true;
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => { Log("File scan error: {0}", ex.Message); scanFileBtn.Enabled = true; }));
                }
            });
        }

        private async void ScanFolder_Click(object sender, EventArgs e)
        {
            using (var fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Select folder containing PE files to scan";
                if (fbd.ShowDialog() != DialogResult.OK) return;

                scanFileBtn.Enabled = false;
                string folder = fbd.SelectedPath;
                Log("Scanning folder: {0}", folder);

                await Task.Run(() =>
                {
                    try
                    {
                        int fileCount = 0;
                        foreach (string ext in new[] { "*.exe", "*.dll", "*.sys" })
                        {
                            foreach (string file in Directory.GetFiles(folder, ext))
                            {
                                try
                                {
                                    var result = FileStringScanner.ScanFileBytes(
                                        File.ReadAllBytes(file), Path.GetFileName(file), 0,
                                        msg => { });

                                    this.SafeInvoke(new Action(() =>
                                    {
                                        foreach (var ds in result.Strings)
                                            AddResult(ds.Address, ds.Decrypted, ds.Method, ds.Category, Path.GetFileName(file));
                                        foreach (var ss in result.StackStrings)
                                            AddResult(ss.Address, ss.Value, "Stack String", "Code", Path.GetFileName(file));
                                        Log("  {0}: {1}", Path.GetFileName(file), result.Summary);
                                    }));
                                    fileCount++;
                                }
                                catch { }
                            }
                        }

                        this.SafeInvoke(new Action(() =>
                        {
                            Log("Folder scan complete: {0} files processed", fileCount);
                            statusLbl.Text = $"Folder scan: {fileCount} files, {resultsList.Items.Count} results";
                            scanFileBtn.Enabled = true;
                        }));
                    }
                    catch (Exception ex)
                    {
                        this.SafeInvoke(new Action(() => { Log("Folder scan error: {0}", ex.Message); scanFileBtn.Enabled = true; }));
                    }
                });
            }
        }

        // ========== Live Monitor Events ==========

        private void StartMonitor_Click(object sender, EventArgs e)
        {
            try
            {
                int interval = (int)intervalBox.Value;

                if (moduleCombo.SelectedIndex == 0)
                {
                    liveMonitor.StartMonitoring(TimeSpan.FromSeconds(interval), true);
                }
                else
                {
                    var mod = modules[moduleCombo.SelectedIndex - 1];
                    liveMonitor.StartMonitoring(TimeSpan.FromSeconds(interval), mod.BaseAddress, mod.ImageSize, mod.ModuleName);
                }

                startMonitorBtn.Enabled = false;
                stopMonitorBtn.Enabled = true;
                monitorStatusLbl.Text = "Monitoring...";
                monitorStatusLbl.ForeColor = DarkTheme.Success;
            }
            catch (Exception ex) { Log("Monitor start error: {0}", ex.Message); }
        }

        private void StopMonitor_Click(object sender, EventArgs e)
        {
            liveMonitor.StopMonitoring();
            startMonitorBtn.Enabled = true;
            stopMonitorBtn.Enabled = false;
            monitorStatusLbl.Text = "Stopped";
            monitorStatusLbl.ForeColor = DarkTheme.TextSecondary;
        }

        // ========== Breakpoint Capture Events ==========

        private void AttachDebugger_Click(object sender, EventArgs e)
        {
            try
            {
                if (bpCapture == null)
                    bpCapture = new BreakpointStringCapture(driver, processId);

                bpCapture.OnStringCaptured += cs =>
                {
                    try { this.SafeInvoke(new Action(() => AddResult(cs.Address, cs.Value, cs.Method, "Breakpoint", "Debugger"))); } catch { }
                };
                bpCapture.OnLog += msg =>
                {
                    try { this.SafeInvoke(new Action(() => Log(msg))); } catch { }
                };

                if (bpCapture.AttachDebugger())
                {
                    bpStatusLbl.Text = "Attached";
                    bpStatusLbl.ForeColor = DarkTheme.Success;
                    attachDbgBtn.Enabled = false;
                    startCaptureBtn.Enabled = true;
                }
                else
                {
                    bpStatusLbl.Text = "Attach failed";
                    bpStatusLbl.ForeColor = DarkTheme.Error;
                }
            }
            catch (Exception ex) { Log("Debugger attach error: {0}", ex.Message); bpStatusLbl.Text = "Error"; bpStatusLbl.ForeColor = DarkTheme.Error; }
        }

        private void AutoDetect_Click(object sender, EventArgs e)
        {
            try
            {
                if (bpCapture == null || !bpCapture.IsAttached)
                {
                    Log("Attach debugger first");
                    return;
                }

                bpCapture.AutoDetectDecryptionFunctions();
                RefreshBreakpointList();
            }
            catch (Exception ex) { Log("Auto-detect error: {0}", ex.Message); }
        }

        private void AddManualBP_Click(object sender, EventArgs e)
        {
            if (bpCapture == null || !bpCapture.IsAttached)
            {
                Log("Attach debugger first");
                return;
            }

            using (var input = new Form())
            {
                input.Text = "Add Breakpoint";
                input.Size = new Size(350, 150);
                input.StartPosition = FormStartPosition.CenterParent;
                input.BackColor = DarkTheme.Surface;

                var lbl = new Label { Text = "Address (hex):", Location = new Point(12, 15), ForeColor = DarkTheme.TextPrimary, AutoSize = true };
                var addrBox = new TextBox { Location = new Point(12, 38), Width = 200, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary };
                var nameLbl = new Label { Text = "Name:", Location = new Point(12, 65), ForeColor = DarkTheme.TextPrimary, AutoSize = true };
                var nameBox = new TextBox { Location = new Point(12, 85), Width = 200, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, Text = "Manual BP" };
                var okBtn = new Button { Text = "OK", Location = new Point(230, 38), Width = 80, DialogResult = DialogResult.OK };
                DarkControlsHelper.StyleButton(okBtn);

                input.Controls.AddRange(new Control[] { lbl, addrBox, nameLbl, nameBox, okBtn });
                input.AcceptButton = okBtn;

                if (input.ShowDialog() == DialogResult.OK)
                {
                    string hex = addrBox.Text.Replace("0x", "").Replace("0X", "");
                    ulong address;
                    if (ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out address))
                    {
                        bpCapture.SetBreakpoint(address, nameBox.Text);
                        RefreshBreakpointList();
                    }
                    else Log("Invalid address");
                }
            }
        }

        private void StartCapture_Click(object sender, EventArgs e)
        {
            try
            {
                bpCapture?.StartCapturing();
                startCaptureBtn.Enabled = false;
                stopCaptureBtn.Enabled = true;
                bpStatusLbl.Text = "Capturing...";
                bpStatusLbl.ForeColor = DarkTheme.Accent;
            }
            catch (Exception ex) { Log("Capture start error: {0}", ex.Message); }
        }

        private void StopCapture_Click(object sender, EventArgs e)
        {
            try
            {
                bpCapture?.StopCapturing();
                startCaptureBtn.Enabled = true;
                stopCaptureBtn.Enabled = false;
                bpStatusLbl.Text = "Stopped";
                bpStatusLbl.ForeColor = DarkTheme.TextSecondary;
            }
            catch (Exception ex) { Log("Capture stop error: {0}", ex.Message); }
        }

        private void RefreshBreakpointList()
        {
            breakpointList.Items.Clear();
            if (bpCapture == null) return;
            foreach (var bp in bpCapture.GetBreakpoints())
                breakpointList.Items.Add($"0x{bp.Address:X}  -  {bp.MethodName}", bp.IsActive);
        }

        // ========== Export ==========

        private void Export_Click(object sender, EventArgs e)
        {
            if (resultsList.Items.Count == 0)
            {
                Log("No results to export");
                return;
            }

            using (var sfd = new SaveFileDialog())
            {
                sfd.FileName = $"{processName}_strings.txt";
                sfd.Filter = "Text Files|*.txt|CSV|*.csv|All Files|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        using (var w = new StreamWriter(sfd.FileName))
                        {
                            w.WriteLine("// KsDumper - String Decryption Results");
                            w.WriteLine($"// Process: {processName} (PID: {processId})");
                            w.WriteLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                            w.WriteLine($"// Total: {resultsList.Items.Count} strings");
                            w.WriteLine();
                            w.WriteLine("// [ADDRESS] [METHOD] [CATEGORY] [SOURCE] VALUE");

                            foreach (ListViewItem item in resultsList.Items)
                            {
                                string escaped = item.SubItems[1].Text.Replace("\\", "\\\\").Replace("\"", "\\\"");
                                w.WriteLine($"[{item.Text}] [{item.SubItems[2].Text}] [{item.SubItems[3].Text}] [{item.SubItems[4].Text}] \"{escaped}\"");
                            }
                        }
                        Log("Exported {0} results to {1}", resultsList.Items.Count, sfd.FileName);
                    }
                    catch (Exception ex) { Log("Export error: {0}", ex.Message); }
                }
            }
        }

        // ========== Helpers ==========

        private void AddResult(ulong address, string value, string method, string category, string source)
        {
            string displayValue = value.Length > 200 ? value.Substring(0, 200) + "..." : value;
            var lvi = new ListViewItem($"0x{address:X}");
            lvi.SubItems.Add(displayValue);
            lvi.SubItems.Add(method);
            lvi.SubItems.Add(category);
            lvi.SubItems.Add(source);

            if (category == "URL") lvi.ForeColor = DarkTheme.Accent;
            else if (category == "File Path") lvi.ForeColor = DarkTheme.Warning;
            else if (category == "Error Message") lvi.ForeColor = DarkTheme.Error;
            else if (category == "Pattern") lvi.ForeColor = DarkTheme.TextMuted;

            resultsList.Items.Add(lvi);
        }

        private void Log(string message, params object[] args)
        {
            this.SafeInvoke(() =>
            {
                logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n");
            });
        }

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private TextBox CreateTextBox(int width)
        {
            return new TextBox
            {
                Width = width, Margin = new Padding(2, 0, 4, 0),
                BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary,
                BorderStyle = BorderStyle.FixedSingle, Font = DarkTheme.UIMonoFont
            };
        }

        private Label MakeLabel(string text)
        {
            return new Label
            {
                Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0),
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont
            };
        }

        private ListView CreateListView()
        {
            return new ListView
            {
                View = View.Details, FullRowSelect = true,
                MultiSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont
            };
        }
    }
}
