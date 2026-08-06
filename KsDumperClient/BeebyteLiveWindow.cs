using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class BeebyteLiveWindow : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;
        private readonly ulong gameAssemblyBase;
        private readonly uint gameAssemblySize;

        private ListView nameList;
        private RichTextBox logBox;
        private Button scanBtn;
        private Button exportBtn;
        private Button exportIdaBtn;
        private ComboBox filterCombo;
        private TextBox searchBox;
        private Label statsLbl;
        private Label statusLbl;
        private ProgressBar progressBar;
        private CheckBox autoRefreshCheck;
        private NumericUpDown intervalBox;

        private CancellationTokenSource cts;
        private bool isScanning;
        private BeebyteDumper.RecoveryResult lastResult;
        private Il2CppDumper.Il2CppMetadataSnapshot lastSnapshot;
        private readonly List<NameRow> allRows = new List<NameRow>();

        private static readonly Color ColorObfuscated = Color.FromArgb(60, 20, 20);
        private static readonly Color ColorRecovered = Color.FromArgb(20, 50, 20);
        private static readonly Color ColorObfuscatedText = Color.FromArgb(255, 120, 120);
        private static readonly Color ColorRecoveredText = Color.FromArgb(120, 255, 120);
        private static readonly Color ColorUnchanged = Color.FromArgb(35, 40, 48);
        private static readonly Color ColorUnchangedText = Color.FromArgb(160, 160, 160);
        private static readonly Color ColorMethodBg = Color.FromArgb(15, 45, 15);
        private static readonly Color ColorFieldBg = Color.FromArgb(15, 15, 45);

        private struct NameRow
        {
            public string Kind;       // "Type", "Method", "Field"
            public string Namespace;
            public string Obfuscated;
            public string Recovered;
            public uint Token;
            public bool IsRecovered;
        }

        public BeebyteLiveWindow(IMemoryReader driver, int processId, string processName, ulong gaBase, uint gaSize)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            this.gameAssemblyBase = gaBase;
            this.gameAssemblySize = gaSize;
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"Beebyte Live Recovery - {processName} (PID: {processId})";
            Size = new Size(1200, 750);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(900, 500);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(8) };

            int y1 = 8;
            scanBtn = MakeButton("Scan Now", 90);
            scanBtn.Location = new Point(8, y1);
            scanBtn.Click += Scan_Click;

            exportBtn = MakeButton("Export Map...", 100);
            exportBtn.Location = new Point(104, y1);
            exportBtn.Enabled = false;
            exportBtn.Click += Export_Click;

            exportIdaBtn = MakeButton("Export IDA Script...", 130);
            exportIdaBtn.Location = new Point(210, y1);
            exportIdaBtn.Enabled = false;
            exportIdaBtn.Click += ExportIda_Click;

            int y2 = 42;
            var filterLbl = new Label { Text = "Filter:", Location = new Point(8, y2 + 3), AutoSize = true, ForeColor = DarkTheme.TextMuted };
            filterCombo = new ComboBox
            {
                Location = new Point(50, y2),
                Width = 100,
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary
            };
            filterCombo.Items.AddRange(new object[] { "All", "Types", "Methods", "Fields", "Recovered", "Obfuscated" });
            filterCombo.SelectedIndex = 0;
            filterCombo.SelectedIndexChanged += (s, e) => ApplyFilter();

            var searchLbl = new Label { Text = "Search:", Location = new Point(160, y2 + 3), AutoSize = true, ForeColor = DarkTheme.TextMuted };
            searchBox = new TextBox
            {
                Location = new Point(210, y2),
                Width = 200,
                BackColor = DarkTheme.SurfaceElevated,
                ForeColor = DarkTheme.TextPrimary
            };
            searchBox.TextChanged += (s, e) => ApplyFilter();

            autoRefreshCheck = new CheckBox
            {
                Text = "Auto-refresh",
                Location = new Point(430, y2 + 2),
                AutoSize = true,
                ForeColor = DarkTheme.TextMuted,
                Checked = false
            };

            var intervalLbl = new Label { Text = "every", Location = new Point(530, y2 + 3), AutoSize = true, ForeColor = DarkTheme.TextMuted };
            intervalBox = new NumericUpDown
            {
                Location = new Point(565, y2),
                Width = 50,
                Minimum = 3,
                Maximum = 120,
                Value = 10,
                BackColor = DarkTheme.SurfaceElevated,
                ForeColor = DarkTheme.TextPrimary
            };
            var secLbl = new Label { Text = "sec", Location = new Point(618, y2 + 3), AutoSize = true, ForeColor = DarkTheme.TextMuted };

            statsLbl = new Label { Text = "Ready", Location = new Point(660, y2 + 3), AutoSize = true, ForeColor = DarkTheme.Accent };

            toolbar.Controls.AddRange(new Control[] {
                scanBtn, exportBtn, exportIdaBtn,
                filterLbl, filterCombo, searchLbl, searchBox,
                autoRefreshCheck, intervalLbl, intervalBox, secLbl, statsLbl
            });

            // Status bar
            var statusBar = new Panel { Dock = DockStyle.Bottom, Height = 28, BackColor = DarkTheme.Surface };
            statusLbl = new Label { Text = "Idle", Dock = DockStyle.Left, AutoSize = true, ForeColor = DarkTheme.TextMuted, Padding = new Padding(8, 6, 0, 0) };
            progressBar = new ProgressBar { Dock = DockStyle.Right, Width = 200, Style = ProgressBarStyle.Marquee, Visible = false, MarqueeAnimationSpeed = 30 };
            statusBar.Controls.AddRange(new Control[] { statusLbl, progressBar });

            // Split panel: ListView top, log bottom
            var splitter = new SplitContainer
            {
                Dock = DockStyle.Fill,
                Orientation = Orientation.Horizontal,
                SplitterDistance = 480,
                BackColor = DarkTheme.Background
            };

            nameList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = false,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIMonoFont,
                OwnerDraw = true,
                HeaderStyle = ColumnHeaderStyle.Nonclickable,
                BorderStyle = BorderStyle.None
            };
            nameList.Columns.Add("Kind", 60);
            nameList.Columns.Add("Status", 70);
            nameList.Columns.Add("Namespace", 180);
            nameList.Columns.Add("Obfuscated Name", 220);
            nameList.Columns.Add("Recovered Name", 260);
            nameList.Columns.Add("Token", 90);
            nameList.DrawColumnHeader += NameList_DrawColumnHeader;
            nameList.DrawSubItem += NameList_DrawSubItem;

            logBox = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIMonoFont,
                WordWrap = false,
                BorderStyle = BorderStyle.None
            };

            splitter.Panel1.Controls.Add(nameList);
            splitter.Panel2.Controls.Add(logBox);

            Controls.Add(splitter);
            Controls.Add(toolbar);
            Controls.Add(statusBar);

            DarkTheme.ApplyTo(this);
        }

        private Button MakeButton(string text, int width)
        {
            return new Button
            {
                Text = text,
                Width = width,
                Height = 26,
                FlatStyle = FlatStyle.Flat,
                BackColor = DarkTheme.SurfaceElevated,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont,
                Cursor = Cursors.Hand
            };
        }

        private void NameList_DrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            e.Graphics.FillRectangle(new SolidBrush(DarkTheme.SurfaceElevated), e.Bounds);
            TextRenderer.DrawText(e.Graphics, e.Header.Text, DarkTheme.UIFontBold, e.Bounds, DarkTheme.TextPrimary,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine);
        }

        private void NameList_DrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            if (e.Item == null) return;

            string kind = e.Item.SubItems[0].Text;
            string status = e.Item.SubItems[1].Text;
            bool isRecovered = status == "OK";
            bool isObfuscated = status == "???";

            Color bgColor;
            Color textColor;

            if (e.ColumnIndex == 3) // Obfuscated Name column
            {
                bgColor = isRecovered ? ColorObfuscated : ColorUnchanged;
                textColor = isRecovered ? ColorObfuscatedText : ColorUnchangedText;
            }
            else if (e.ColumnIndex == 4) // Recovered Name column
            {
                bgColor = isRecovered ? ColorRecovered : ColorUnchanged;
                textColor = isRecovered ? ColorRecoveredText : ColorUnchangedText;
            }
            else if (e.ColumnIndex == 1) // Status column
            {
                bgColor = isRecovered ? ColorRecovered : (isObfuscated ? ColorObfuscated : ColorUnchanged);
                textColor = isRecovered ? ColorRecoveredText : (isObfuscated ? ColorObfuscatedText : ColorUnchangedText);
            }
            else
            {
                bgColor = DarkTheme.Surface;
                textColor = DarkTheme.TextPrimary;

                if (kind == "  Method")
                {
                    bgColor = isRecovered ? Color.FromArgb(15, 45, 15) : Color.FromArgb(30, 34, 40);
                    textColor = Color.FromArgb(180, 200, 180);
                }
                else if (kind == "  Field")
                {
                    bgColor = isRecovered ? Color.FromArgb(15, 15, 45) : Color.FromArgb(30, 34, 40);
                    textColor = Color.FromArgb(180, 180, 200);
                }
            }

            // Selected row highlight
            if (e.Item.Selected)
            {
                bgColor = DarkTheme.AccentSubtle;
                textColor = Color.White;
            }

            using (var brush = new SolidBrush(bgColor))
                e.Graphics.FillRectangle(brush, e.Bounds);

            var textBounds = new Rectangle(e.Bounds.X + 4, e.Bounds.Y, e.Bounds.Width - 4, e.Bounds.Height);
            TextRenderer.DrawText(e.Graphics, e.SubItem.Text, nameList.Font, textBounds, textColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.SingleLine | TextFormatFlags.EndEllipsis);
        }

        private async void Scan_Click(object sender, EventArgs e)
        {
            if (isScanning) return;
            await RunScan();

            if (autoRefreshCheck.Checked)
            {
                cts = new CancellationTokenSource();
                _ = AutoRefreshLoop(cts.Token);
            }
        }

        private async Task AutoRefreshLoop(CancellationToken token)
        {
            while (!token.IsCancellationRequested && autoRefreshCheck.Checked)
            {
                int interval = (int)intervalBox.Value * 1000;
                try { await Task.Delay(interval, token); }
                catch (TaskCanceledException) { break; }

                if (!token.IsCancellationRequested && autoRefreshCheck.Checked)
                    await RunScan();
            }
        }

        private async Task RunScan()
        {
            isScanning = true;
            scanBtn.Enabled = false;
            progressBar.Visible = true;
            statusLbl.Text = "Reading IL2CPP metadata...";
            LogLine("Starting Beebyte recovery scan...", DarkTheme.Accent);

            await Task.Run(() =>
            {
                try
                {
                    // Step 1: Read metadata
                    this.SafeInvoke(new Action(() => statusLbl.Text = "Reading metadata..."));
                    var result = driver.ReadIl2CppMetadata(processId);
                    if (result.metadata == null || !Il2CppDumper.ValidateMagic(result.metadata))
                    {
                        this.SafeInvoke(new Action(() =>
                        {
                            LogLine("IL2CPP metadata not found in process memory", Color.FromArgb(255, 100, 100));
                            statusLbl.Text = "Metadata not found";
                        }));
                        return;
                    }

                    // Step 2: Parse
                    this.SafeInvoke(new Action(() => statusLbl.Text = "Parsing metadata..."));
                    var snapshot = Il2CppDumper.ParseFullMetadata(result.metadata);
                    if (snapshot == null || snapshot.TypeDefinitions.Length == 0)
                    {
                        this.SafeInvoke(new Action(() =>
                        {
                            LogLine("Failed to parse IL2CPP metadata", Color.FromArgb(255, 100, 100));
                            statusLbl.Text = "Parse failed";
                        }));
                        return;
                    }

                    this.SafeInvoke(new Action(() =>
                    {
                        LogLine($"Parsed {snapshot.TypeDefinitions.Length} types, {snapshot.Methods.Length} methods", DarkTheme.TextPrimary);
                        statusLbl.Text = "Scanning for runtime classes...";
                    }));

                    // Step 3: Beebyte recovery
                    var recovery = BeebyteDumper.RecoverNames(
                        driver, processId, gameAssemblyBase, gameAssemblySize, snapshot,
                        msg => this.SafeInvoke(new Action(() => LogLine("  " + msg, DarkTheme.TextMuted))));

                    lastResult = recovery;
                    lastSnapshot = snapshot;

                    // Step 4: Build row data
                    var rows = BuildRows(snapshot, recovery);

                    this.SafeInvoke(new Action(() =>
                    {
                        allRows.Clear();
                        allRows.AddRange(rows);
                        ApplyFilter();

                        exportBtn.Enabled = recovery.RecoveredTypes > 0;
                        exportIdaBtn.Enabled = recovery.RecoveredTypes > 0;

                        string statusText = recovery.IsObfuscated
                            ? $"Recovered {recovery.RecoveredTypes}/{recovery.TotalTypes} types, {recovery.RecoveredMethods} methods, {recovery.RecoveredFields} fields"
                            : "No Beebyte obfuscation detected";
                        statsLbl.Text = statusText;
                        statusLbl.Text = "Scan complete";

                        Color logColor = recovery.IsObfuscated && recovery.RecoveredTypes > 0
                            ? Color.FromArgb(120, 255, 120)
                            : (recovery.IsObfuscated ? Color.FromArgb(255, 180, 50) : DarkTheme.Accent);
                        LogLine(statusText, logColor);
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() =>
                    {
                        LogLine($"Error: {ex.Message}", Color.FromArgb(255, 100, 100));
                        statusLbl.Text = "Error";
                    }));
                }
            });

            isScanning = false;
            scanBtn.Enabled = true;
            progressBar.Visible = false;
        }

        private List<NameRow> BuildRows(Il2CppDumper.Il2CppMetadataSnapshot snapshot, BeebyteDumper.RecoveryResult recovery)
        {
            var rows = new List<NameRow>();
            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            var recoveryMap = new Dictionary<int, BeebyteDumper.RecoveredName>();
            foreach (var r in recovery.Names)
                recoveryMap[r.TypeIndex] = r;

            for (int i = 0; i < snapshot.TypeDefinitions.Length; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                string metaName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);
                string metaNs = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);

                if (string.IsNullOrEmpty(metaName) || metaName == "<Module>") continue;

                BeebyteDumper.RecoveredName rec;
                bool hasRecovery = recoveryMap.TryGetValue(i, out rec);

                rows.Add(new NameRow
                {
                    Kind = "Type",
                    Namespace = metaNs ?? "",
                    Obfuscated = metaName,
                    Recovered = hasRecovery ? rec.RealName : metaName,
                    Token = td.Token,
                    IsRecovered = hasRecovery
                });

                // Add methods under this type
                if (hasRecovery && rec.Methods != null)
                {
                    foreach (var m in rec.Methods)
                    {
                        rows.Add(new NameRow
                        {
                            Kind = "  Method",
                            Namespace = "",
                            Obfuscated = m.ObfuscatedName,
                            Recovered = m.RealName,
                            Token = m.Token,
                            IsRecovered = true
                        });
                    }
                }
                else if (td.MethodStart >= 0 && td.MethodCount > 0 && !hasRecovery)
                {
                    int end = Math.Min(td.MethodStart + td.MethodCount, snapshot.Methods.Length);
                    for (int mi = td.MethodStart; mi < end; mi++)
                    {
                        string methodName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)snapshot.Methods[mi].NameIndex);
                        rows.Add(new NameRow
                        {
                            Kind = "  Method",
                            Namespace = "",
                            Obfuscated = methodName ?? "",
                            Recovered = methodName ?? "",
                            Token = snapshot.Methods[mi].Token,
                            IsRecovered = false
                        });
                    }
                }

                // Add fields under this type
                if (hasRecovery && rec.Fields != null)
                {
                    foreach (var f in rec.Fields)
                    {
                        rows.Add(new NameRow
                        {
                            Kind = "  Field",
                            Namespace = "",
                            Obfuscated = f.ObfuscatedName,
                            Recovered = f.RealName,
                            Token = f.Token,
                            IsRecovered = true
                        });
                    }
                }
            }

            return rows;
        }

        private void ApplyFilter()
        {
            nameList.BeginUpdate();
            nameList.Items.Clear();

            string filter = filterCombo.SelectedItem?.ToString() ?? "All";
            string search = searchBox.Text.Trim();
            bool hasSearch = search.Length > 0;

            foreach (var row in allRows)
            {
                // Filter by kind
                if (filter == "Types" && row.Kind.Trim() != "Type") continue;
                if (filter == "Methods" && row.Kind.Trim() != "Method") continue;
                if (filter == "Fields" && row.Kind.Trim() != "Field") continue;
                if (filter == "Recovered" && !row.IsRecovered) continue;
                if (filter == "Obfuscated" && row.IsRecovered) continue;

                // Search filter
                if (hasSearch)
                {
                    bool match = row.Obfuscated.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 row.Recovered.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0 ||
                                 row.Namespace.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;
                    if (!match) continue;
                }

                string status = row.IsRecovered ? "OK" : (row.Kind.Trim() == "Type" ? "???" : "");
                var item = new ListViewItem(new string[]
                {
                    row.Kind,
                    status,
                    row.Namespace,
                    row.Obfuscated,
                    row.Recovered,
                    $"0x{row.Token:X8}"
                });
                nameList.Items.Add(item);
            }

            nameList.EndUpdate();
        }

        private void Export_Click(object sender, EventArgs e)
        {
            if (lastResult == null || lastResult.RecoveredTypes == 0) return;

            using (var sfd = new SaveFileDialog())
            {
                sfd.FileName = $"{processName}_beebyte_map.txt";
                sfd.Filter = "Text files|*.txt|All files|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    BeebyteDumper.SaveMapping(sfd.FileName, lastResult, processName);
                    LogLine($"Map saved: {sfd.FileName}", Color.FromArgb(120, 255, 120));

                    if (lastSnapshot != null)
                    {
                        string sdkPath = Path.ChangeExtension(sfd.FileName, ".cs");
                        string sdk = BeebyteDumper.GenerateDeobfuscatedSdk(lastSnapshot, lastResult);
                        File.WriteAllText(sdkPath, sdk, Encoding.UTF8);
                        LogLine($"Deobfuscated SDK saved: {sdkPath}", Color.FromArgb(120, 255, 120));
                    }
                }
            }
        }

        private void ExportIda_Click(object sender, EventArgs e)
        {
            if (lastResult == null || lastResult.RecoveredTypes == 0) return;

            using (var sfd = new SaveFileDialog())
            {
                sfd.FileName = $"{processName}_beebyte_ida.py";
                sfd.Filter = "Python scripts|*.py|All files|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    BeebyteDumper.SaveIdaScript(sfd.FileName, lastResult);
                    LogLine($"IDA script saved: {sfd.FileName}", Color.FromArgb(120, 255, 120));
                }
            }
        }

        private void LogLine(string text, Color color)
        {
            if (logBox.InvokeRequired) { this.SafeInvoke(new Action(() => LogLine(text, color))); return; }

            logBox.SelectionStart = logBox.TextLength;
            logBox.SelectionColor = color;
            logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {text}\n");
            logBox.ScrollToCaret();
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            cts?.Cancel();
            base.OnFormClosing(e);
        }
    }
}
