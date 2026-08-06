using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.PE;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class ModuleSelectionDialog : Form
    {
        private readonly IMemoryReader driver;
        private readonly ProcessSummary processSummary;
        private readonly ProcessDumper dumper;

        private ListView moduleList;
        private Button dumpSelectedBtn;
        private Button dumpAllBtn;
        private Button dumpGameBtn;
        private Button dumpStringsBtn;
        private Button toolsBtn;
        private ContextMenuStrip toolsMenu;
        private ToolStripButton refreshBtn;
        private ToolStripButton unprotectBtn;
        private ToolStripButton suspendBtn;
        private bool processSuspended;
        private ToolStripButton waitIATCheckBox;
        private ToolStripButton rebuildImportsCheckBox;
        private NumericUpDown waitSecondsUpDown;
        private Label statusLabel;
        private ProgressBar progressBar;
        private RichTextBox logTextBox;
        private ComboBox acComboBox;
        private Button suspendACBtn;
        private Button resumeACBtn;
        private Button bypassACBtn;
        private Button dumpUnityBtn;
        private Button loadUnityBtn;
        private Label unityStatusLabel;
        private bool isUnityIl2Cpp;
        private bool isUnityMono;
        private Button dumpMonoBtn;
        private UnityReference gameAssemblyRef;
        private UnityReference unityPlayerRef;
        private ContextMenuStrip moduleContextMenu;

        public ModuleSelectionDialog(IMemoryReader driver, ProcessSummary processSummary)
        {
            this.driver = driver;
            this.processSummary = processSummary;
            this.dumper = new ProcessDumper(driver);
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"Modules - {processSummary.ProcessName} (PID: {processSummary.ProcessId})";
            Size = new Size(960, 700);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimumSize = new Size(750, 550);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            Padding = Padding.Empty;
            try { this.Icon = Utility.AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new ToolStrip();
            toolbar.AutoSize = false;
            toolbar.Height = 36;
            toolbar.GripStyle = ToolStripGripStyle.Hidden;
            toolbar.Padding = new Padding(8, 4, 8, 4);

            refreshBtn = new ToolStripButton("  Refresh  ") { DisplayStyle = ToolStripItemDisplayStyle.Text, Margin = new Padding(0, 1, 4, 2) };
            refreshBtn.Click += RefreshBtn_Click;
            toolbar.Items.Add(refreshBtn);

            unprotectBtn = new ToolStripButton("  Unprotect Process  ") { DisplayStyle = ToolStripItemDisplayStyle.Text, Margin = new Padding(0, 1, 4, 2) };
            unprotectBtn.Click += UnprotectBtn_Click;
            toolbar.Items.Add(unprotectBtn);

            suspendBtn = new ToolStripButton("  Suspend Process  ") { DisplayStyle = ToolStripItemDisplayStyle.Text, Margin = new Padding(0, 1, 4, 2) };
            suspendBtn.Click += SuspendBtn_Click;
            toolbar.Items.Add(suspendBtn);

            toolbar.Items.Add(new ToolStripSeparator());

            waitIATCheckBox = new ToolStripButton("  Wait for IAT Init  ") { DisplayStyle = ToolStripItemDisplayStyle.Text, CheckOnClick = true, Margin = new Padding(0, 1, 4, 2) };
            toolbar.Items.Add(waitIATCheckBox);

            rebuildImportsCheckBox = new ToolStripButton("  Rebuild Imports  ") { DisplayStyle = ToolStripItemDisplayStyle.Text, CheckOnClick = true, Checked = true, Margin = new Padding(0, 1, 4, 2) };
            toolbar.Items.Add(rebuildImportsCheckBox);

            var waitLabel = new ToolStripLabel("Wait (s):") { ForeColor = DarkTheme.TextSecondary };
            toolbar.Items.Add(waitLabel);
            waitSecondsUpDown = new DarkNumericUpDown { Minimum = 0, Maximum = 60, Value = 3, Width = 55 };
            var waitHost = new ToolStripControlHost(waitSecondsUpDown);
            waitHost.Margin = new Padding(4, 4, 0, 4);
            waitHost.BackColor = DarkTheme.Surface;
            toolbar.Items.Add(waitHost);

            Controls.Add(toolbar);

            // Module list
            moduleList = new ListView
            {
                View = View.Details,
                FullRowSelect = true,
                MultiSelect = true,
                BorderStyle = BorderStyle.None,
                Location = new Point(8, 44),
                Size = new Size(928, 370),
                Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };
            moduleList.Columns.Add("Name", 190);
            moduleList.Columns.Add("Base Address", 125);
            moduleList.Columns.Add("Entry Point", 125);
            moduleList.Columns.Add("Image Size", 95);
            moduleList.Columns.Add("Path", 295);
            moduleList.Columns.Add("Status", 85);

            // Module right-click context menu
            moduleContextMenu = new ContextMenuStrip();
            moduleContextMenu.Items.Add("Dump Module", null, CtxDumpModule_Click);
            moduleContextMenu.Items.Add("Open File Location", null, CtxOpenFileLocation_Click);
            moduleContextMenu.Items.Add("Copy Base Address", null, CtxCopyBaseAddress_Click);
            moduleContextMenu.Items.Add("Copy Module Name", null, CtxCopyModuleName_Click);
            moduleContextMenu.Items.Add("Reveal Entry Point", null, CtxRevealEntryPoint_Click);
            moduleContextMenu.Items.Add(new ToolStripSeparator());
            moduleContextMenu.Items.Add("Analyze Module", null, CtxAnalyzeModule_Click);
            moduleContextMenu.Items.Add("Decrypt Strings", null, CtxDecryptStrings_Click);
            moduleContextMenu.Items.Add("String Scanner...", null, CtxStringScanner_Click);
            moduleContextMenu.Items.Add("List Windows", null, CtxListWindows_Click);
            moduleContextMenu.Items.Add("GDI Handle Count", null, CtxGdiCount_Click);
            moduleContextMenu.Items.Add("Generate Structures Header", null, CtxGenerateHeader_Click);
            moduleContextMenu.Items.Add(new ToolStripSeparator());
            moduleContextMenu.Items.Add("Show System Drivers", null, CtxShowSystemDrivers_Click);
            moduleContextMenu.Items.Add(new ToolStripSeparator());
            moduleContextMenu.Items.Add("PE Protection Bypass", null, CtxPEProtectionBypass_Click);
            var unloadMenuItem = moduleContextMenu.Items.Add("Unload Module", null, CtxUnloadModule_Click);
            moduleContextMenu.Items.Add(new ToolStripSeparator());
            var lsassMenuItem = moduleContextMenu.Items.Add("Stealth Dump via LSASS", null, CtxStealthDump_Click);
            moduleList.ContextMenuStrip = moduleContextMenu;

            if (!driver.IsKernelMode)
            {
                unloadMenuItem.Enabled = false;
                lsassMenuItem.Enabled = false;
            }

            Controls.Add(moduleList);

            // Buttons row
            var buttonPanel = new Panel
            {
                Location = new Point(8, 420),
                Size = new Size(1280, 38),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };

            dumpSelectedBtn = CreateButton("Dump Selected", 0, 120);
            dumpAllBtn = CreateButton("Dump All", 128, 95);
            dumpGameBtn = CreateButton("Dump Game Modules", 231, 150);
            dumpStringsBtn = CreateButton("Dump Strings", 389, 120);
            toolsBtn = CreateButton("Tools ▼", 517, 75);

            // Unity IL2CPP buttons (hidden until Unity detected)
            loadUnityBtn = CreateButton("Load Unity", 600, 95);
            loadUnityBtn.Enabled = false;
            loadUnityBtn.Visible = false;
            loadUnityBtn.Click += LoadUnityBtn_Click;

            dumpUnityBtn = CreateButton("Dump Unity", 703, 110);
            dumpUnityBtn.Enabled = false;
            dumpUnityBtn.Visible = false;
            dumpUnityBtn.Click += DumpUnityBtn_Click;

            dumpMonoBtn = CreateButton("Dump Mono", 703, 110);
            dumpMonoBtn.Enabled = false;
            dumpMonoBtn.Visible = false;
            dumpMonoBtn.Click += DumpMonoBtn_Click;

            unityStatusLabel = new Label { Text = "", Location = new Point(821, 8), AutoSize = true, ForeColor = DarkTheme.TextMuted, Visible = false };

            // Anti-cheat bypass controls
            var acLabel = new Label { Text = "Anti-Cheat:", Location = new Point(960, 8), AutoSize = true, ForeColor = DarkTheme.TextSecondary };
            acComboBox = new DarkComboBox
            {
                Location = new Point(1030, 5),
                Size = new Size(130, 24)
            };
            acComboBox.Items.Add("None");
            acComboBox.Items.Add("EasyAntiCheat");
            acComboBox.Items.Add("BattlEye");
            acComboBox.SelectedIndex = 0;

            suspendACBtn = CreateButton("Suspend AC", 1175, 85);
            resumeACBtn = CreateButton("Resume AC", 1270, 85);
            bypassACBtn = CreateButton("Full Bypass", 1365, 85);

            suspendACBtn.Click += SuspendACBtn_Click;
            resumeACBtn.Click += ResumeACBtn_Click;
            bypassACBtn.Click += BypassACBtn_Click;

            statusLabel = new Label { Location = new Point(1460, 8), Size = new Size(200, 24), AutoSize = false, ForeColor = DarkTheme.TextSecondary };

            dumpSelectedBtn.Click += DumpSelectedBtn_Click;
            dumpAllBtn.Click += DumpAllBtn_Click;
            dumpGameBtn.Click += DumpGameBtn_Click;
            dumpStringsBtn.Click += DumpStringsBtn_Click;
            toolsBtn.Click += ToolsBtn_Click;

            // Tools dropdown menu
            toolsMenu = new ContextMenuStrip();
            toolsMenu.Items.Add("Memory Map", null, ToolMemoryMap_Click);
            toolsMenu.Items.Add("Il2Cpp Metadata", null, ToolIl2CppMetadata_Click);
            toolsMenu.Items.Add("String Xrefs", null, ToolStringXrefs_Click);
            toolsMenu.Items.Add("String Dedup Report", null, ToolStringDedup_Click);
            toolsMenu.Items.Add(new ToolStripSeparator());
            toolsMenu.Items.Add("Beebyte Recovery", null, ToolBeebyteRecovery_Click);
            toolsMenu.Items.Add("Detect Engine", null, ToolDetectEngine_Click);
            toolsMenu.Items.Add("Compare PE...", null, ToolComparePE_Click);

            buttonPanel.Controls.AddRange(new Control[] { dumpSelectedBtn, dumpAllBtn, dumpGameBtn, dumpStringsBtn, toolsBtn, loadUnityBtn, dumpUnityBtn, dumpMonoBtn, unityStatusLabel, acLabel, acComboBox, suspendACBtn, resumeACBtn, bypassACBtn, statusLabel });
            Controls.Add(buttonPanel);

            // Progress bar
            progressBar = new ProgressBar
            {
                Location = new Point(8, 464),
                Size = new Size(928, 6),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right,
                Visible = false,
                Style = ProgressBarStyle.Continuous
            };
            Controls.Add(progressBar);

            // Log panel
            var logPanel = new Panel
            {
                Location = new Point(8, 478),
                Size = new Size(928, 175),
                Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right
            };

            var logHeaderLabel = new Label
            {
                Text = "   Output Log",
                Dock = DockStyle.Top,
                Height = 26,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = DarkTheme.TextSecondary,
                Font = DarkTheme.UIFontBold
            };

            logTextBox = new RichTextBox
            {
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };

            logPanel.Controls.Add(logTextBox);
            logPanel.Controls.Add(logHeaderLabel);
            Controls.Add(logPanel);

            // Disable kernel-only features in usermode
            if (!driver.IsKernelMode)
            {
                unprotectBtn.Enabled = false;
                unprotectBtn.ToolTipText = "Requires kernel driver";
                suspendBtn.Enabled = false;
                suspendBtn.ToolTipText = "Requires kernel driver";
                suspendACBtn.Enabled = false;
                resumeACBtn.Enabled = false;
                bypassACBtn.Enabled = false;
            }

            DarkTheme.ApplyTo(this);

            // toolsMenu is not attached to a control, so ApplyToControls missed it
            toolsMenu.Renderer = new DarkToolStripRenderer();
            toolsMenu.BackColor = DarkTheme.Surface;
            toolsMenu.ForeColor = DarkTheme.TextPrimary;
            foreach (ToolStripItem item in toolsMenu.Items)
                item.ForeColor = DarkTheme.TextPrimary;

            Load += ModuleSelectionDialog_Load;

            // Auto-expand last column to fill available width
            void ResizeModuleListLastCol()
            {
                if (moduleList.Columns.Count == 0) return;
                moduleList.Columns[moduleList.Columns.Count - 1].Width = -2;
            }
            moduleList.Resize += (s, ev) => ResizeModuleListLastCol();
            Load += (s, ev) => ResizeModuleListLastCol();
        }

        private Button CreateButton(string text, int x, int width)
        {
            var btn = new Button
            {
                Text = text,
                Location = new Point(x, 0),
                Size = new Size(width, 34)
            };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private void ModuleSelectionDialog_Load(object sender, EventArgs e)
        {
            LoadModuleList();
        }

        private void LoadModuleList()
        {
            moduleList.Items.Clear();
            statusLabel.Text = "Loading modules...";

            Task.Run(() =>
            {
                if (driver.GetModuleSummaryList(processSummary.ProcessId, out ModuleSummary[] modules))
                {
                    this.SafeInvoke(() =>
                    {
                        foreach (var mod in modules)
                        {
                            var lvi = new ListViewItem(mod.ModuleName);
                            lvi.SubItems.Add($"0x{mod.BaseAddress:x}");
                            lvi.SubItems.Add(mod.EntryPoint > 0 ? $"0x{mod.EntryPoint:x}" : "(hidden)");
                            lvi.SubItems.Add($"0x{mod.ImageSize:x}");
                            lvi.SubItems.Add(mod.FileName ?? "(no path - manually mapped)");
                            lvi.SubItems.Add(mod.IsHidden ? "HIDDEN" : "Normal");
                            lvi.Tag = mod;

                            if (mod.IsHidden)
                            {
                                lvi.ForeColor = DarkTheme.HiddenModule;
                                lvi.Font = new Font(moduleList.Font, FontStyle.Bold);
                            }
                            else if (string.IsNullOrEmpty(mod.FileName))
                            {
                                lvi.ForeColor = DarkTheme.NoPathModule;
                            }

                            moduleList.Items.Add(lvi);
                        }

                        int hiddenCount = 0;
                        foreach (var mod in modules)
                            if (mod.IsHidden) hiddenCount++;

                        statusLabel.Text = $"{modules.Length} modules loaded ({hiddenCount} hidden)";
                        Log("Found {0} modules ({1} hidden/manual-mapped)", modules.Length, hiddenCount);

                        // Auto-recover entry points for modules showing "(hidden)"
                        RecoverEntryPointsAsync(modules);

                        // Detect packed/protected modules via entropy analysis
                        DetectPackedModulesAsync(modules);

                        // Auto-detect Unity IL2CPP
                        var detection = EngineDetector.Detect(modules);
                        if (EngineDetector.IsUnityIl2Cpp(detection))
                        {
                            isUnityIl2Cpp = true;
                            loadUnityBtn.Enabled = true;
                            loadUnityBtn.Visible = true;
                            dumpUnityBtn.Enabled = true;
                            dumpUnityBtn.Visible = true;
                            unityStatusLabel.Visible = true;
                            unityStatusLabel.Text = "Unity IL2CPP";
                            unityStatusLabel.ForeColor = DarkTheme.Success;
                            Log("Unity IL2CPP detected via: {0}", string.Join(", ", detection.IndicatorModules));
                            Log("  Use 'Load Unity' to select on-disk DLLs for decrypted section comparison");
                        }
                        else if (EngineDetector.IsUnityMono(detection))
                        {
                            isUnityMono = true;
                            dumpMonoBtn.Enabled = true;
                            dumpMonoBtn.Visible = true;
                            unityStatusLabel.Visible = true;
                            unityStatusLabel.Text = "Unity Mono";
                            unityStatusLabel.ForeColor = DarkTheme.Success;
                            Log("Unity Mono detected via: {0}", string.Join(", ", detection.IndicatorModules));
                            Log("  Use 'Dump Mono' to extract managed assemblies and generate SDK");
                        }
                    });
                }
                else
                {
                    this.SafeInvoke(() => statusLabel.Text = "Failed to load modules");
                }
            });
        }

        private void RefreshBtn_Click(object sender, EventArgs e)
        {
            LoadModuleList();
        }

        private void UnprotectBtn_Click(object sender, EventArgs e)
        {
            unprotectBtn.Enabled = false;
            Task.Run(() =>
            {
                int status = driver.UnprotectProcess(processSummary.ProcessId);
                this.SafeInvoke(() =>
                {
                    unprotectBtn.Enabled = true;
                    switch (status)
                    {
                        case 0:
                            Log("Process unprotected successfully (PPL cleared, ObCallbacks removed)");
                            statusLabel.Text = "Process unprotected";
                            break;
                        case 1:
                            Log("Process unprotected (PPL was not set, ObCallbacks removed)");
                            statusLabel.Text = "Process unprotected (no PPL)";
                            break;
                        case 2:
                            Log("Unprotect failed: could not attach to process");
                            statusLabel.Text = "Unprotect failed";
                            break;
                        case -1:
                            Log("Unprotect failed: driver communication error");
                            statusLabel.Text = "Driver error";
                            break;
                        default:
                            Log("Unprotect returned status: {0}", status);
                            break;
                    }
                });
            });
        }

        private void SuspendBtn_Click(object sender, EventArgs e)
        {
            suspendBtn.Enabled = false;
            Task.Run(() =>
            {
                if (!processSuspended)
                {
                    int count = driver.SuspendProcess(processSummary.ProcessId);
                    this.SafeInvoke(() =>
                    {
                        suspendBtn.Enabled = true;
                        if (count >= 0)
                        {
                            processSuspended = true;
                            suspendBtn.Text = "Resume Process";
                            Log("Suspended {0} threads", count);
                            statusLabel.Text = $"{count} threads suspended";
                        }
                        else
                        {
                            Log("Suspend failed: driver communication error");
                            statusLabel.Text = "Suspend failed";
                        }
                    });
                }
                else
                {
                    int count = driver.ResumeProcess(processSummary.ProcessId);
                    this.SafeInvoke(() =>
                    {
                        suspendBtn.Enabled = true;
                        if (count >= 0)
                        {
                            processSuspended = false;
                            suspendBtn.Text = "Suspend Process";
                            Log("Resumed {0} threads", count);
                            statusLabel.Text = $"{count} threads resumed";
                        }
                        else
                        {
                            Log("Resume failed: driver communication error");
                            statusLabel.Text = "Resume failed";
                        }
                    });
                }
            });
        }

        private async void DumpSelectedBtn_Click(object sender, EventArgs e)
        {
            if (moduleList.SelectedItems.Count == 0) return;

            var selected = new ModuleSummary[moduleList.SelectedItems.Count];
            for (int i = 0; i < moduleList.SelectedItems.Count; i++)
                selected[i] = (ModuleSummary)moduleList.SelectedItems[i].Tag;

            await DumpModules(selected);
        }

        private async void DumpAllBtn_Click(object sender, EventArgs e)
        {
            var all = new ModuleSummary[moduleList.Items.Count];
            for (int i = 0; i < moduleList.Items.Count; i++)
                all[i] = (ModuleSummary)moduleList.Items[i].Tag;

            await DumpModules(all);
        }

        private async void DumpGameBtn_Click(object sender, EventArgs e)
        {
            var gameModules = new List<ModuleSummary>();
            for (int i = 0; i < moduleList.Items.Count; i++)
            {
                var mod = (ModuleSummary)moduleList.Items[i].Tag;
                if (SystemDllFilter.IsGameModule(mod))
                    gameModules.Add(mod);
            }

            if (gameModules.Count == 0)
            {
                statusLabel.Text = "No game modules found";
                return;
            }

            Log("Filtering: {0} game modules out of {1} total", gameModules.Count, moduleList.Items.Count);
            await DumpModules(gameModules.ToArray());
        }

        private async void DumpStringsBtn_Click(object sender, EventArgs e)
        {
            dumpStringsBtn.Enabled = false;
            statusLabel.Text = "Scanning process memory for strings...";
            Log("Scanning process memory for decrypted strings (min length: 4)...");

            string savePath = null;
            using (var sfd = new SaveFileDialog())
            {
                sfd.FileName = $"{Path.GetFileNameWithoutExtension(processSummary.ProcessName)}_strings.txt";
                sfd.Filter = "Text Files|*.txt|All Files|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                    savePath = sfd.FileName;
            }

            if (string.IsNullOrEmpty(savePath))
            {
                dumpStringsBtn.Enabled = true;
                return;
            }

            await Task.Run(() =>
            {
                try
                {
                    var strings = driver.DumpLiveStrings(processSummary.ProcessId, minStringLength: 4);

                    if (strings.Count > 0)
                    {
                        using (var writer = new StreamWriter(savePath))
                        {
                            writer.WriteLine($"// KsDumper - Live Process String Dump");
                            writer.WriteLine($"// Process: {processSummary.ProcessName} (PID: {processSummary.ProcessId})");
                            writer.WriteLine($"// Total strings: {strings.Count}");
                            writer.WriteLine($"// Format: [ADDRESS] [TYPE] VALUE");
                            writer.WriteLine();

                            foreach (var (address, isUnicode, value) in strings)
                            {
                                string type = isUnicode ? "U" : "A";
                                // Escape newlines/tabs for readability
                                string escaped = value.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
                                writer.WriteLine($"[0x{address:x}] [{type}] {escaped}");
                            }
                        }

                        int asciiCount = 0, unicodeCount = 0;
                        foreach (var (_, isUnicode, _) in strings)
                        {
                            if (isUnicode) unicodeCount++; else asciiCount++;
                        }

                        this.SafeInvoke(new Action(() =>
                        {
                            Log("Dumped {0} strings ({1} ASCII, {2} Unicode)", strings.Count, asciiCount, unicodeCount);
                            Log("Saved to: {0}", savePath);
                            statusLabel.Text = $"Dumped {strings.Count} strings";
                        }));
                    }
                    else
                    {
                        this.SafeInvoke(new Action(() =>
                        {
                            Log("No strings found in process memory");
                            statusLabel.Text = "No strings found";
                        }));
                    }
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() =>
                    {
                        Log("String dump error: {0}", ex.Message);
                        statusLabel.Text = "String dump failed";
                    }));
                }
            });

            dumpStringsBtn.Enabled = true;
        }

        private void ToolsBtn_Click(object sender, EventArgs e)
        {
            toolsMenu.Show(toolsBtn, new Point(0, toolsBtn.Height));
        }

        private async void ToolMemoryMap_Click(object sender, EventArgs e)
        {
            statusLabel.Text = "Enumerating memory regions...";
            Log("Enumerating process memory regions...");

            await Task.Run(() =>
            {
                try
                {
                    var regions = driver.EnumRegions(processSummary.ProcessId);
                    if (regions.Count == 0)
                    {
                        this.SafeInvoke(new Action(() => { Log("No regions found"); statusLabel.Text = "No regions"; }));
                        return;
                    }

                    this.SafeInvoke(new Action(() =>
                    {
                        using (var sfd = new SaveFileDialog())
                        {
                            sfd.FileName = $"{Path.GetFileNameWithoutExtension(processSummary.ProcessName)}_memmap.txt";
                            sfd.Filter = "Text Files|*.txt|All Files|*.*";
                            if (sfd.ShowDialog() == DialogResult.OK)
                            {
                                MemoryMapDumper.Save(sfd.FileName, regions, processSummary.ProcessName, processSummary.ProcessId);
                                Log("Memory map saved: {0} ({1} regions)", sfd.FileName, regions.Count);
                                statusLabel.Text = $"Saved {regions.Count} regions";
                            }
                        }
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => { Log("Memory map error: {0}", ex.Message); statusLabel.Text = "Memory map failed"; }));
                }
            });
        }

        private async void ToolIl2CppMetadata_Click(object sender, EventArgs e)
        {
            statusLabel.Text = "Scanning for Il2Cpp metadata...";
            Log("Searching for Il2Cpp global-metadata.dat (magic: 0xFAB11BAF)...");

            await Task.Run(() =>
            {
                try
                {
                    var (metadata, address) = driver.ReadIl2CppMetadata(processSummary.ProcessId);

                    if (metadata == null)
                    {
                        this.SafeInvoke(new Action(() => { Log("Il2Cpp metadata not found (not a Unity Il2Cpp game?)"); statusLabel.Text = "Metadata not found"; }));
                        return;
                    }

                    var info = Il2CppDumper.ParseHeader(metadata, address);
                    this.SafeInvoke(new Action(() =>
                    {
                        Log("Found Il2Cpp metadata at 0x{0:X} (version {1}, {2} bytes)", address, info.Version, metadata.Length);

                        using (var sfd = new SaveFileDialog())
                        {
                            sfd.FileName = "global-metadata.dat";
                            sfd.Filter = "DAT Files|*.dat|All Files|*.*";
                            if (sfd.ShowDialog() == DialogResult.OK)
                            {
                                Il2CppDumper.Save(sfd.FileName, metadata, info);
                                Log("Metadata saved: {0}", sfd.FileName);
                                statusLabel.Text = $"Il2Cpp metadata saved ({metadata.Length / 1024}KB)";
                            }
                        }
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => { Log("Il2Cpp metadata error: {0}", ex.Message); statusLabel.Text = "Metadata dump failed"; }));
                }
            });
        }

        private async void ToolStringXrefs_Click(object sender, EventArgs e)
        {
            if (moduleList.SelectedItems.Count == 0)
            {
                Log("Select a module first to scan string cross-references");
                return;
            }

            var mod = (ModuleSummary)moduleList.SelectedItems[0].Tag;
            statusLabel.Text = "Dumping strings for xref analysis...";
            Log("Scanning for strings and cross-references in {0}...", mod.ModuleName);

            await Task.Run(() =>
            {
                try
                {
                    // First dump live strings
                    var strings = driver.DumpLiveStrings(processSummary.ProcessId, 4);
                    if (strings.Count == 0)
                    {
                        this.SafeInvoke(new Action(() => { Log("No strings found for xref analysis"); statusLabel.Text = "No strings found"; }));
                        return;
                    }

                    // Dump the module to get PE sections
                    var modProcessSummary = new ProcessSummary(
                        processSummary.ProcessId, processSummary.ProcessName,
                        mod.BaseAddress, mod.FileName, mod.ImageSize, mod.EntryPoint);

                    if (!dumper.DumpProcess(modProcessSummary, out PEFile peFile, false))
                    {
                        this.SafeInvoke(new Action(() => { Log("Failed to dump module for xref analysis"); statusLabel.Text = "Dump failed"; }));
                        return;
                    }

                    // Scan for xrefs
                    var xrefs = StringXrefScanner.FindXrefs(peFile, strings, mod.BaseAddress);

                    this.SafeInvoke(new Action(() =>
                    {
                        Log("Found {0} referenced strings with {1} total xrefs",
                            xrefs.Count, xrefs.Sum(x => x.ReferencedFrom.Count));

                        using (var sfd = new SaveFileDialog())
                        {
                            sfd.FileName = $"{Path.GetFileNameWithoutExtension(mod.ModuleName)}_xrefs.txt";
                            sfd.Filter = "Text Files|*.txt|All Files|*.*";
                            if (sfd.ShowDialog() == DialogResult.OK)
                            {
                                StringXrefScanner.SaveXrefReport(sfd.FileName, xrefs, mod.BaseAddress);
                                Log("Xref report saved: {0}", sfd.FileName);
                                statusLabel.Text = $"Saved {xrefs.Count} xrefs";
                            }
                        }
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => { Log("Xref error: {0}", ex.Message); statusLabel.Text = "Xref scan failed"; }));
                }
            });
        }

        private async void ToolStringDedup_Click(object sender, EventArgs e)
        {
            statusLabel.Text = "Dumping strings for dedup report...";
            Log("Dumping and deduplicating strings...");

            await Task.Run(() =>
            {
                try
                {
                    var strings = driver.DumpLiveStrings(processSummary.ProcessId, 4);
                    if (strings.Count == 0)
                    {
                        this.SafeInvoke(new Action(() => { Log("No strings found"); statusLabel.Text = "No strings"; }));
                        return;
                    }

                    var deduped = StringDeduplicator.Deduplicate(strings);

                    this.SafeInvoke(new Action(() =>
                    {
                        Log("Total strings: {0}, Unique: {1}", strings.Count, deduped.Count);

                        using (var sfd = new SaveFileDialog())
                        {
                            sfd.FileName = $"{Path.GetFileNameWithoutExtension(processSummary.ProcessName)}_strings_dedup.txt";
                            sfd.Filter = "Text Files|*.txt|All Files|*.*";
                            if (sfd.ShowDialog() == DialogResult.OK)
                            {
                                using (var writer = new StreamWriter(sfd.FileName))
                                {
                                    writer.WriteLine($"// KsDumper - Deduplicated String Report");
                                    writer.WriteLine($"// Process: {processSummary.ProcessName} (PID: {processSummary.ProcessId})");
                                    writer.WriteLine($"// Total: {strings.Count}, Unique: {deduped.Count}");
                                    writer.WriteLine();

                                    foreach (var entry in deduped)
                                    {
                                        string type = entry.IsUnicode ? "U" : "A";
                                        string escaped = entry.Value.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
                                        writer.WriteLine($"[{type}] \"{escaped}\" ({entry.Addresses.Count} occurrence(s))");
                                        foreach (ulong addr in entry.Addresses)
                                            writer.WriteLine($"    0x{addr:x}");
                                        writer.WriteLine();
                                    }
                                }
                                Log("Dedup report saved: {0}", sfd.FileName);
                                statusLabel.Text = $"Saved {deduped.Count} unique strings";
                            }
                        }
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => { Log("Dedup error: {0}", ex.Message); statusLabel.Text = "Dedup failed"; }));
                }
            });
        }

        private UnityStatusWindow unityStatusWin;

        private void LoadUnityBtn_Click(object sender, EventArgs e)
        {
            string selectedDir = null;
            using (var fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Select the folder containing the ORIGINAL on-disk GameAssembly.dll and UnityPlayer.dll";
                if (fbd.ShowDialog() == DialogResult.OK)
                    selectedDir = fbd.SelectedPath;
            }

            if (string.IsNullOrEmpty(selectedDir))
                return;

            loadUnityBtn.Enabled = false;
            statusLabel.Text = "Loading Unity reference DLLs...";
            Log("Loading on-disk Unity DLLs from: {0}", selectedDir);

            Task.Run(() =>
            {
                string gaPath = null;
                string upPath = null;

                // Search for the DLLs (case-insensitive)
                foreach (var file in Directory.GetFiles(selectedDir, "*.dll"))
                {
                    string name = Path.GetFileName(file);
                    if (name.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))
                        gaPath = file;
                    else if (name.Equals("UnityPlayer.dll", StringComparison.OrdinalIgnoreCase))
                        upPath = file;
                }

                // Create status window
                var statusWin = new UnityStatusWindow();
                statusWin.StartPosition = FormStartPosition.CenterParent;

                this.SafeInvoke(() =>
                {
                    statusWin.Show(this);
                    unityStatusWin = statusWin;
                });

                // Load GameAssembly.dll
                if (gaPath != null)
                {
                    var gaRef = UnityReference.Load(gaPath);
                    if (gaRef != null)
                    {
                        gameAssemblyRef = gaRef;
                        this.SafeInvoke(() =>
                        {
                            Log("  GameAssembly.dll loaded: {0}", gaPath);
                            Log("    Image Base: 0x{0:X}, Size: 0x{1:X}, Sections: {2}, Exports: {3}",
                                gaRef.ImageBase, gaRef.ImageSize, gaRef.Sections.Length, gaRef.Exports.Length);
                            statusWin.AppendSection("GameAssembly.dll", gaPath, gaRef);
                        });
                    }
                    else
                    {
                        this.SafeInvoke(() => Log("  FAILED to parse GameAssembly.dll: {0}", gaPath));
                    }
                }
                else
                {
                    this.SafeInvoke(() => Log("  GameAssembly.dll not found in selected folder"));
                }

                // Load UnityPlayer.dll
                if (upPath != null)
                {
                    var upRef = UnityReference.Load(upPath);
                    if (upRef != null)
                    {
                        unityPlayerRef = upRef;
                        this.SafeInvoke(() =>
                        {
                            Log("  UnityPlayer.dll loaded: {0}", upPath);
                            Log("    Image Base: 0x{0:X}, Size: 0x{1:X}, Sections: {2}, Exports: {3}",
                                upRef.ImageBase, upRef.ImageSize, upRef.Sections.Length, upRef.Exports.Length);
                            statusWin.AppendSection("UnityPlayer.dll", upPath, upRef);
                        });
                    }
                    else
                    {
                        this.SafeInvoke(() => Log("  FAILED to parse UnityPlayer.dll: {0}", upPath));
                    }
                }
                else
                {
                    this.SafeInvoke(() => Log("  UnityPlayer.dll not found in selected folder"));
                }

                this.SafeInvoke(() =>
                {
                    string loaded = "";
                    if (gameAssemblyRef != null) loaded += "GA";
                    if (unityPlayerRef != null) loaded += (loaded.Length > 0 ? " + " : "") + "UP";

                    unityStatusLabel.Text = loaded.Length > 0 ? $"Loaded: {loaded}" : "Load failed";
                    unityStatusLabel.ForeColor = loaded.Length > 0 ? DarkTheme.Success : DarkTheme.Error;
                    statusLabel.Text = loaded.Length > 0 ? "Unity reference loaded" : "Load failed";
                    loadUnityBtn.Enabled = true;
                });
            });
        }

        private async void DumpUnityBtn_Click(object sender, EventArgs e)
        {
            dumpUnityBtn.Enabled = false;
            statusLabel.Text = "Dumping Unity IL2CPP...";
            Log("Starting Unity IL2CPP dump...");

            string outputDir = null;
            using (var fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Select output folder for Unity dump (metadata + GameAssembly + SDK)";
                if (fbd.ShowDialog() == DialogResult.OK)
                    outputDir = fbd.SelectedPath;
            }

            if (string.IsNullOrEmpty(outputDir))
            {
                dumpUnityBtn.Enabled = true;
                return;
            }

            progressBar.Visible = true;
            progressBar.Maximum = 6;
            progressBar.Value = 0;

            await Task.Run(() =>
            {
                try
                {
                    // Step 1: Dump global-metadata.dat (with retry for encrypted metadata)
                    this.SafeInvoke(new Action(() => { Log("Step 1/6: Reading Il2Cpp metadata from memory..."); progressBar.Value = 0; }));
                    byte[] metadata = null;
                    ulong metadataAddr = 0;

                    for (int attempt = 1; attempt <= 3; attempt++)
                    {
                        var result = driver.ReadIl2CppMetadata(processSummary.ProcessId);
                        metadata = result.metadata;
                        metadataAddr = result.address;

                        if (metadata != null && Il2CppDumper.ValidateMagic(metadata))
                            break;

                        if (attempt < 3)
                        {
                            this.SafeInvoke(new Action(() => Log("  Metadata not ready (attempt {0}/3), waiting 5s for game to initialize...", attempt)));
                            Task.Delay(5000).Wait();
                        }
                    }

                    if (metadata == null || !Il2CppDumper.ValidateMagic(metadata))
                    {
                        this.SafeInvoke(new Action(() =>
                        {
                            Log("FAILED: Il2Cpp metadata not found or still encrypted after 3 attempts");
                            Log("  Make sure the game has fully loaded (past loading screen) before retrying");
                            statusLabel.Text = "Metadata dump failed";
                            progressBar.Visible = false;
                            dumpUnityBtn.Enabled = true;
                        }));
                        return;
                    }

                    var metaInfo = Il2CppDumper.ParseHeader(metadata, metadataAddr);
                    string metadataPath = Path.Combine(outputDir, "global-metadata.dat");
                    Il2CppDumper.Save(metadataPath, metadata, metaInfo);
                    this.SafeInvoke(new Action(() => Log("  Saved: {0} ({1}KB, version {2})", metadataPath, metadata.Length / 1024, metaInfo.Version)));

                    // Step 2: Dump GameAssembly.dll from memory
                    this.SafeInvoke(new Action(() => { Log("Step 2/6: Dumping GameAssembly.dll from memory..."); progressBar.Value = 1; }));

                    ModuleSummary gameAssembly = null;
                    for (int i = 0; i < moduleList.Items.Count; i++)
                    {
                        var mod = (ModuleSummary)moduleList.Items[i].Tag;
                        if (mod.ModuleName != null && mod.ModuleName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))
                        {
                            gameAssembly = mod;
                            break;
                        }
                    }

                    PEFile dumpedGaFile = default;
                    bool gaDumped = false;

                    if (gameAssembly != null)
                    {
                        var gaProcessSummary = new ProcessSummary(
                            processSummary.ProcessId, processSummary.ProcessName,
                            gameAssembly.BaseAddress, gameAssembly.FileName, gameAssembly.ImageSize, gameAssembly.EntryPoint);

                        if (dumper.DumpProcess(gaProcessSummary, out dumpedGaFile, rebuildImportsCheckBox.Checked))
                        {
                            gaDumped = true;
                            string gaPath = Path.Combine(outputDir, "GameAssembly_dump.dll");
                            dumpedGaFile.SaveToDisk(gaPath);
                            this.SafeInvoke(new Action(() => Log("  Saved: {0}", gaPath)));
                        }
                        else
                        {
                            this.SafeInvoke(new Action(() => Log("  WARNING: Failed to dump GameAssembly.dll (try suspending process first)")));
                        }
                    }
                    else
                    {
                        this.SafeInvoke(new Action(() => Log("  WARNING: GameAssembly.dll not found in module list")));
                    }

                    // Step 3: Compare on-disk vs in-memory sections (if reference loaded)
                    this.SafeInvoke(new Action(() => { Log("Step 3/6: Comparing on-disk vs in-memory sections..."); progressBar.Value = 2; }));

                    if (gameAssemblyRef != null && gaDumped && gameAssembly != null)
                    {
                        try
                        {
                            // Dump the full in-memory image section-by-section for comparison
                            byte[] memImage = gameAssemblyRef.DumpInMemoryImage(driver, processSummary.ProcessId, gameAssembly.BaseAddress);
                            var comparisons = gameAssemblyRef.CompareSections(memImage);

                            string decrDir = Path.Combine(outputDir, "decrypted_sections");
                            gameAssemblyRef.SaveDecryptedSections(decrDir, comparisons);

                            string reportPath = Path.Combine(outputDir, "section_comparison.txt");
                            gameAssemblyRef.SaveComparisonReport(reportPath, comparisons);

                            int decryptedCount = 0;
                            foreach (var cmp in comparisons)
                            {
                                if (cmp.IsDecrypted)
                                {
                                    decryptedCount++;
                                    this.SafeInvoke(new Action(() =>
                                    {
                                        Log("  [{0}] DECRYPTED: {1} bytes changed ({2:F1}%)", cmp.Name, cmp.DifferentBytes, cmp.DiffPercent);
                                        if (unityStatusWin != null)
                                            unityStatusWin.AppendComparison(cmp);
                                    }));
                                }
                                else
                                {
                                    this.SafeInvoke(new Action(() => Log("  [{0}] identical", cmp.Name)));
                                }
                            }

                            this.SafeInvoke(new Action(() =>
                            {
                                Log("  Section comparison complete: {0} decrypted, {1} identical", decryptedCount, comparisons.Count - decryptedCount);
                                Log("  Decrypted sections saved to: {0}", decrDir);
                                Log("  Report saved: {0}", reportPath);
                            }));

                            // Map IL2CPP API exports from on-disk to in-memory addresses
                            if (gameAssemblyRef.Exports.Length > 0)
                            {
                                string exportsPath = Path.Combine(outputDir, "il2cpp_exports.txt");
                                using (var writer = new StreamWriter(exportsPath))
                                {
                                    writer.WriteLine("// KsDumper - IL2CPP API Export Map");
                                    writer.WriteLine($"// On-disk base: 0x{gameAssemblyRef.ImageBase:X}");
                                    writer.WriteLine($"// In-memory base: 0x{gameAssembly.BaseAddress:X}");
                                    writer.WriteLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                                    writer.WriteLine();
                                    writer.WriteLine("// Format: [IN-MEMORY ADDR] [RVA] [EXPORT NAME]");
                                    writer.WriteLine();

                                    foreach (var exp in gameAssemblyRef.Exports)
                                    {
                                        ulong inMemAddr = gameAssembly.BaseAddress + exp.Rva;
                                        writer.WriteLine($"  0x{inMemAddr:X16}  RVA:0x{exp.Rva:X8}  {exp.Name}");
                                    }
                                }
                                this.SafeInvoke(new Action(() => Log("  Export map saved: {0} ({1} functions)", exportsPath, gameAssemblyRef.Exports.Length)));
                            }
                        }
                        catch (Exception ex)
                        {
                            this.SafeInvoke(new Action(() => Log("  Section comparison error: {0}", ex.Message)));
                        }
                    }
                    else if (gameAssemblyRef == null)
                    {
                        this.SafeInvoke(new Action(() => Log("  Skipped: no on-disk reference loaded (use 'Load Unity' first)")));
                    }

                    // Also compare UnityPlayer.dll if reference loaded
                    if (unityPlayerRef != null)
                    {
                        ModuleSummary unityPlayer = null;
                        for (int i = 0; i < moduleList.Items.Count; i++)
                        {
                            var mod = (ModuleSummary)moduleList.Items[i].Tag;
                            if (mod.ModuleName != null && mod.ModuleName.Equals("UnityPlayer.dll", StringComparison.OrdinalIgnoreCase))
                            {
                                unityPlayer = mod;
                                break;
                            }
                        }

                        if (unityPlayer != null)
                        {
                            try
                            {
                                byte[] upMemImage = unityPlayerRef.DumpInMemoryImage(driver, processSummary.ProcessId, unityPlayer.BaseAddress);
                                var upComparisons = unityPlayerRef.CompareSections(upMemImage);

                                string upDecrDir = Path.Combine(outputDir, "UnityPlayer_decrypted");
                                unityPlayerRef.SaveDecryptedSections(upDecrDir, upComparisons);

                                string upReportPath = Path.Combine(outputDir, "UnityPlayer_comparison.txt");
                                unityPlayerRef.SaveComparisonReport(upReportPath, upComparisons);

                                foreach (var cmp in upComparisons)
                                {
                                    if (cmp.IsDecrypted)
                                    {
                                        this.SafeInvoke(new Action(() => Log("  UP [{0}] DECRYPTED: {1} bytes ({2:F1}%)", cmp.Name, cmp.DifferentBytes, cmp.DiffPercent)));
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                this.SafeInvoke(new Action(() => Log("  UnityPlayer comparison error: {0}", ex.Message)));
                            }
                        }
                    }

                    // Step 4: Parse metadata and generate SDK
                    this.SafeInvoke(new Action(() => { Log("Step 4/6: Generating IL2CPP SDK..."); progressBar.Value = 3; }));

                    var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                    if (snapshot != null && snapshot.TypeDefinitions.Length > 0)
                    {
                        var classInfo = Il2CppSdkGenerator.BuildClassInfo(snapshot);
                        string sdkText = Il2CppSdkGenerator.GenerateSdk(classInfo);

                        string sdkPath = Path.Combine(outputDir, "Il2CppSdk.cs");
                        Il2CppSdkGenerator.Save(sdkPath, sdkText, snapshot);

                        int totalMethods = classInfo.Sum(c => c.Methods.Count);
                        int totalFields = classInfo.Sum(c => c.Fields.Count);
                        this.SafeInvoke(new Action(() => Log("  Saved: {0} ({1} classes, {2} methods, {3} fields)", sdkPath, classInfo.Count, totalMethods, totalFields)));
                    }
                    else
                    {
                        this.SafeInvoke(new Action(() => Log("  WARNING: Could not parse metadata for SDK generation (version may be unsupported)")));
                    }

                    // Step 5: Beebyte deobfuscation (auto-detect)
                    this.SafeInvoke(new Action(() => { Log("Step 5/6: Checking for Beebyte obfuscation..."); progressBar.Value = 4; }));

                    BeebyteDumper.RecoveryResult beebyte = null;
                    if (snapshot != null && snapshot.TypeDefinitions.Length > 0 && gameAssembly != null)
                    {
                        try
                        {
                            beebyte = BeebyteDumper.RecoverNames(
                                driver, processSummary.ProcessId,
                                gameAssembly.BaseAddress, gameAssembly.ImageSize,
                                snapshot,
                                msg => this.SafeInvoke(new Action(() => Log("  " + msg))));

                            if (beebyte.IsObfuscated && beebyte.RecoveredTypes > 0)
                            {
                                string mapPath = Path.Combine(outputDir, "beebyte_deobfuscation_map.txt");
                                BeebyteDumper.SaveMapping(mapPath, beebyte, processSummary.ProcessName);
                                this.SafeInvoke(new Action(() => Log("  Saved deobfuscation map: {0}", mapPath)));

                                string idaPath = Path.Combine(outputDir, "beebyte_ida_rename.py");
                                BeebyteDumper.SaveIdaScript(idaPath, beebyte);
                                this.SafeInvoke(new Action(() => Log("  Saved IDA rename script: {0}", idaPath)));

                                string deobSdkPath = Path.Combine(outputDir, "Il2CppSdk_deobfuscated.cs");
                                string deobSdk = BeebyteDumper.GenerateDeobfuscatedSdk(snapshot, beebyte);
                                File.WriteAllText(deobSdkPath, deobSdk, Encoding.UTF8);
                                this.SafeInvoke(new Action(() => Log("  Saved deobfuscated SDK: {0}", deobSdkPath)));

                                this.SafeInvoke(new Action(() => Log("  Beebyte recovery: {0}/{1} types, {2} methods, {3} fields",
                                    beebyte.RecoveredTypes, beebyte.TotalTypes, beebyte.RecoveredMethods, beebyte.RecoveredFields)));
                            }
                            else if (!beebyte.IsObfuscated)
                            {
                                this.SafeInvoke(new Action(() => Log("  No Beebyte obfuscation detected — names appear clean")));
                            }
                            else
                            {
                                this.SafeInvoke(new Action(() => Log("  Beebyte obfuscation detected but could not recover names")));
                                this.SafeInvoke(new Action(() => Log("  Make sure the game is fully loaded (past main menu) and try again")));
                            }
                        }
                        catch (Exception ex)
                        {
                            this.SafeInvoke(new Action(() => Log("  Beebyte recovery error: {0}", ex.Message)));
                        }
                    }

                    // Step 6: Write dump summary
                    this.SafeInvoke(new Action(() => { Log("Step 6/6: Writing dump summary..."); progressBar.Value = 5; }));

                    string summaryPath = Path.Combine(outputDir, "dump_info.txt");
                    using (var writer = new StreamWriter(summaryPath))
                    {
                        writer.WriteLine("// KsDumper - Unity IL2CPP Dump Summary");
                        writer.WriteLine($"// Process: {processSummary.ProcessName} (PID: {processSummary.ProcessId})");
                        writer.WriteLine($"// Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                        writer.WriteLine();
                        writer.WriteLine($"Metadata Version: {metaInfo.Version}");
                        writer.WriteLine($"Metadata Address: 0x{metadataAddr:X}");
                        writer.WriteLine($"Metadata Size: {metadata.Length} bytes");
                        if (snapshot != null)
                        {
                            writer.WriteLine($"Type Definitions: {snapshot.TypeDefinitions.Length}");
                            writer.WriteLine($"Methods: {snapshot.Methods.Length}");
                            writer.WriteLine($"Fields: {snapshot.Fields.Length}");
                            writer.WriteLine($"Parameters: {snapshot.Parameters.Length}");
                            writer.WriteLine($"Properties: {snapshot.Properties.Length}");
                        }
                        if (gameAssembly != null)
                        {
                            writer.WriteLine();
                            writer.WriteLine($"GameAssembly.dll Base: 0x{gameAssembly.BaseAddress:X}");
                            writer.WriteLine($"GameAssembly.dll Size: 0x{gameAssembly.ImageSize:X}");
                            writer.WriteLine($"GameAssembly.dll Path: {gameAssembly.FileName}");
                        }
                        if (gameAssemblyRef != null)
                        {
                            writer.WriteLine();
                            writer.WriteLine($"// On-Disk Reference");
                            writer.WriteLine($"GameAssembly.dll (disk): {gameAssemblyRef.FilePath}");
                            writer.WriteLine($"Sections: {gameAssemblyRef.Sections.Length}, Exports: {gameAssemblyRef.Exports.Length}");
                        }
                        if (beebyte != null && beebyte.IsObfuscated)
                        {
                            writer.WriteLine();
                            writer.WriteLine($"// Beebyte Deobfuscation");
                            writer.WriteLine($"Obfuscated: Yes");
                            writer.WriteLine($"Types Recovered: {beebyte.RecoveredTypes}/{beebyte.TotalTypes}");
                            writer.WriteLine($"Methods Recovered: {beebyte.RecoveredMethods}");
                            writer.WriteLine($"Fields Recovered: {beebyte.RecoveredFields}");
                        }
                    }

                    this.SafeInvoke(new Action(() =>
                    {
                        Log("Unity IL2CPP dump complete! Output: {0}", outputDir);
                        statusLabel.Text = "Unity dump complete";
                        progressBar.Value = 6;
                        progressBar.Visible = false;
                        dumpUnityBtn.Enabled = true;
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() =>
                    {
                        Log("Unity dump error: {0}", ex.Message);
                        statusLabel.Text = "Unity dump failed";
                        progressBar.Visible = false;
                        dumpUnityBtn.Enabled = true;
                    }));
                }
            });
        }

        private async void DumpMonoBtn_Click(object sender, EventArgs e)
        {
            dumpMonoBtn.Enabled = false;
            statusLabel.Text = "Dumping Mono assemblies...";
            Log("Starting Unity Mono dump...");

            string outputDir = null;
            using (var fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Select output folder for Mono dump (assemblies + SDK)";
                if (fbd.ShowDialog() == DialogResult.OK)
                    outputDir = fbd.SelectedPath;
            }

            if (string.IsNullOrEmpty(outputDir))
            {
                dumpMonoBtn.Enabled = true;
                return;
            }

            progressBar.Visible = true;
            progressBar.Maximum = 3;
            progressBar.Value = 0;

            var allModules = new ModuleSummary[moduleList.Items.Count];
            for (int i = 0; i < moduleList.Items.Count; i++)
                allModules[i] = (ModuleSummary)moduleList.Items[i].Tag;

            await Task.Run(() =>
            {
                try
                {
                    // Step 1: Dump managed assemblies
                    this.SafeInvoke(new Action(() => { Log("Step 1/3: Dumping managed assemblies..."); progressBar.Value = 0; }));

                    var result = MonoDumper.DumpManagedAssemblies(
                        driver, processSummary.ProcessId, allModules, dumper,
                        outputDir, msg => this.SafeInvoke(new Action(() => Log(msg))));

                    // Step 2: Generate SDK from dumped assemblies
                    this.SafeInvoke(new Action(() => { Log("Step 2/3: Generating Mono SDK..."); progressBar.Value = 1; }));

                    int sdkClasses = 0;
                    foreach (var file in result.DumpedFiles)
                    {
                        try
                        {
                            byte[] peBytes = File.ReadAllBytes(file);
                            var sdkInfo = MonoSdkGenerator.ParseFromPE(peBytes);
                            if (sdkInfo != null && sdkInfo.Classes.Count > 0)
                            {
                                sdkInfo.AssemblyName = Path.GetFileNameWithoutExtension(file);
                                string sdkText = MonoSdkGenerator.GenerateSdk(sdkInfo);
                                string sdkPath = Path.Combine(outputDir,
                                    Path.GetFileNameWithoutExtension(file) + "_sdk.cs");
                                MonoSdkGenerator.Save(sdkPath, sdkText, sdkInfo);
                                sdkClasses += sdkInfo.Classes.Count;
                                this.SafeInvoke(new Action(() => Log("  SDK: {0} ({1} classes)", Path.GetFileName(sdkPath), sdkInfo.Classes.Count)));
                            }
                        }
                        catch (Exception ex)
                        {
                            this.SafeInvoke(new Action(() => Log("  SDK generation failed for {0}: {1}", Path.GetFileName(file), ex.Message)));
                        }
                    }

                    // Step 3: Write summary
                    this.SafeInvoke(new Action(() => { Log("Step 3/3: Writing summary..."); progressBar.Value = 2; }));

                    this.SafeInvoke(new Action(() =>
                    {
                        Log("Mono dump complete! {0}/{1} assemblies dumped, {2} SDK classes, {3} decrypted strings",
                            result.AssembliesDumped, result.AssembliesFound, sdkClasses, result.DecryptedStrings.Count);
                        Log("Output: {0}", outputDir);
                        statusLabel.Text = $"Mono dump: {result.AssembliesDumped} assemblies";
                        progressBar.Value = 3;
                        progressBar.Visible = false;
                        dumpMonoBtn.Enabled = true;
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() =>
                    {
                        Log("Mono dump error: {0}", ex.Message);
                        statusLabel.Text = "Mono dump failed";
                        progressBar.Visible = false;
                        dumpMonoBtn.Enabled = true;
                    }));
                }
            });
        }

        private void ToolBeebyteRecovery_Click(object sender, EventArgs e)
        {
            ModuleSummary gameAssembly = null;
            for (int i = 0; i < moduleList.Items.Count; i++)
            {
                var mod = (ModuleSummary)moduleList.Items[i].Tag;
                if (mod.ModuleName != null && mod.ModuleName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))
                {
                    gameAssembly = mod;
                    break;
                }
            }

            if (gameAssembly == null)
            {
                Log("Beebyte Recovery requires GameAssembly.dll (Unity IL2CPP game)");
                statusLabel.Text = "Not a Unity IL2CPP process";
                return;
            }

            var win = new BeebyteLiveWindow(driver, processSummary.ProcessId, processSummary.ProcessName,
                gameAssembly.BaseAddress, gameAssembly.ImageSize);
            win.Show(this);
        }

        private void ToolDetectEngine_Click(object sender, EventArgs e)
        {
            var modules = new ModuleSummary[moduleList.Items.Count];
            for (int i = 0; i < moduleList.Items.Count; i++)
                modules[i] = (ModuleSummary)moduleList.Items[i].Tag;

            var result = EngineDetector.Detect(modules);
            Log("Engine Detection: {0}", result.Details);

            if (result.IndicatorModules.Count > 0)
                Log("Indicator modules: {0}", string.Join(", ", result.IndicatorModules));

            statusLabel.Text = $"Engine: {result.Engine}";

            if (result.Engine == EngineDetector.GameEngine.UnityIl2Cpp)
                Log("Tip: Use 'Il2Cpp Metadata' from Tools to dump global-metadata.dat");
        }

        private async void ToolComparePE_Click(object sender, EventArgs e)
        {
            if (moduleList.SelectedItems.Count == 0)
            {
                Log("Select a dumped module first to compare");
                return;
            }

            string originalPath = null;
            using (var ofd = new OpenFileDialog())
            {
                ofd.Title = "Select the ORIGINAL on-disk binary to compare against";
                ofd.Filter = "Executable Files|*.exe;*.dll|All Files|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                    originalPath = ofd.FileName;
            }

            if (string.IsNullOrEmpty(originalPath)) return;

            var mod = (ModuleSummary)moduleList.SelectedItems[0].Tag;
            statusLabel.Text = "Dumping and comparing...";
            Log("Dumping {0} for comparison...", mod.ModuleName);

            await Task.Run(() =>
            {
                try
                {
                    var modProcessSummary = new ProcessSummary(
                        processSummary.ProcessId, processSummary.ProcessName,
                        mod.BaseAddress, mod.FileName, mod.ImageSize, mod.EntryPoint);

                    if (!dumper.DumpProcess(modProcessSummary, out PEFile peFile, false))
                    {
                        this.SafeInvoke(new Action(() => { Log("Dump failed for comparison"); statusLabel.Text = "Dump failed"; }));
                        return;
                    }

                    var diffs = PEComparator.Compare(peFile, originalPath);

                    this.SafeInvoke(new Action(() =>
                    {
                        using (var sfd = new SaveFileDialog())
                        {
                            sfd.FileName = $"{Path.GetFileNameWithoutExtension(mod.ModuleName)}_comparison.txt";
                            sfd.Filter = "Text Files|*.txt|All Files|*.*";
                            if (sfd.ShowDialog() == DialogResult.OK)
                            {
                                PEComparator.SaveReport(sfd.FileName, diffs, originalPath);

                                foreach (var diff in diffs)
                                {
                                    if (diff.Identical)
                                        Log("[{0}] IDENTICAL", diff.SectionName);
                                    else
                                        Log("[{0}] DIFFERS: {1} bytes ({2:F1}%)", diff.SectionName, diff.DifferentBytes, diff.DifferencePercent);
                                }

                                Log("Comparison report saved: {0}", sfd.FileName);
                                statusLabel.Text = "Comparison saved";
                            }
                        }
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => { Log("Compare error: {0}", ex.Message); statusLabel.Text = "Compare failed"; }));
                }
            });
        }

        // ---- Entry Point Recovery ----

        private void RecoverEntryPointsAsync(ModuleSummary[] modules)
        {
            var hidden = new List<ModuleSummary>();
            foreach (var mod in modules)
                if (mod.EntryPoint == 0) hidden.Add(mod);

            if (hidden.Count == 0) return;

            Task.Run(() =>
            {
                int recovered = 0;
                foreach (var mod in hidden)
                {
                    try
                    {
                        ulong ep = ReadEntryPointFromPE(mod.BaseAddress);
                        if (ep > 0)
                        {
                            recovered++;
                            int idx = -1;
                            this.SafeInvoke(new Action(() =>
                            {
                                for (int i = 0; i < moduleList.Items.Count; i++)
                                {
                                    var m = (ModuleSummary)moduleList.Items[i].Tag;
                                    if (m.BaseAddress == mod.BaseAddress) { idx = i; break; }
                                }
                                if (idx >= 0)
                                    moduleList.Items[idx].SubItems[2].Text = $"0x{ep:x}";
                            }));
                        }
                    }
                    catch { }
                }
                if (recovered > 0)
                    this.SafeInvoke(() => Log("Recovered {0} hidden entry points from PE headers", recovered));
            });
        }

        private ulong ReadEntryPointFromPE(ulong baseAddress)
        {
            IntPtr basePtr = (IntPtr)baseAddress;

            byte[] dosHeader = ReadBytes(basePtr, 64);

            if (BitConverter.ToUInt16(dosHeader, 0) != 0x5A4D) return 0;
            int e_lfanew = BitConverter.ToInt32(dosHeader, 60);

            int peOff = e_lfanew + 24;
            IntPtr pePtr = new IntPtr(basePtr.ToInt64() + peOff);
            byte[] peOpt = ReadBytes(pePtr, 20);

            uint entryPointRVA = BitConverter.ToUInt32(peOpt, 16);
            if (entryPointRVA == 0) return 0;
            return baseAddress + entryPointRVA;
        }

        // ---- Packed/Protected Module Detection ----

        private void DetectPackedModulesAsync(ModuleSummary[] modules)
        {
            Task.Run(() =>
            {
                int packedCount = 0;

                foreach (var mod in modules)
                {
                    if (mod.ImageSize == 0) continue;

                    try
                    {
                        double entropy = CalculateModuleCodeEntropy(mod.BaseAddress, mod.ImageSize);
                        if (entropy >= 6.8)
                        {
                            packedCount++;
                            this.SafeInvoke(new Action(() =>
                            {
                                for (int i = 0; i < moduleList.Items.Count; i++)
                                {
                                    var m = (ModuleSummary)moduleList.Items[i].Tag;
                                    if (m.BaseAddress == mod.BaseAddress)
                                    {
                                        var lvi = moduleList.Items[i];
                                        lvi.ForeColor = DarkTheme.PackedModule;
                                        lvi.Font = new Font(moduleList.Font, FontStyle.Bold);
                                        lvi.SubItems[5].Text = $"PACKED ({entropy:F1})";
                                        lvi.ToolTipText = $"High entropy ({entropy:F2}) in code section - likely packed, encrypted, or protected";
                                        break;
                                    }
                                }
                            }));
                        }
                    }
                    catch { }
                }

                if (packedCount > 0)
                    this.SafeInvoke(() => Log("Detected {0} packed/protected module(s) (high code entropy)", packedCount));
            });
        }

        private double CalculateModuleCodeEntropy(ulong baseAddress, uint imageSize)
        {
            IntPtr basePtr = (IntPtr)baseAddress;

            // Read DOS header
            byte[] dosHeader = ReadBytes(basePtr, 64);

            if (BitConverter.ToUInt16(dosHeader, 0) != 0x5A4D) return 0;
            int e_lfanew = BitConverter.ToInt32(dosHeader, 60);

            int peHeaderSize = 512;
            IntPtr pePtr = new IntPtr(basePtr.ToInt64() + e_lfanew);
            byte[] peHeader = ReadBytes(pePtr, peHeaderSize);

            if (BitConverter.ToUInt32(peHeader, 0) != 0x00004550) return 0;

            ushort numSections = BitConverter.ToUInt16(peHeader, 6);
            ushort sizeOfOptHdr = BitConverter.ToUInt16(peHeader, 20);
            int sectionTableOff = 24 + sizeOfOptHdr;

            for (int i = 0; i < numSections; i++)
            {
                int secOff = sectionTableOff + i * 40;
                if (secOff + 40 > peHeaderSize) break;

                uint characteristics = BitConverter.ToUInt32(peHeader, secOff + 36);
                bool isCode = (characteristics & 0x00000020) != 0;
                if (!isCode) continue;

                uint virtualSize = BitConverter.ToUInt32(peHeader, secOff + 8);
                uint virtualAddr = BitConverter.ToUInt32(peHeader, secOff + 12);
                if (virtualSize == 0 || virtualAddr == 0) continue;

                int readSize = (int)Math.Min(virtualSize, 0x10000);
                IntPtr secPtr = new IntPtr(basePtr.ToInt64() + virtualAddr);
                byte[] data = ReadBytes(secPtr, readSize);

                return ShannonEntropy(data);
            }

            return 0;
        }

        private static double ShannonEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0;

            int[] freq = new int[256];
            foreach (byte b in data)
                freq[b]++;

            double entropy = 0;
            int len = data.Length;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] == 0) continue;
                double p = (double)freq[i] / len;
                entropy -= p * Math.Log(p, 2);
            }
            return entropy;
        }

        // ---- Module Context Menu Handlers ----

        private ModuleSummary GetContextModule()
        {
            if (moduleList.SelectedItems.Count == 0) return null;
            return (ModuleSummary)moduleList.SelectedItems[0].Tag;
        }

        private async void CtxDumpModule_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;
            await DumpModules(new[] { mod });
        }

        private void CtxOpenFileLocation_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;

            if (!string.IsNullOrEmpty(mod.FileName) && File.Exists(mod.FileName))
            {
                System.Diagnostics.Process.Start("explorer.exe", $"/select,\"{mod.FileName}\"");
            }
            else
            {
                Log("File not accessible: {0}", mod.FileName ?? "(no path)");
            }
        }

        private void CtxCopyBaseAddress_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;
            Clipboard.SetText($"0x{mod.BaseAddress:x}");
            Log("Copied base address: 0x{0:x}", mod.BaseAddress);
        }

        private void CtxCopyModuleName_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;
            Clipboard.SetText(mod.ModuleName);
            Log("Copied module name: {0}", mod.ModuleName);
        }

        private void CtxRevealEntryPoint_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;

            if (mod.EntryPoint > 0)
            {
                Log("{0} entry point: 0x{1:x} (already known)", mod.ModuleName, mod.EntryPoint);
                return;
            }

            Task.Run(() =>
            {
                try
                {
                    IntPtr basePtr = (IntPtr)mod.BaseAddress;
                    byte[] dosHeader = ReadBytes(basePtr, 64);

                    if (BitConverter.ToUInt16(dosHeader, 0) != 0x5A4D)
                    {
                        this.SafeInvoke(new Action(() => Log("Invalid DOS signature for {0}", mod.ModuleName)));
                        return;
                    }

                    int e_lfanew = BitConverter.ToInt32(dosHeader, 60);

                    int peReadSize = 264;
                    IntPtr pePtr = new IntPtr(basePtr.ToInt64() + e_lfanew);
                    byte[] peHeader = ReadBytes(pePtr, peReadSize);

                    // Verify PE signature
                    if (BitConverter.ToUInt32(peHeader, 0) != 0x00004550)
                    {
                        this.SafeInvoke(new Action(() => Log("Invalid PE signature for {0}", mod.ModuleName)));
                        return;
                    }

                    // AddressOfEntryPoint is at offset 16 from start of optional header
                    // Optional header starts at offset 24 (after PE sig + FileHeader)
                    uint entryPointRVA = BitConverter.ToUInt32(peHeader, 24 + 16);
                    ulong entryPointVA = mod.BaseAddress + entryPointRVA;

                    this.SafeInvoke(new Action(() =>
                    {
                        Log("{0} entry point revealed: RVA 0x{1:x} (VA: 0x{2:x})", mod.ModuleName, entryPointRVA, entryPointVA);
                        Clipboard.SetText($"0x{entryPointVA:x}");

                        // Update the list item
                        if (moduleList.SelectedItems.Count > 0)
                        {
                            moduleList.SelectedItems[0].SubItems[2].Text = $"0x{entryPointVA:x}";
                        }
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Log("Entry point reveal error: {0}", ex.Message)));
                }
            });
        }

        private async void CtxAnalyzeModule_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;

            statusLabel.Text = "Analyzing module...";
            Log("Running PE analysis on {0}...", mod.ModuleName);

            await Task.Run(() =>
            {
                var modPS = new ProcessSummary(processSummary.ProcessId, processSummary.ProcessName,
                    mod.BaseAddress, mod.FileName, mod.ImageSize, mod.EntryPoint);

                if (!dumper.DumpProcess(modPS, out PEFile peFile, false))
                {
                    this.SafeInvoke(() => { Log("Failed to dump module for analysis"); statusLabel.Text = "Analysis failed"; });
                    return;
                }

                var rtti = PEAnalyzer.ScanRTTI(peFile);
                var vtables = PEAnalyzer.FindVTables(peFile, mod.BaseAddress);
                var entropy = PEAnalyzer.CalculateEntropy(peFile);
                var imports = PEAnalyzer.GetImportStats(peFile);
                var strings = PEAnalyzer.ExtractStrings(peFile);

                this.SafeInvoke(() =>
                {
                    Log("=== Analysis: {0} ===", mod.ModuleName);
                    Log("PE Type: {0}, Sections: {1}", peFile.Type, peFile.Sections.Length);
                    Log("Imports: {0} total, {1} resolved ({2} DLLs)", imports.total, imports.resolved, imports.dllCount);
                    Log("RTTI Classes: {0}", rtti.Count);
                    foreach (var cls in rtti) Log("  class {0}", cls);
                    Log("VTables: {0}", vtables.Count);
                    foreach (var vt in vtables) Log("  RVA: 0x{0:X8} ({1} methods)", vt.rva, vt.methodCount);
                    Log("Entropy:");
                    foreach (var sec in entropy)
                        Log("  [{0}] {1:F2} - {2}", sec.Name, sec.Entropy, sec.Assessment);
                    Log("Strings: {0} found", strings.Count);
                    statusLabel.Text = $"Analysis complete: {mod.ModuleName}";
                });
            });
        }

        private async void CtxDecryptStrings_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;

            statusLabel.Text = "Advanced string decryption...";
            Log("Running advanced string decryption on {0}...", mod.ModuleName);

            await Task.Run(() =>
            {
                try
                {
                    var result = AdvancedStringDecryptor.ScanModule(
                        driver, processSummary.ProcessId, mod.BaseAddress, mod.ImageSize,
                        msg => this.SafeInvoke(new Action(() => Log(msg))));

                    this.SafeInvoke(new Action(() =>
                    {
                        if (result.Strings.Count == 0)
                        {
                            Log("No decryptable strings found");
                            statusLabel.Text = "No strings found";
                            return;
                        }

                        // Group by category and display
                        var grouped = result.Strings.GroupBy(s => s.Category).OrderBy(g => g.Key);
                        foreach (var group in grouped)
                        {
                            Log("=== {0} ({1} strings) ===", group.Key, group.Count());
                            int shown = 0;
                            foreach (var ds in group.OrderByDescending(d => d.Confidence))
                            {
                                if (shown++ >= 20) { Log("  ... and {0} more", group.Count() - 20); break; }
                                Log("  [{0:F2}] [{1}] [0x{2:X}] \"{3}\"",
                                    ds.Confidence, ds.Method, ds.Address,
                                    ds.Decrypted.Length > 100 ? ds.Decrypted.Substring(0, 100) + "..." : ds.Decrypted);
                            }
                        }

                        Log("Total: {0}", result.Summary);

                        using (var sfd = new SaveFileDialog())
                        {
                            sfd.FileName = Path.GetFileNameWithoutExtension(mod.ModuleName) + "_strings_advanced.txt";
                            sfd.Filter = "Text Files|*.txt|All Files|*.*";
                            if (sfd.ShowDialog() == DialogResult.OK)
                            {
                                AdvancedStringDecryptor.SaveReport(sfd.FileName, result, mod.ModuleName);
                                Log("Report saved: {0}", sfd.FileName);
                            }
                        }

                        statusLabel.Text = $"Decrypted {result.DecryptedCount} strings";
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => { Log("String decryption error: {0}", ex.Message); statusLabel.Text = "Decryption failed"; }));
                }
            });
        }

        private void CtxStringScanner_Click(object sender, EventArgs e)
        {
            ModuleSummary[] mods = null;
            driver.GetModuleSummaryList(processSummary.ProcessId, out mods);
            var window = new StringDecryptionWindow(driver, processSummary.ProcessId, processSummary.ProcessName, mods);
            window.Show(this);
        }

        private void CtxListWindows_Click(object sender, EventArgs e)
        {
            Log("Enumerating windows for PID {0}...", processSummary.ProcessId);
            var windows = new List<(IntPtr handle, string title, string className, bool visible)>();

            WinApi.EnumWindows((hwnd, lParam) =>
            {
                uint pid;
                WinApi.GetWindowThreadProcessId(hwnd, out pid);
                if ((int)pid == processSummary.ProcessId)
                {
                    var sb = new System.Text.StringBuilder(256);
                    WinApi.GetWindowText(hwnd, sb, 256);
                    string title = sb.ToString();

                    var clsSb = new System.Text.StringBuilder(256);
                    WinApi.GetClassName(hwnd, clsSb, 256);
                    string className = clsSb.ToString();

                    bool visible = WinApi.IsWindowVisible(hwnd);
                    windows.Add((hwnd, title, className, visible));
                }
                return true;
            }, IntPtr.Zero);

            Log("Found {0} windows:", windows.Count);
            foreach (var (handle, title, className, visible) in windows)
            {
                Log("  [0x{0:X}] \"{1}\" Class: {2} Visible: {3}", handle.ToInt64(), title, className, visible);
            }
        }

        private void CtxGdiCount_Click(object sender, EventArgs e)
        {
            try
            {
                var proc = System.Diagnostics.Process.GetProcessById(processSummary.ProcessId);
                int gdiCount = WinApi.GetGuiResources(proc.Handle, 0); // GR_GDIOBJECTS
                int userCount = WinApi.GetGuiResources(proc.Handle, 1); // GR_USEROBJECTS
                Log("GDI objects: {0}, USER objects: {1}", gdiCount, userCount);
            }
            catch (Exception ex) { Log("GDI count error: {0}", ex.Message); }
        }

        private async void CtxGenerateHeader_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;

            statusLabel.Text = "Generating structures header...";
            Log("Dumping {0} for structure header generation...", mod.ModuleName);

            await Task.Run(() =>
            {
                var modPS = new ProcessSummary(processSummary.ProcessId, processSummary.ProcessName,
                    mod.BaseAddress, mod.FileName, mod.ImageSize, mod.EntryPoint);

                if (!dumper.DumpProcess(modPS, out PEFile peFile, false))
                {
                    this.SafeInvoke(() => { Log("Dump failed for header generation"); statusLabel.Text = "Dump failed"; });
                    return;
                }

                string headerContent = StructureHeaderGenerator.Generate(peFile, mod, mod.BaseAddress);

                this.SafeInvoke(() =>
                {
                    using (var sfd = new SaveFileDialog())
                    {
                        sfd.FileName = Path.GetFileNameWithoutExtension(mod.ModuleName) + "_structures.h";
                        sfd.Filter = "Header Files|*.h|All Files|*.*";
                        if (sfd.ShowDialog() == DialogResult.OK)
                        {
                            StructureHeaderGenerator.Save(sfd.FileName, headerContent);
                            Log("Structures header saved: {0}", sfd.FileName);
                            statusLabel.Text = "Header generated";
                        }
                    }
                });
            });
        }

        private void CtxShowSystemDrivers_Click(object sender, EventArgs e)
        {
            if (!driver.IsKernelMode)
            {
                Log("Show System Drivers requires kernel driver");
                return;
            }
            var driverListWindow = new DriverListView(driver);
            driverListWindow.Show(this);
        }

        private async void CtxPEProtectionBypass_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;

            statusLabel.Text = "Dumping and stripping PE protections...";
            Log("Dumping {0} for PE protection bypass...", mod.ModuleName);

            await Task.Run(() =>
            {
                var modPS = new ProcessSummary(processSummary.ProcessId, processSummary.ProcessName,
                    mod.BaseAddress, mod.FileName, mod.ImageSize, mod.EntryPoint);

                if (!dumper.DumpProcess(modPS, out PEFile peFile, rebuildImportsCheckBox.Checked))
                {
                    this.SafeInvoke(() => { Log("Dump failed for PE bypass"); statusLabel.Text = "Dump failed"; });
                    return;
                }

                PEProtectionBypass.StripAll(peFile);

                this.SafeInvoke(() =>
                {
                    string defaultName = mod.ModuleName.Replace(".dll", "_stripped.dll").Replace(".exe", "_stripped.exe");
                    using (var sfd = new SaveFileDialog())
                    {
                        sfd.FileName = defaultName;
                        sfd.Filter = "Executable Files|*.exe;*.dll|All Files|*.*";
                        if (sfd.ShowDialog() == DialogResult.OK)
                        {
                            peFile.SaveToDisk(sfd.FileName);
                            Log("PE protections stripped and saved: {0}", sfd.FileName);
                            Log("  Cleared: Checksum, ForceIntegrity, CFG, ASLR, Security, LoadConfig");
                            statusLabel.Text = "PE bypass saved";
                        }
                    }
                });
            });
        }

        private void CtxUnloadModule_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;

            var confirm = MessageBox.Show(
                $"Unload module '{mod.ModuleName}' from process?\nBase: 0x{mod.BaseAddress:x}\n\nThis will unlink it from the PEB and zero the PE header.",
                "Unload Module", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);

            if (confirm != DialogResult.Yes) return;

            Task.Run(() =>
            {
                int result = driver.UnloadModule(processSummary.ProcessId, mod.BaseAddress);
                this.SafeInvoke(new Action(() =>
                {
                    switch (result)
                    {
                        case 0: Log("Module '{0}' unloaded successfully", mod.ModuleName); break;
                        case 1: Log("Module not found in PEB lists (may already be unlinked)"); break;
                        case 2: Log("Module unload failed"); break;
                        case -1: Log("Driver communication error"); break;
                    }
                    statusLabel.Text = result == 0 ? "Module unloaded" : "Unload failed";
                    if (result == 0) LoadModuleList();
                }));
            });
        }

        private async void CtxStealthDump_Click(object sender, EventArgs e)
        {
            var mod = GetContextModule();
            if (mod == null) return;

            statusLabel.Text = "Stealth dumping via LSASS...";
            Log("Dumping {0} through LSASS read proxy...", mod.ModuleName);

            await Task.Run(() =>
            {
                int imageSize = (int)mod.ImageSize;
                IntPtr fullImage = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)imageSize,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (fullImage == IntPtr.Zero)
                {
                    this.SafeInvoke(new Action(() =>
                    {
                        Log("LSASS dump: memory allocation failed");
                        statusLabel.Text = "LSASS dump failed";
                    }));
                    return;
                }

                bool ok = driver.LsassReadMemory(processSummary.ProcessId,
                    (IntPtr)mod.BaseAddress, fullImage, imageSize);

                if (!ok)
                {
                    WinApi.VirtualFree(fullImage, UIntPtr.Zero, WinApi.MEM_RELEASE);
                    this.SafeInvoke(new Action(() =>
                    {
                        Log("LSASS read failed (is lsass.exe running? Try unprotecting the process first)");
                        statusLabel.Text = "LSASS dump failed";
                    }));
                    return;
                }

                byte[] imageBytes = new byte[imageSize];
                System.Runtime.InteropServices.Marshal.Copy(fullImage, imageBytes, 0, imageSize);
                WinApi.VirtualFree(fullImage, UIntPtr.Zero, WinApi.MEM_RELEASE);

                this.SafeInvoke(new Action(() =>
                {
                    using (var sfd = new SaveFileDialog())
                    {
                        string defaultName = mod.ModuleName.Replace(".dll", "_lsass_dump.dll").Replace(".exe", "_lsass_dump.exe");
                        sfd.FileName = defaultName;
                        sfd.Filter = "Executable Files|*.exe;*.dll|All Files|*.*";
                        if (sfd.ShowDialog() == DialogResult.OK)
                        {
                            File.WriteAllBytes(sfd.FileName, imageBytes);
                            Log("LSASS stealth dump saved: {0} ({1} bytes)", sfd.FileName, imageSize);
                            statusLabel.Text = "LSASS dump saved";
                        }
                    }
                }));
            });
        }

        private async Task DumpModules(ModuleSummary[] modules)
        {
            if (waitIATCheckBox.Checked)
            {
                int waitSec = (int)waitSecondsUpDown.Value;
                if (waitSec > 0)
                {
                    Log("Polling kernel driver for IAT initialization (timeout {0}s)...", waitSec);
                    progressBar.Visible = true;
                    progressBar.Maximum = waitSec * 2;
                    progressBar.Value = 0;

                    int tableStatus = -1; // TABLES_NOT_READY
                    for (int i = 0; i < waitSec * 2; i++)
                    {
                        tableStatus = await Task.Run(() => driver.CheckTablesReady(processSummary.ProcessId));
                        progressBar.Value = i + 1;

                        if (tableStatus == 1) // TABLES_READY
                        {
                            Log("Kernel reports tables are RESOLVED");
                            break;
                        }
                        if (tableStatus == 2) // TABLES_NO_IMPORTS
                        {
                            Log("Kernel reports no import table (may be shellcode/module without imports)");
                            break;
                        }

                        await Task.Delay(500);
                    }

                    if (tableStatus == 0) // TABLES_NOT_READY after timeout
                    {
                        bool usermodeCheck = ValidateIATReady(modules[0]);
                        Log("Timeout reached. Usermode IAT check: {0}", usermodeCheck ? "RESOLVED" : "NOT YET (dumping anyway)");
                    }

                    progressBar.Visible = false;
                }
            }

            progressBar.Visible = true;
            progressBar.Maximum = modules.Length;
            progressBar.Value = 0;
            dumpSelectedBtn.Enabled = false;
            dumpAllBtn.Enabled = false;

            string outputDir = "";
            if (modules.Length > 1)
            {
                using (var fbd = new FolderBrowserDialog())
                {
                    fbd.Description = "Select output folder for dumped modules";
                    if (fbd.ShowDialog() != DialogResult.OK)
                    {
                        progressBar.Visible = false;
                        dumpSelectedBtn.Enabled = true;
                        dumpAllBtn.Enabled = true;
                        return;
                    }
                    outputDir = fbd.SelectedPath;
                }
            }

            int successCount = 0;
            int failCount = 0;

            await Task.Run(() =>
            {
                for (int i = 0; i < modules.Length; i++)
                {
                    var mod = modules[i];
                    var modProcessSummary = new ProcessSummary(
                        processSummary.ProcessId,
                        processSummary.ProcessName,
                        mod.BaseAddress,
                        mod.FileName,
                        mod.ImageSize,
                        mod.EntryPoint);

                    if (dumper.DumpProcess(modProcessSummary, out PEFile peFile, rebuildImportsCheckBox.Checked))
                    {
                        string fileName = string.IsNullOrEmpty(mod.FileName)
                            ? $"hidden_0x{mod.BaseAddress:x}_dump.exe"
                            : mod.ModuleName.Replace(".dll", "_dump.dll").Replace(".exe", "_dump.exe");

                        string savePath = modules.Length > 1
                            ? Path.Combine(outputDir, fileName)
                            : PromptSavePath(fileName);

                        if (!string.IsNullOrEmpty(savePath))
                        {
                            peFile.SaveToDisk(savePath);
                            this.SafeInvoke(new Action(() => Log("Saved: {0}", savePath)));

                            // Save analysis report alongside the dump
                            try
                            {
                                string reportPath = Path.ChangeExtension(savePath, null) + "_analysis.txt";
                                var rtti = PEAnalyzer.ScanRTTI(peFile);
                                var vt = PEAnalyzer.FindVTables(peFile, mod.BaseAddress);
                                var strs = PEAnalyzer.ExtractStrings(peFile);
                                var stats = PEAnalyzer.GetImportStats(peFile);
                                PEAnalyzer.WriteReport(reportPath, peFile, rtti, vt, strs, stats);

                                // Append entropy analysis
                                var entropy = PEAnalyzer.CalculateEntropy(peFile);
                                using (var entropyWriter = new StreamWriter(reportPath, true))
                                {
                                    entropyWriter.WriteLine();
                                    entropyWriter.WriteLine("--- Section Entropy ---");
                                    foreach (var sec in entropy)
                                        entropyWriter.WriteLine("  [{0}] RVA: 0x{1:X8} Size: {2} Entropy: {3:F2} ({4})",
                                            sec.Name, sec.RVA, sec.Size, sec.Entropy, sec.Assessment);
                                }

                                this.SafeInvoke(new Action(() => Log("Report: {0}", reportPath)));
                            }
                            catch (Exception ex)
                            {
                                this.SafeInvoke(new Action(() => Log("Report error: {0}", ex.Message)));
                            }

                            successCount++;
                        }
                    }
                    else
                    {
                        this.SafeInvoke(new Action(() => Log("FAILED: {0} @ 0x{1:x}", mod.ModuleName, mod.BaseAddress)));
                        failCount++;
                    }

                    int idx = i + 1;
                    this.SafeInvoke(new Action(() => progressBar.Value = idx));
                }
            });

            progressBar.Visible = false;
            dumpSelectedBtn.Enabled = true;
            dumpAllBtn.Enabled = true;
            statusLabel.Text = $"Dumped: {successCount} success, {failCount} failed";
            Log("Batch dump complete: {0} success, {1} failed", successCount, failCount);
        }

        // Checks if the IAT entries in the target module's import table contain resolved function addresses
        // (i.e., values outside the module's own VA range). If all thunks still point into the IAT itself,
        // the imports haven't been resolved yet (common with delayed-init anti-cheat packed binaries).
        private bool ValidateIATReady(ModuleSummary mainModule)
        {
            IntPtr basePtr = (IntPtr)mainModule.BaseAddress;
            var dosHeader = ReadStruct<IMAGE_DOS_HEADER>(basePtr);

            if (!dosHeader.IsValid) return false;

            var peHeaderPtr = basePtr + dosHeader.e_lfanew;
            // Read enough of the PE header to get to the import directory
            byte[] peBytes = ReadBytes(peHeaderPtr, 264);
            if (peBytes.Length < 264) return false;

            // Parse import directory RVA from optional header data directory[1]
            // PE signature (4) + FileHeader (20) + OptionalHeader magic (2) + ...
            // Data directory starts at offset 112 from PE signature for PE32+, 96 for PE32
            // Import directory is entry [1] at offset +8 from data dir start
            int optHeaderOffset = 24; // after PE sig + FileHeader
            ushort magic = BitConverter.ToUInt16(peBytes, optHeaderOffset);
            int dataDirOffset = magic == 0x20b ? optHeaderOffset + 112 : optHeaderOffset + 96; // PE32+ vs PE32
            int importDirRVA = BitConverter.ToInt32(peBytes, dataDirOffset + 8);

            if (importDirRVA == 0) return false; // No import table

            // Read first import descriptor (20 bytes)
            IntPtr importDescPtr = basePtr + importDirRVA;
            byte[] descBytes = ReadBytes(importDescPtr, 20);
            if (descBytes.Length < 20) return false;

            int firstThunkRVA = BitConverter.ToInt32(descBytes, 16);
            if (firstThunkRVA == 0) return false;

            // Read first thunk entry (8 bytes for x64)
            IntPtr thunkPtr = basePtr + firstThunkRVA;
            byte[] thunkBytes = ReadBytes(thunkPtr, 8);
            if (thunkBytes.Length < 8) return false;

            ulong thunkValue = BitConverter.ToUInt64(thunkBytes, 0);
            if (thunkValue == 0) return false;

            // If the thunk points to an address within the module's VA range, imports aren't resolved yet
            ulong moduleStart = mainModule.BaseAddress;
            ulong moduleEnd = moduleStart + mainModule.ImageSize;
            return thunkValue < moduleStart || thunkValue >= moduleEnd;
        }

        private T ReadStruct<T>(IntPtr address) where T : struct
        {
            int size = System.Runtime.InteropServices.Marshal.SizeOf<T>();
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return default(T);
            try
            {
                if (driver.CopyVirtualMemory(processSummary.ProcessId, address, buffer, size))
                    return System.Runtime.InteropServices.Marshal.PtrToStructure<T>(buffer);
                return default(T);
            }
            finally
            {
                WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
        }

        private byte[] ReadBytes(IntPtr address, int size)
        {
            IntPtr buffer = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buffer == IntPtr.Zero) return new byte[size];
            driver.CopyVirtualMemory(processSummary.ProcessId, address, buffer, size);
            byte[] result = new byte[size];
            System.Runtime.InteropServices.Marshal.Copy(buffer, result, 0, size);
            WinApi.VirtualFree(buffer, UIntPtr.Zero, WinApi.MEM_RELEASE);
            return result;
        }

        private string PromptSavePath(string defaultName)
        {
            string result = null;
            this.SafeInvoke(new Action(() =>
            {
                using (var sfd = new SaveFileDialog())
                {
                    sfd.FileName = defaultName;
                    sfd.Filter = "Executable Files|*.exe;*.dll|All Files|*.*";
                    if (sfd.ShowDialog() == DialogResult.OK)
                        result = sfd.FileName;
                }
            }));
            return result;
        }

        private void Log(string message, params object[] args)
        {
            this.SafeInvoke(new Action(() =>
            {
                logTextBox.AppendText($"[{DateTime.Now.ToLongTimeString()}] {string.Format(message, args)}\n");
            }));
        }

        private AntiCheatType GetSelectedAntiCheatType()
        {
            switch (acComboBox.SelectedIndex)
            {
                case 1: return AntiCheatType.EasyAntiCheat;
                case 2: return AntiCheatType.BattlEye;
                default: return AntiCheatType.None;
            }
        }

        private void SuspendACBtn_Click(object sender, EventArgs e)
        {
            var acType = GetSelectedAntiCheatType();
            if (acType == AntiCheatType.None)
            {
                Log("Select an anti-cheat first");
                return;
            }

            suspendACBtn.Enabled = false;
            Task.Run(() =>
            {
                int count = AntiCheatBypass.SuspendAntiCheatProcesses(driver, acType, msg => this.SafeInvoke(new Action(() => Log(msg))));
                this.SafeInvoke(new Action(() =>
                {
                    suspendACBtn.Enabled = true;
                    statusLabel.Text = $"Suspended {count} AC threads";
                }));
            });
        }

        private void ResumeACBtn_Click(object sender, EventArgs e)
        {
            var acType = GetSelectedAntiCheatType();
            if (acType == AntiCheatType.None)
            {
                Log("Select an anti-cheat first");
                return;
            }

            resumeACBtn.Enabled = false;
            Task.Run(() =>
            {
                int count = AntiCheatBypass.ResumeAntiCheatProcesses(driver, acType, msg => this.SafeInvoke(new Action(() => Log(msg))));
                this.SafeInvoke(new Action(() =>
                {
                    resumeACBtn.Enabled = true;
                    statusLabel.Text = $"Resumed {count} AC threads";
                }));
            });
        }

        private void BypassACBtn_Click(object sender, EventArgs e)
        {
            var acType = GetSelectedAntiCheatType();
            if (acType == AntiCheatType.None)
            {
                Log("Select an anti-cheat first");
                return;
            }

            var result = MessageBox.Show(
                $"This will stop {acType} services, kill its processes, and unload its drivers.\nContinue?",
                "Anti-Cheat Bypass",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning);

            if (result != DialogResult.Yes)
                return;

            bypassACBtn.Enabled = false;
            Task.Run(() =>
            {
                var bypassResult = AntiCheatBypass.Execute(driver, acType, msg => this.SafeInvoke(new Action(() => Log(msg))));
                this.SafeInvoke(new Action(() =>
                {
                    bypassACBtn.Enabled = true;
                    statusLabel.Text = $"Bypass: {bypassResult.ProcessesKilled} killed, {bypassResult.ServicesStopped} stopped, {bypassResult.DriversUnloaded} unloaded";
                }));
            });
        }

        // Minimal IMAGE_DOS_HEADER wrapper for IAT validation
        private struct IMAGE_DOS_HEADER
        {
            public ushort e_magic;
            public ushort e_cblp, e_cp, e_crlc, e_cparhdr, e_minalloc, e_maxalloc;
            public ushort e_ss, e_sp, e_csum, e_ip, e_cs, e_lfarlc, e_ovno;
            public ushort e_res0, e_res1, e_res2, e_res3;
            public ushort e_oemid, e_oeminfo;
            public ushort e_res4, e_res5, e_res6, e_res7, e_res8, e_res9, e_res10, e_res11, e_res12, e_res13;
            public int e_lfanew;

            public bool IsValid => e_magic == 0x5A4D;
        }
    }
}
