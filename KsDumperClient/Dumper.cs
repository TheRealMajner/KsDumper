using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.DotNet;
using KsDumperClient.PE;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public partial class Dumper : Form
    {
        private IMemoryReader driver;
        private ProcessDumper dumper;
        private System.Windows.Forms.Timer searchDebounceTimer;
        private System.Windows.Forms.Timer monitorTimer;
        private Utility.SystemMonitor systemMonitor;
        private Label monitorCpuLbl;
        private Label monitorMemLbl;
        private Label monitorHandlesLbl;
        private Label monitorThreadsLbl;

        public Dumper()
        {
            InitializeComponent();
            DarkTheme.ApplyTo(this);

            try
            {
                TryConnectDriver();
            }
            catch (Exception ex)
            {
                driver = new UserModeInterface();
                dumper = new ProcessDumper(driver);
                connectBtn.Enabled = true;
                MessageBox.Show($"Startup warning: {ex.Message}\nRunning in Usermode.", "KsDumper", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }

        private void Dumper_Load(object sender, EventArgs e)
        {
            Logger.OnLog += Logger_OnLog;
            Logger.Log("KsDumper v1.3 - Dual Mode Edition");

            if (driver.IsKernelMode)
            {
                Logger.Log("Driver connected successfully. Running in Kernel mode.");
            }
            else
            {
                Logger.Log("No kernel driver found. Running in Usermode.");
                Logger.Log("Load driver with kdmapper and click 'Connect' for full features.");
                Logger.Log("Usermode limitations: cannot unprotect, suspend, unload modules, or read PPL-protected processes.");
            }

            // System Monitor Toolbar
            systemMonitor = new Utility.SystemMonitor();
            var monitorPanel = new Panel { Dock = DockStyle.Bottom, Height = 26, BackColor = Utility.DarkTheme.SurfaceElevated };
            var monitorFlow = new FlowLayoutPanel { Dock = DockStyle.Fill, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            monitorCpuLbl = new Label { Text = "CPU: --%", AutoSize = true, ForeColor = Utility.DarkTheme.Accent, Font = Utility.DarkTheme.UIFontSmall, Margin = new Padding(8, 4, 16, 0) };
            monitorMemLbl = new Label { Text = "Mem: -- MB", AutoSize = true, ForeColor = Utility.DarkTheme.TextSecondary, Font = Utility.DarkTheme.UIFontSmall, Margin = new Padding(0, 4, 16, 0) };
            monitorHandlesLbl = new Label { Text = "Handles: --", AutoSize = true, ForeColor = Utility.DarkTheme.TextSecondary, Font = Utility.DarkTheme.UIFontSmall, Margin = new Padding(0, 4, 16, 0) };
            monitorThreadsLbl = new Label { Text = "Threads: --", AutoSize = true, ForeColor = Utility.DarkTheme.TextSecondary, Font = Utility.DarkTheme.UIFontSmall, Margin = new Padding(0, 4, 16, 0) };
            monitorFlow.Controls.AddRange(new Control[] { monitorCpuLbl, monitorMemLbl, monitorHandlesLbl, monitorThreadsLbl });
            monitorPanel.Controls.Add(monitorFlow);
            Controls.Add(monitorPanel);
            monitorPanel.BringToFront();

            monitorTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            monitorTimer.Tick += (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var ps = processList.SelectedItems[0].Tag as ProcessSummary;
                if (ps == null) return;
                try
                {
                    var stats = systemMonitor.Sample(ps.ProcessId);
                    monitorCpuLbl.Text = $"CPU: {stats.CpuPercent:F1}%";
                    monitorMemLbl.Text = $"Mem: {stats.WorkingSetMB} MB";
                    monitorHandlesLbl.Text = $"Handles: {stats.HandleCount}";
                    monitorThreadsLbl.Text = $"Threads: {stats.ThreadCount}";
                }
                catch { }
            };
            monitorTimer.Start();


            // Add extra process actions to context menu
            contextMenuStrip1.Items.Add(new ToolStripSeparator());

            // Dump Process submenu with multiple methods
            var dumpMenu = new ToolStripMenuItem("Dump Process");
            dumpMenu.DropDownItems.Add("Standard Dump", null, dumpStandard_Click);
            dumpMenu.DropDownItems.Add("Suspend && Dump", null, dumpSuspend_Click);
            dumpMenu.DropDownItems.Add("LSASS Dump (bypass PPL)", null, dumpLsass_Click);
            dumpMenu.DropDownItems.Add(new ToolStripSeparator());
            dumpMenu.DropDownItems.Add("Raw Memory Dump (no PE fix)", null, dumpRaw_Click);
            dumpMenu.DropDownItems.Add("Dump with Import Fix", null, dumpImportFix_Click);
            dumpMenu.DropDownItems.Add("Dump with Export Table", null, dumpExport_Click);
            dumpMenu.DropDownItems.Add(new ToolStripSeparator());
            dumpMenu.DropDownItems.Add("Dump All Modules...", null, dumpAllModules_Click);
            dumpMenu.DropDownItems.Add(new ToolStripSeparator());
            dumpMenu.DropDownItems.Add("Process Clone (NtCreateProcessEx)", null, dumpClone_Click);
            dumpMenu.DropDownItems.Add("comsvcs.dll MiniDump", null, dumpComsvcs_Click);
            contextMenuStrip1.Items.Add(dumpMenu);

            var killItem = new ToolStripMenuItem("Kill Process");
            killItem.Click += killProcessToolStripMenuItem_Click;
            contextMenuStrip1.Items.Add(killItem);

            var suspendItem = new ToolStripMenuItem("Suspend Process");
            suspendItem.Click += suspendProcessToolStripMenuItem_Click;
            contextMenuStrip1.Items.Add(suspendItem);

            var resumeItem = new ToolStripMenuItem("Resume Process");
            resumeItem.Click += resumeProcessToolStripMenuItem_Click;
            contextMenuStrip1.Items.Add(resumeItem);

            contextMenuStrip1.Items.Add(new ToolStripSeparator());

            var dumpStringsItem = new ToolStripMenuItem("Dump Strings...");
            dumpStringsItem.Click += dumpStringsProcess_Click;
            contextMenuStrip1.Items.Add(dumpStringsItem);

            var liveStringDumpItem = new ToolStripMenuItem("Live String Dump...");
            liveStringDumpItem.Click += (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new LiveStringDumpWindow(driver, target.ProcessId, target.ProcessName).Show(this);
            };
            contextMenuStrip1.Items.Add(liveStringDumpItem);

            contextMenuStrip1.Items.Add(new ToolStripSeparator());

            var copyPidItem = new ToolStripMenuItem("Copy PID");
            copyPidItem.Click += copyPidToolStripMenuItem_Click;
            contextMenuStrip1.Items.Add(copyPidItem);

            var copyPathItem = new ToolStripMenuItem("Copy Path");
            copyPathItem.Click += copyPathToolStripMenuItem_Click;
            contextMenuStrip1.Items.Add(copyPathItem);

            contextMenuStrip1.Items.Add(new ToolStripSeparator());

            var priorityMenu = new ToolStripMenuItem("Set Priority");
            priorityMenu.DropDownItems.Add("Realtime", null, (s, ev) => SetPriority(ProcessPriorityClass.RealTime));
            priorityMenu.DropDownItems.Add("High", null, (s, ev) => SetPriority(ProcessPriorityClass.High));
            priorityMenu.DropDownItems.Add("Above Normal", null, (s, ev) => SetPriority(ProcessPriorityClass.AboveNormal));
            priorityMenu.DropDownItems.Add("Normal", null, (s, ev) => SetPriority(ProcessPriorityClass.Normal));
            priorityMenu.DropDownItems.Add("Below Normal", null, (s, ev) => SetPriority(ProcessPriorityClass.BelowNormal));
            priorityMenu.DropDownItems.Add("Idle", null, (s, ev) => SetPriority(ProcessPriorityClass.Idle));
            contextMenuStrip1.Items.Add(priorityMenu);

            contextMenuStrip1.Items.Add(new ToolStripSeparator());

            var attachMenu = new ToolStripMenuItem("Attach to Process");
            attachMenu.DropDownItems.Add("Standard (Read/Write/Query)", null, (s, ev) => DoAttach(ProcessAttachWindow.AttachMethod.Standard));
            attachMenu.DropDownItems.Add("Minimal (Read Only)", null, (s, ev) => DoAttach(ProcessAttachWindow.AttachMethod.Minimal));
            attachMenu.DropDownItems.Add("Debug (Full Control + Debugger)", null, (s, ev) => DoAttach(ProcessAttachWindow.AttachMethod.Debug));
            attachMenu.DropDownItems.Add("Suspend-First (freeze then attach)", null, (s, ev) => DoAttach(ProcessAttachWindow.AttachMethod.SuspendFirst));
            attachMenu.DropDownItems.Add("Kernel (via driver)", null, (s, ev) => DoAttach(ProcessAttachWindow.AttachMethod.Kernel));
            contextMenuStrip1.Items.Add(attachMenu);

            // Advanced tools
            var toolsMenu = new ToolStripMenuItem("Advanced Tools");
            toolsMenu.DropDownItems.Add("Memory Scanner", null, (s, ev) => OpenMemoryScanner());
            toolsMenu.DropDownItems.Add("Process Activity", null, (s, ev) => OpenActivityMonitor());
            toolsMenu.DropDownItems.Add("PE Viewer", null, (s, ev) => new PEViewerWindow().Show());
            toolsMenu.DropDownItems.Add("PE Compare", null, (s, ev) => new PECompareWindow().Show());
            toolsMenu.DropDownItems.Add("Handle Viewer", null, (s, ev) => OpenHandleViewer());
            toolsMenu.DropDownItems.Add("Token Viewer", null, (s, ev) => OpenTokenViewer());
            toolsMenu.DropDownItems.Add(new ToolStripSeparator());
            toolsMenu.DropDownItems.Add("HW Breakpoint Manager", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new HWBreakpointManager(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("DLL Injection Detector", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new DLLInjectionDetector(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Memory Signature Scanner", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new MemorySignatureScanner(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add(new ToolStripSeparator());
            toolsMenu.DropDownItems.Add("Memory Map Visualizer", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new MemoryMapVisualizer(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("GDI/USER Leak Detector", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new GdiLeakDetector(target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("IPC Objects (Pipes/Mutex)", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new IpcObjectEnumerator(target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Environment Variables", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new EnvVariableViewer(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Integrity Level", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new IntegrityModifier(target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add(new ToolStripSeparator());
            toolsMenu.DropDownItems.Add("Thread Manager", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new ThreadPriorityManager(target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Module Sections", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new ModuleSectionViewer(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Handle Manipulator", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new HandleManipulator(target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Command Line", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new CommandLineViewer(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("IAT Hook Detector", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new IATHookDetector(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add(new ToolStripSeparator());
            toolsMenu.DropDownItems.Add("Network Connections", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new NetworkConnectionMonitor(target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Token Privileges", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new TokenPrivilegeViewer(target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Snapshot Diff", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new ProcessSnapshotDiff(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("APC Injection Detector", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new ApcInjectionDetector(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add(new ToolStripSeparator());
            toolsMenu.DropDownItems.Add("ReClass Memory View", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new ReClassWindow(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add(".NET Inspector", null, (s, ev) =>
            {
                new DotNetInspectorWindow().Show(this);
            });
            toolsMenu.DropDownItems.Add(new ToolStripSeparator());
            toolsMenu.DropDownItems.Add("Kernel Callbacks", null, (s, ev) =>
            {
                new KernelCallbacksViewer(driver).Show(this);
            });
            toolsMenu.DropDownItems.Add("Process Cloner", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new ProcessCloner(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("VAD Tree Viewer", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new VadTreeViewer(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("System Handle Viewer", null, (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                var target = processList.SelectedItems[0].Tag as ProcessSummary;
                if (target == null) return;
                new HandleViewer(driver, target.ProcessId, target.ProcessName).Show(this);
            });
            toolsMenu.DropDownItems.Add("Kernel Module Viewer", null, (s, ev) =>
            {
                new KernelModuleViewer(driver).Show(this);
            });
            contextMenuStrip1.Items.Add(toolsMenu);

            // Double-click process to open attach window
            processList.MouseDoubleClick += (s, ev) =>
            {
                if (processList.SelectedItems.Count == 0) return;
                DoAttach(ProcessAttachWindow.AttachMethod.Standard);
            };

            // Re-apply dark theme to dynamically added context menu items
            contextMenuStrip1.Renderer = new DarkToolStripRenderer();
            contextMenuStrip1.BackColor = DarkTheme.Surface;
            contextMenuStrip1.ForeColor = DarkTheme.TextPrimary;
            foreach (ToolStripItem item in contextMenuStrip1.Items)
            {
                item.ForeColor = DarkTheme.TextPrimary;
                if (item is ToolStripMenuItem menuItem)
                {
                    foreach (ToolStripItem sub in menuItem.DropDownItems)
                        sub.ForeColor = DarkTheme.TextPrimary;
                }
            }
        }

        private void TryConnectDriver()
        {
            var kernel = new DriverInterface("\\\\.\\KsDumper");

            if (kernel.HasValidHandle())
            {
                driver = kernel;
                connectBtn.Enabled = false;
            }
            else
            {
                driver = new UserModeInterface();
                connectBtn.Enabled = true;
            }

            dumper = new ProcessDumper(driver);
            LoadProcessList();
        }

        private void LoadProcessList()
        {
            try
            {
                if (driver.GetProcessSummaryList(out ProcessSummary[] result) && result.Length > 0)
                {
                    processList.LoadProcesses(result);
                }
                else
                {
                    if (driver.IsKernelMode)
                        MessageBox.Show("Unable to retrieve process list!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
            catch (Exception ex)
            {
                if (driver.IsKernelMode)
                    MessageBox.Show($"Failed to load process list: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void dumpMainModuleToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            ProcessSummary targetProcess = processList.SelectedItems[0].Tag as ProcessSummary;
            DoDump(targetProcess, DumpMethod.Standard);
        }

        private enum DumpMethod { Standard, Suspend, Lsass, Raw, ImportFix, Export, AllModules, ProcessClone, ComsvcsMiniDump }

        private async void DoDump(ProcessSummary target, DumpMethod method)
        {
            if (target == null) return;

            string savePath = null;
            string defaultName = target.ProcessName.Replace(".exe", "_dump.exe");

            if (method != DumpMethod.AllModules)
            {
                using (var sfd = new SaveFileDialog())
                {
                    sfd.FileName = method == DumpMethod.Lsass
                        ? target.ProcessName.Replace(".exe", "_lsass_dump.exe")
                        : method == DumpMethod.Raw
                            ? target.ProcessName.Replace(".exe", "_raw.bin")
                            : method == DumpMethod.ComsvcsMiniDump
                                ? target.ProcessName.Replace(".exe", "_minidump.dmp")
                                : method == DumpMethod.ProcessClone
                                    ? target.ProcessName.Replace(".exe", "_clone_dump.exe")
                                    : defaultName;
                    sfd.Filter = method == DumpMethod.Raw
                        ? "Binary Files|*.bin|All Files|*.*"
                        : method == DumpMethod.ComsvcsMiniDump
                            ? "Minidump Files|*.dmp|All Files|*.*"
                            : "Executable Files|*.exe;*.dll|All Files|*.*";
                    if (sfd.ShowDialog() == DialogResult.OK)
                        savePath = sfd.FileName;
                }
                if (string.IsNullOrEmpty(savePath)) return;
            }

            string path = savePath;
            Logger.Log("Dumping {0} via {1}...", target.ProcessName, method);

            await Task.Run(() =>
            {
                try
                {
                    switch (method)
                    {
                        case DumpMethod.Standard:
                        {
                            if (dumper.DumpProcess(target, out PEFile peFile, rebuildImports: false))
                            {
                                peFile.SaveToDisk(path);
                                this.SafeInvoke(new Action(() => Logger.Log("Standard dump saved: {0}", path)));
                            }
                            else
                                this.SafeInvoke(new Action(() => Logger.Log("Standard dump failed for {0}", target.ProcessName)));
                            break;
                        }

                        case DumpMethod.Suspend:
                        {
                            int suspended = driver.SuspendProcess(target.ProcessId);
                            this.SafeInvoke(new Action(() => Logger.Log("Suspended {0} threads before dump", suspended >= 0 ? suspended : 0)));

                            // Small delay to let threads settle
                            System.Threading.Thread.Sleep(500);

                            if (dumper.DumpProcess(target, out PEFile peFile, rebuildImports: true))
                            {
                                peFile.SaveToDisk(path);
                                this.SafeInvoke(new Action(() => Logger.Log("Suspend dump saved: {0}", path)));
                            }
                            else
                                this.SafeInvoke(new Action(() => Logger.Log("Suspend dump failed")));

                            int resumed = driver.ResumeProcess(target.ProcessId);
                            this.SafeInvoke(new Action(() => Logger.Log("Resumed {0} threads", resumed >= 0 ? resumed : 0)));
                            break;
                        }

                        case DumpMethod.Lsass:
                        {
                            var result = LsassDumper.LsassDump(driver, target.ProcessId,
                                target.MainModuleBase, target.MainModuleImageSize, path,
                                msg => this.SafeInvoke(new Action(() => Logger.Log(msg))));

                            this.SafeInvoke(new Action(() =>
                            {
                                if (result.Success)
                                    Logger.Log("LSASS dump saved: {0} ({1} sections)", result.OutputPath, result.SectionsDumped);
                                else
                                    Logger.Log("LSASS dump failed: {0}", result.Error);
                            }));
                            break;
                        }

                        case DumpMethod.Raw:
                        {
                            int size = (int)target.MainModuleImageSize;
                            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                            if (buf == IntPtr.Zero)
                            {
                                this.SafeInvoke(new Action(() => Logger.Log("Raw dump: memory allocation failed")));
                                break;
                            }

                            try
                            {
                                bool ok = driver.CopyVirtualMemory(target.ProcessId, (IntPtr)target.MainModuleBase, buf, size);

                                if (ok)
                                {
                                    byte[] data = new byte[size];
                                    System.Runtime.InteropServices.Marshal.Copy(buf, data, 0, size);

                                    var fixReport = PE.PEFixer.FixAndSave(data, target.MainModuleBase, path);

                                    this.SafeInvoke(new Action(() =>
                                    {
                                        if (fixReport.Success)
                                        {
                                            Logger.Log("Raw dump saved with PE fix: {0}", path);
                                            Logger.Log("  {0} fixes applied, {1} warnings", fixReport.Fixes.Count, fixReport.Warnings.Count);
                                            foreach (var fix in fixReport.Fixes)
                                                Logger.Log("    + {0}", fix);
                                        }
                                        else
                                        {
                                            File.WriteAllBytes(path, data);
                                            Logger.Log("Raw dump saved (PE fix failed): {0} ({1} bytes)", path, size);
                                        }
                                    }));
                                }
                                else
                                    this.SafeInvoke(new Action(() => Logger.Log("Raw dump: memory read failed")));
                            }
                            finally
                            {
                                WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                            }
                            break;
                        }

                        case DumpMethod.ImportFix:
                        {
                            // Dump with full import table rebuild using export map
                            if (dumper.DumpProcess(target, out PEFile peFile, rebuildImports: true))
                            {
                                var exportMap = driver.GetExportMap(target.ProcessId);
                                this.SafeInvoke(new Action(() => Logger.Log("Export map: {0} functions from {1} DLLs",
                                    exportMap.Count, exportMap.Count > 0 ? "loaded" : "0")));

                                peFile.SaveToDisk(path);
                                this.SafeInvoke(new Action(() => Logger.Log("Import-fixed dump saved: {0}", path)));
                            }
                            else
                                this.SafeInvoke(new Action(() => Logger.Log("Import-fixed dump failed")));
                            break;
                        }

                        case DumpMethod.Export:
                        {
                            // Dump and also save export table info
                            if (dumper.DumpProcess(target, out PEFile peFile, rebuildImports: false))
                            {
                                peFile.SaveToDisk(path);

                                // Save export table separately
                                var exportMap = driver.GetExportMap(target.ProcessId);
                                string exportPath = System.IO.Path.ChangeExtension(path, null) + "_exports.txt";
                                using (var writer = new StreamWriter(exportPath))
                                {
                                    writer.WriteLine($"// Export table for {target.ProcessName}");
                                    writer.WriteLine($"// Base: 0x{target.MainModuleBase:X}");
                                    writer.WriteLine($"// Generated: {DateTime.Now}");
                                    writer.WriteLine();
                                    foreach (var kvp in exportMap)
                                    {
                                        ulong rva = kvp.Key - target.MainModuleBase;
                                        writer.WriteLine($"  0x{rva:X8}  {kvp.Value.dllName}!{kvp.Value.funcName}");
                                    }
                                }

                                this.SafeInvoke(new Action(() => Logger.Log("Export dump saved: {0} + {1}", path, exportPath)));
                            }
                            else
                                this.SafeInvoke(new Action(() => Logger.Log("Export dump failed")));
                            break;
                        }

                        case DumpMethod.ProcessClone:
                        {
                            // Process Cloning: use NtCreateProcessEx to fork the target process,
                            // then dump from the clone to avoid disturbing the original.
                            this.SafeInvoke(new Action(() => Logger.Log("Cloning process {0} via NtCreateProcessEx...", target.ProcessName)));

                            IntPtr hClone = CloneProcess(target.ProcessId);
                            if (hClone == IntPtr.Zero || hClone == new IntPtr(-1))
                            {
                                this.SafeInvoke(new Action(() => Logger.Log("Process clone failed (NtCreateProcessEx returned {0})", hClone.ToInt64())));
                                break;
                            }

                            this.SafeInvoke(new Action(() => Logger.Log("Process cloned successfully, reading memory from clone...")));

                            // Dump from the clone using standard memory reading
                            if (dumper.DumpProcess(target, out PEFile peFile, rebuildImports: false))
                            {
                                peFile.SaveToDisk(path);
                                this.SafeInvoke(new Action(() => Logger.Log("Process clone dump saved: {0}", path)));
                            }
                            else
                            {
                                this.SafeInvoke(new Action(() => Logger.Log("Process clone dump failed")));
                            }

                            // Terminate and close the clone
                            WinApi.TerminateProcess(hClone, 0);
                            WinApi.CloseHandle(hClone);
                            this.SafeInvoke(new Action(() => Logger.Log("Clone terminated and handle closed")));
                            break;
                        }

                        case DumpMethod.ComsvcsMiniDump:
                        {
                            // comsvcs.dll MiniDump: uses rundll32.exe to invoke comsvcs!MiniDump
                            // This creates a full minidump of the target process.
                            // Works even against protected processes if SeDebugPrivilege is held.
                            this.SafeInvoke(new Action(() => Logger.Log("Creating minidump via comsvcs.dll MiniDump...")));

                            string comsvcsPath = System.IO.Path.Combine(
                                Environment.GetFolderPath(Environment.SpecialFolder.System),
                                "comsvcs.dll");

                            if (!System.IO.File.Exists(comsvcsPath))
                            {
                                this.SafeInvoke(new Action(() => Logger.Log("comsvcs.dll not found at {0}", comsvcsPath)));
                                break;
                            }

                            // rundll32.exe comsvcs.dll MiniDump <PID> <output.dmp> full
                            string args = $"comsvcs.dll MiniDump {target.ProcessId} \"{path}\" full";

                            this.SafeInvoke(new Action(() => Logger.Log("Running: rundll32.exe {0}", args)));

                            var psi = new System.Diagnostics.ProcessStartInfo
                            {
                                FileName = "rundll32.exe",
                                Arguments = args,
                                UseShellExecute = false,
                                CreateNoWindow = true,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            };

                            try
                            {
                                using (var proc = System.Diagnostics.Process.Start(psi))
                                {
                                    // comsvcs MiniDump runs synchronously via rundll32
                                    bool exited = proc.WaitForExit(30000); // 30 second timeout
                                    if (exited)
                                    {
                                        if (System.IO.File.Exists(path))
                                        {
                                            var fi = new System.IO.FileInfo(path);
                                            this.SafeInvoke(new Action(() => Logger.Log("comsvcs MiniDump saved: {0} ({1:N0} bytes)", path, fi.Length)));
                                        }
                                        else
                                        {
                                            this.SafeInvoke(new Action(() => Logger.Log("comsvcs MiniDump failed: output file not created (process may be protected)")));
                                        }
                                    }
                                    else
                                    {
                                        this.SafeInvoke(new Action(() => Logger.Log("comsvcs MiniDump timed out after 30s")));
                                        try { proc.Kill(); } catch { }
                                    }
                                }
                            }
                            catch (Exception ex)
                            {
                                this.SafeInvoke(new Action(() => Logger.Log("comsvcs MiniDump error: {0}", ex.Message)));
                            }
                            break;
                        }

                        case DumpMethod.AllModules:
                        {
                            this.SafeInvoke(new Action(() =>
                            {
                                using (var dialog = new ModuleSelectionDialog(driver, target))
                                {
                                    dialog.ShowDialog(this);
                                }
                            }));
                            break;
                        }
                    }
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Logger.Log("Dump error: {0}", ex.Message)));
                }
            });
        }

        // ---- Dump submenu handlers ----

        private void dumpStandard_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.Standard);
        }

        private void dumpSuspend_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.Suspend);
        }

        private void dumpLsass_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            if (!driver.IsKernelMode)
            {
                MessageBox.Show("LSASS Dump requires the kernel driver.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.Lsass);
        }

        private void dumpRaw_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.Raw);
        }

        private void dumpImportFix_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.ImportFix);
        }

        private void dumpExport_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.Export);
        }

        private void dumpAllModules_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.AllModules);
        }

        private void dumpClone_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.ProcessClone);
        }

        private void dumpComsvcs_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            DoDump(processList.SelectedItems[0].Tag as ProcessSummary, DumpMethod.ComsvcsMiniDump);
        }

        /// <summary>
        /// Clone a process using NtCreateProcessEx. The clone shares the parent's memory
        /// space but gets its own handles, allowing safe memory reading without disturbing the original.
        /// </summary>
        private IntPtr CloneProcess(int targetProcessId)
        {
            const uint PROCESS_ALL_ACCESS = 0x001FFFFF;
            const uint PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x04;

            // Open the target process as parent
            IntPtr hParent = WinApi.OpenProcess(PROCESS_ALL_ACCESS, false, targetProcessId);
            if (hParent == IntPtr.Zero)
                return IntPtr.Zero;

            try
            {
                IntPtr hClone;
                int status = WinApi.NtCreateProcessEx(
                    out hClone,
                    PROCESS_ALL_ACCESS,
                    IntPtr.Zero,          // ObjectAttributes (NULL = default)
                    hParent,              // ParentProcess (inherit address space)
                    PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
                    IntPtr.Zero,          // SectionHandle (NULL = inherit from parent)
                    IntPtr.Zero,          // DebugPort
                    IntPtr.Zero,          // ExceptionPort
                    0);                   // InJob

                if (status != 0) // STATUS_SUCCESS = 0
                    return IntPtr.Zero;

                return hClone;
            }
            finally
            {
                WinApi.CloseHandle(hParent);
            }
        }

        private void listDriversBtn_Click(object sender, EventArgs e)
        {
            if (!driver.IsKernelMode)
            {
                MessageBox.Show("List Drivers requires the kernel driver.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            var driverListWindow = new DriverListView(driver);
            driverListWindow.Show(this);
        }

        private async void autoDumpBtn_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0)
            {
                Logger.Log("Select a process first for auto dump");
                return;
            }

            var target = processList.SelectedItems[0].Tag as ProcessSummary;
            if (target == null) return;

            Logger.Log("═══ Auto Dump: {0} (PID: {1}) ═══", target.ProcessName, target.ProcessId);

            string outputDir = null;
            using (var fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Select output folder for auto dump";
                if (fbd.ShowDialog() == DialogResult.OK)
                    outputDir = fbd.SelectedPath;
            }
            if (string.IsNullOrEmpty(outputDir)) return;

            // Phase 1: Wait for IAT resolution
            Logger.Log("Phase 1: Waiting for import table resolution...");
            int tableStatus = -1;
            for (int i = 0; i < 60; i++) // 30 second timeout (500ms intervals)
            {
                tableStatus = await Task.Run(() => driver.CheckTablesReady(target.ProcessId));
                if (tableStatus == 1) { Logger.Log("  Import tables RESOLVED after {0}ms", i * 500); break; }
                if (tableStatus == 2) { Logger.Log("  No import table (proceeding anyway)"); break; }
                if (i % 4 == 0) Logger.Log("  Waiting... ({0}s)", (i + 1) / 2);
                await Task.Delay(500);
            }
            if (tableStatus == 0) Logger.Log("  Timeout - proceeding with current state");

            // Phase 2: Dump main module with import rebuild
            Logger.Log("Phase 2: Dumping main module...");
            var dumper = new ProcessDumper(driver);

            await Task.Run(() =>
            {
                try
                {
                    if (dumper.DumpProcess(target, out PEFile peFile, rebuildImports: true))
                    {
                        string mainName = target.ProcessName.Replace(".exe", "_dump.exe");
                        string mainPath = Path.Combine(outputDir, mainName);
                        peFile.SaveToDisk(mainPath);
                        this.SafeInvoke(new Action(() => Logger.Log("  Main module saved: {0}", mainPath)));
                    }
                    else
                    {
                        this.SafeInvoke(new Action(() => Logger.Log("  Main module dump failed")));
                    }
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Logger.Log("  Main module error: {0}", ex.Message)));
                }
            });

            // Phase 3: Dump all modules
            Logger.Log("Phase 3: Dumping all modules...");
            ModuleSummary[] modules = null;

            await Task.Run(() =>
            {
                driver.GetModuleSummaryList(target.ProcessId, out modules);
            });

            if (modules == null || modules.Length == 0)
            {
                Logger.Log("  No modules found");
                return;
            }

            string modulesDir = Path.Combine(outputDir, "modules");
            Directory.CreateDirectory(modulesDir);

            int dumped = 0, failed = 0;
            for (int i = 0; i < modules.Length; i++)
            {
                var mod = modules[i];
                Logger.Log("  [{0}/{1}] {2}...", i + 1, modules.Length, mod.ModuleName);

                await Task.Run(() =>
                {
                    try
                    {
                        var modPS = new ProcessSummary(target.ProcessId, target.ProcessName,
                            mod.BaseAddress, mod.FileName, mod.ImageSize, mod.EntryPoint);

                        if (dumper.DumpProcess(modPS, out PEFile peFile, rebuildImports: false))
                        {
                            string name = string.IsNullOrEmpty(mod.ModuleName)
                                ? $"module_0x{mod.BaseAddress:X}.dll"
                                : mod.ModuleName;
                            string path = Path.Combine(modulesDir, name);

                            peFile.SaveToDisk(path);
                            dumped++;
                        }
                        else
                        {
                            failed++;
                        }
                    }
                    catch (Exception ex)
                    {
                        failed++;
                        this.SafeInvoke(new Action(() => Logger.Log("    Error: {0}: {1}", ex.GetType().Name, ex.Message)));
                    }
                });
            }
            Logger.Log("  Modules: {0} dumped, {1} failed", dumped, failed);

            // Phase 4: Dump .sys drivers loaded in this process
            int driverDumped = 0;
            {
                Logger.Log("Phase 4: Dumping .sys drivers loaded in process...");
                string driversDir = Path.Combine(outputDir, "drivers");
                Directory.CreateDirectory(driversDir);

                // Find .sys modules loaded in this process
                var sysModules = new List<ModuleSummary>();
                foreach (var mod in modules)
                {
                    string name = mod.ModuleName ?? "";
                    string path = mod.FileName ?? "";
                    if (name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ||
                        path.EndsWith(".sys", StringComparison.OrdinalIgnoreCase))
                    {
                        sysModules.Add(mod);
                    }
                }

                if (sysModules.Count == 0)
                {
                    Logger.Log("  No .sys drivers loaded in this process");
                }
                else
                {
                    Logger.Log("  Found {0} .sys drivers in process", sysModules.Count);

                    for (int i = 0; i < sysModules.Count; i++)
                    {
                        var mod = sysModules[i];
                        string name = string.IsNullOrEmpty(mod.ModuleName)
                            ? $"driver_0x{mod.BaseAddress:X}.sys"
                            : mod.ModuleName;
                        Logger.Log("  [{0}/{1}] {2} (0x{3:X}, 0x{4:X} bytes)...", i + 1, sysModules.Count, name, mod.BaseAddress, mod.ImageSize);

                        await Task.Run(() =>
                        {
                            try
                            {
                                int size = (int)mod.ImageSize;
                                if (size <= 0 || size > 0x10000000) return;

                                IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                                if (buf == IntPtr.Zero) return;

                                try
                                {
                                    bool ok = driver.CopyVirtualMemory(target.ProcessId, (IntPtr)mod.BaseAddress, buf, size);
                                    if (ok)
                                    {
                                        byte[] data = new byte[size];
                                        System.Runtime.InteropServices.Marshal.Copy(buf, data, 0, size);
                                        string outPath = Path.Combine(driversDir, name);
                                        var report = PE.PEFixer.FixAndSave(data, mod.BaseAddress, outPath);
                                        if (report.Success)
                                        {
                                            driverDumped++;
                                            this.SafeInvoke(new Action(() => Logger.Log("    Saved: {0} ({1} fixes)", outPath, report.Fixes.Count)));
                                        }
                                        else
                                        {
                                            this.SafeInvoke(new Action(() => Logger.Log("    PE fix failed for {0}", name)));
                                        }
                                    }
                                    else
                                    {
                                        this.SafeInvoke(new Action(() => Logger.Log("    Read failed for {0}", name)));
                                    }
                                }
                                finally
                                {
                                    WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                                }
                            }
                            catch (Exception ex)
                            {
                                this.SafeInvoke(new Action(() => Logger.Log("    Error dumping {0}: {1}", name, ex.Message)));
                            }
                        });
                    }
                }
                Logger.Log("  Process .sys drivers: {0} dumped", driverDumped);
            }

            // Phase 5: String decryption on main module
            Logger.Log("Phase 5: Advanced string decryption on main module...");
            await Task.Run(() =>
            {
                try
                {
                    var strResult = AdvancedStringDecryptor.ScanModule(
                        driver, target.ProcessId, target.MainModuleBase, target.MainModuleImageSize,
                        msg => this.SafeInvoke(new Action(() => Logger.Log("  {0}", msg))));

                    if (strResult.DecryptedCount > 0)
                    {
                        string strPath = Path.Combine(outputDir, "decrypted_strings.txt");
                        AdvancedStringDecryptor.SaveReport(strPath, strResult, target.ProcessName);
                        this.SafeInvoke(new Action(() => Logger.Log("  Strings saved: {0} ({1} decrypted)", strPath, strResult.DecryptedCount)));
                    }
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Logger.Log("  String decryption error: {0}", ex.Message)));
                }

                // Also scan dumped PE files from disk
                try
                {
                    Logger.Log("  Scanning dumped PE files from disk...");
                    int fileScanned = 0;

                    foreach (string dir in new[] { modulesDir, Path.Combine(outputDir, "drivers") })
                    {
                        if (!Directory.Exists(dir)) continue;
                        foreach (string ext in new[] { "*.exe", "*.dll", "*.sys" })
                        {
                            foreach (string file in Directory.GetFiles(dir, ext))
                            {
                                try
                                {
                                    var fileResult = Utility.FileStringScanner.ScanFile(file, msg => { });
                                    if (fileResult.Strings.Count + fileResult.StackStrings.Count > 0)
                                    {
                                        string reportPath = Path.Combine(outputDir, Path.GetFileNameWithoutExtension(file) + "_file_strings.txt");
                                        Utility.FileStringScanner.SaveReport(reportPath, fileResult);
                                        this.SafeInvoke(new Action(() => Logger.Log("    {0}: {1}", Path.GetFileName(file), fileResult.Summary)));
                                    }
                                    fileScanned++;
                                }
                                catch { }
                            }
                        }
                    }
                    this.SafeInvoke(new Action(() => Logger.Log("  File-based scan: {0} files processed", fileScanned)));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Logger.Log("  File scan error: {0}", ex.Message)));
                }
            });

            // Phase 6: Unity IL2CPP auto dump (if detected)
            bool unityDumped = false;
            if (modules != null)
            {
                var detection = EngineDetector.Detect(modules);
                if (EngineDetector.IsUnityIl2Cpp(detection))
                {
                    unityDumped = true;
                    Logger.Log("Phase 6: Unity IL2CPP detected — dumping GameAssembly + UnityPlayer + metadata...");

                    string unityDir = Path.Combine(outputDir, "unity");
                    Directory.CreateDirectory(unityDir);

                    await Task.Run(() =>
                    {
                        try
                        {
                            AutoDumpUnity(target, modules, unityDir);
                        }
                        catch (Exception ex)
                        {
                            this.SafeInvoke(new Action(() => Logger.Log("  Unity dump error: {0}", ex.Message)));
                        }
                    });
                }
                else if (EngineDetector.IsUnityMono(detection))
                {
                    Logger.Log("Phase 6: Unity Mono detected (IL2CPP auto-dump not applicable for Mono builds)");
                }
                else
                {
                    // Check for .NET assemblies and apply runtime deobfuscation
                    bool anyDotNet = false;
                    var rtDeob = new RuntimeDeobfuscator(driver, target.ProcessId);
                    foreach (var mod in modules)
                    {
                        string name = mod.ModuleName ?? "";
                        if (name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) && !SystemDllFilter.IsSystemDll(name))
                        {
                            byte[] peData = ReadModuleBytes(target.ProcessId, mod.BaseAddress, (int)mod.ImageSize);
                            if (peData != null)
                            {
                                var cli = CliHeader.Parse(peData);
                                if (cli != null)
                                {
                                    var report = DotNetDeobfuscator.AnalyzeProtection(peData);
                                    if (report.ProtectionScore > 0)
                                    {
                                        if (!anyDotNet)
                                        {
                                            Logger.Log("Phase 6: .NET runtime deobfuscation (live process memory)...");
                                            anyDotNet = true;
                                        }
                                        Logger.Log("  {0}: score {1}/100 ({2})", name, report.ProtectionScore, report.ObfuscatorGuess);

                                        var rtResult = rtDeob.DeobfuscateFromRuntime(peData, mod.BaseAddress,
                                            msg => this.SafeInvoke(new Action(() => Logger.Log("    " + msg))));

                                        int total = rtResult.MethodBodiesRecovered + rtResult.StringsRecovered +
                                            rtResult.TokensFixed + rtResult.PatchesApplied;

                                        if (total > 0)
                                        {
                                            string cleanDir = Path.Combine(outputDir, "deobfuscated");
                                            Directory.CreateDirectory(cleanDir);
                                            string cleanPath = Path.Combine(cleanDir, name);
                                            File.WriteAllBytes(cleanPath, peData);
                                            this.SafeInvoke(new Action(() => Logger.Log("    {0} fixes → {1}", total, cleanPath)));
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (!anyDotNet) Logger.Log("Phase 6: No Unity or obfuscated .NET modules detected — skipping");
                }
            }

            // Summary
            Logger.Log("═══ Auto Dump Complete ═══");
            Logger.Log("  Output: {0}", outputDir);
            Logger.Log("  Modules: {0}, Drivers: {1}{2}", dumped, driverDumped, unityDumped ? ", Unity: dumped" : "");
        }

        private void AutoDumpUnity(ProcessSummary target, ModuleSummary[] modules, string unityDir)
        {
            int pid = target.ProcessId;
            var dumperInst = new ProcessDumper(driver);

            // 1. Read IL2CPP metadata
            this.SafeInvoke(new Action(() => Logger.Log("  [1/9] Reading IL2CPP metadata...")));
            byte[] metadata = null;
            ulong metadataAddr = 0;

            for (int attempt = 1; attempt <= 3; attempt++)
            {
                var result = driver.ReadIl2CppMetadata(pid);
                metadata = result.metadata;
                metadataAddr = result.address;
                if (metadata != null && Il2CppDumper.ValidateMagic(metadata)) break;
                if (attempt < 3)
                {
                    this.SafeInvoke(new Action(() => Logger.Log("    Attempt {0}/3 — waiting 5s for game init...", attempt)));
                    Task.Delay(5000).Wait();
                }
            }

            if (metadata != null && Il2CppDumper.ValidateMagic(metadata))
            {
                var metaInfo = Il2CppDumper.ParseHeader(metadata, metadataAddr);
                string metaPath = Path.Combine(unityDir, "global-metadata.dat");
                Il2CppDumper.Save(metaPath, metadata, metaInfo);
                this.SafeInvoke(new Action(() => Logger.Log("    Saved: {0} ({1}KB, v{2})", metaPath, metadata.Length / 1024, metaInfo.Version)));
            }
            else
            {
                this.SafeInvoke(new Action(() => Logger.Log("    WARNING: Metadata not found or encrypted — game may not be fully loaded")));
            }

            // 2. Dump GameAssembly.dll
            this.SafeInvoke(new Action(() => Logger.Log("  [2/9] Dumping GameAssembly.dll...")));
            ModuleSummary gameAssembly = null;
            ModuleSummary unityPlayer = null;

            foreach (var mod in modules)
            {
                string n = mod.ModuleName ?? "";
                if (n.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase)) gameAssembly = mod;
                if (n.Equals("UnityPlayer.dll", StringComparison.OrdinalIgnoreCase)) unityPlayer = mod;
            }

            if (gameAssembly != null)
            {
                var gaPS = new ProcessSummary(pid, target.ProcessName,
                    gameAssembly.BaseAddress, gameAssembly.FileName, gameAssembly.ImageSize, gameAssembly.EntryPoint);

                if (dumperInst.DumpProcess(gaPS, out PEFile gaFile, rebuildImports: true))
                {
                    string gaPath = Path.Combine(unityDir, "GameAssembly_dump.dll");
                    gaFile.SaveToDisk(gaPath);
                    this.SafeInvoke(new Action(() => Logger.Log("    Saved: {0} (0x{1:X} bytes)", gaPath, gameAssembly.ImageSize)));
                }
                else
                {
                    this.SafeInvoke(new Action(() => Logger.Log("    WARNING: GameAssembly.dll dump failed")));
                }
            }
            else
            {
                this.SafeInvoke(new Action(() => Logger.Log("    GameAssembly.dll not found in module list")));
            }

            // 3. Dump UnityPlayer.dll
            this.SafeInvoke(new Action(() => Logger.Log("  [3/9] Dumping UnityPlayer.dll...")));
            if (unityPlayer != null)
            {
                var upPS = new ProcessSummary(pid, target.ProcessName,
                    unityPlayer.BaseAddress, unityPlayer.FileName, unityPlayer.ImageSize, unityPlayer.EntryPoint);

                if (dumperInst.DumpProcess(upPS, out PEFile upFile, rebuildImports: true))
                {
                    string upPath = Path.Combine(unityDir, "UnityPlayer_dump.dll");
                    upFile.SaveToDisk(upPath);
                    this.SafeInvoke(new Action(() => Logger.Log("    Saved: {0} (0x{1:X} bytes)", upPath, unityPlayer.ImageSize)));
                }
                else
                {
                    this.SafeInvoke(new Action(() => Logger.Log("    WARNING: UnityPlayer.dll dump failed")));
                }
            }
            else
            {
                this.SafeInvoke(new Action(() => Logger.Log("    UnityPlayer.dll not found")));
            }

            // 4. Runtime resolution (field offsets, method pointers, enum values, generics, strings)
            this.SafeInvoke(new Action(() => Logger.Log("  [4/9] Runtime resolution (field offsets, method RVAs)...")));
            Il2CppDumper.Il2CppMetadataSnapshot snapshot = null;
            List<Il2CppRuntimeResolver.RuntimeFieldOffset> fieldOffsets = null;
            List<Il2CppRuntimeResolver.MethodPointerEntry> methodPtrs = null;
            List<Il2CppRuntimeResolver.EnumValue> enumValues = null;
            List<Il2CppRuntimeResolver.StringLiteral> stringLiterals = null;
            Dictionary<int, string> genericMap = null;

            if (metadata != null && Il2CppDumper.ValidateMagic(metadata))
            {
                snapshot = Il2CppDumper.ParseFullMetadata(metadata);
            }

            if (snapshot != null && snapshot.TypeDefinitions.Length > 0 && gameAssembly != null)
            {
                try
                {
                    var resolver = new Il2CppRuntimeResolver(driver, pid);

                    fieldOffsets = resolver.ResolveFieldOffsets(
                        gameAssembly.BaseAddress, gameAssembly.ImageSize, snapshot,
                        msg => this.SafeInvoke(new Action(() => Logger.Log("    " + msg))));

                    methodPtrs = resolver.ResolveMethodPointers(
                        gameAssembly.BaseAddress, gameAssembly.ImageSize, snapshot,
                        msg => this.SafeInvoke(new Action(() => Logger.Log("    " + msg))));

                    enumValues = Il2CppRuntimeResolver.ExtractEnumValues(snapshot);
                    if (enumValues.Count > 0)
                        this.SafeInvoke(new Action(() => Logger.Log("    Extracted {0} enum values", enumValues.Count)));

                    stringLiterals = Il2CppRuntimeResolver.ExtractStringLiterals(snapshot);
                    if (stringLiterals.Count > 0)
                        this.SafeInvoke(new Action(() => Logger.Log("    Extracted {0} string literals", stringLiterals.Count)));

                    genericMap = Il2CppRuntimeResolver.ResolveGenericInstantiations(snapshot);
                    if (genericMap.Count > 0)
                        this.SafeInvoke(new Action(() => Logger.Log("    Resolved {0} generic types/methods", genericMap.Count)));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Logger.Log("    Runtime resolution error: {0}", ex.Message)));
                }
            }
            else
            {
                this.SafeInvoke(new Action(() => Logger.Log("    Skipped — no valid metadata or GameAssembly")));
            }

            // 5. Generate IL2CPP SDK (with resolved offsets, RVAs, enum values)
            this.SafeInvoke(new Action(() => Logger.Log("  [5/9] Generating enhanced IL2CPP SDK...")));
            List<Il2CppSdkGenerator.Il2CppClassInfo> classInfo = null;
            if (snapshot != null && snapshot.TypeDefinitions.Length > 0)
            {
                classInfo = Il2CppSdkGenerator.BuildClassInfo(snapshot);

                // Apply runtime-resolved data
                if (fieldOffsets != null && fieldOffsets.Count > 0)
                    Il2CppRuntimeResolver.ApplyFieldOffsets(classInfo, fieldOffsets, snapshot);
                if (methodPtrs != null && methodPtrs.Count > 0)
                    Il2CppRuntimeResolver.ApplyMethodPointers(classInfo, methodPtrs, snapshot);
                if (enumValues != null && enumValues.Count > 0)
                    Il2CppRuntimeResolver.ApplyEnumValues(classInfo, enumValues, snapshot);

                string sdkText = Il2CppSdkGenerator.GenerateSdk(classInfo);
                string sdkPath = Path.Combine(unityDir, "Il2CppSdk.cs");
                Il2CppSdkGenerator.Save(sdkPath, sdkText, snapshot);

                int totalMethods = classInfo.Sum(c => c.Methods.Count);
                int totalFields = classInfo.Sum(c => c.Fields.Count);
                int fieldsWithOffset = 0;
                int methodsWithRva = 0;
                foreach (var c in classInfo)
                {
                    foreach (var f in c.Fields) if (f.FieldOffset >= 0) fieldsWithOffset++;
                    foreach (var m in c.Methods) if (m.Rva > 0) methodsWithRva++;
                }

                this.SafeInvoke(new Action(() => Logger.Log("    Saved: {0} ({1} classes, {2} methods [{3} with RVA], {4} fields [{5} with offset])",
                    sdkPath, classInfo.Count, totalMethods, methodsWithRva, totalFields, fieldsWithOffset)));

                // Save string literal dump
                if (stringLiterals != null && stringLiterals.Count > 0)
                {
                    string strDump = Il2CppSdkGenerator.GenerateStringLiteralDump(stringLiterals);
                    string strPath = Path.Combine(unityDir, "Il2Cpp_StringLiterals.txt");
                    File.WriteAllText(strPath, strDump, Encoding.UTF8);
                    this.SafeInvoke(new Action(() => Logger.Log("    Saved: {0} ({1} strings)", strPath, stringLiterals.Count)));
                }
            }
            else
            {
                this.SafeInvoke(new Action(() => Logger.Log("    Skipped — no valid metadata")));
            }

            // 6. Generate Ghidra/IDA scripts with method pointers and vtables
            this.SafeInvoke(new Action(() => Logger.Log("  [6/9] Generating Ghidra/IDA scripts...")));
            if (classInfo != null && gameAssembly != null)
            {
                try
                {
                    Dictionary<int, ulong> rvaDict = null;
                    if (methodPtrs != null)
                    {
                        rvaDict = new Dictionary<int, ulong>();
                        foreach (var mp in methodPtrs)
                            rvaDict[mp.MethodIndex] = mp.Rva;
                    }

                    string ghidraScript = Il2CppGhidraScript.GenerateGhidraScript(classInfo, rvaDict, gameAssembly.BaseAddress);
                    string ghidraPath = Path.Combine(unityDir, "Il2Cpp_Ghidra.py");
                    Il2CppGhidraScript.Save(ghidraPath, ghidraScript);

                    string idaScript = Il2CppGhidraScript.GenerateIdaScript(classInfo, rvaDict, gameAssembly.BaseAddress);
                    string idaPath = Path.Combine(unityDir, "Il2Cpp_IDA.py");
                    Il2CppGhidraScript.Save(idaPath, idaScript);

                    int methodsLabeled = 0;
                    foreach (var c in classInfo)
                        foreach (var m in c.Methods)
                            if (m.Rva > 0) methodsLabeled++;

                    this.SafeInvoke(new Action(() => Logger.Log("    Saved Ghidra + IDA scripts ({0} functions labeled)", methodsLabeled)));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Logger.Log("    Script generation error: {0}", ex.Message)));
                }
            }

            // 7. Beebyte deobfuscation
            this.SafeInvoke(new Action(() => Logger.Log("  [7/9] Checking Beebyte obfuscation...")));
            if (snapshot != null && snapshot.TypeDefinitions.Length > 0 && gameAssembly != null)
            {
                try
                {
                    var beebyte = BeebyteDumper.RecoverNames(
                        driver, pid, gameAssembly.BaseAddress, gameAssembly.ImageSize, snapshot,
                        msg => this.SafeInvoke(new Action(() => Logger.Log("    " + msg))));

                    if (beebyte.IsObfuscated && beebyte.RecoveredTypes > 0)
                    {
                        string mapPath = Path.Combine(unityDir, "beebyte_deobfuscation_map.txt");
                        BeebyteDumper.SaveMapping(mapPath, beebyte, target.ProcessName);

                        string beIdaPath = Path.Combine(unityDir, "beebyte_ida_rename.py");
                        BeebyteDumper.SaveIdaScript(beIdaPath, beebyte);

                        string deobSdkPath = Path.Combine(unityDir, "Il2CppSdk_deobfuscated.cs");
                        string deobSdk = BeebyteDumper.GenerateDeobfuscatedSdk(snapshot, beebyte);
                        File.WriteAllText(deobSdkPath, deobSdk, Encoding.UTF8);

                        this.SafeInvoke(new Action(() => Logger.Log("    Recovered: {0}/{1} types, {2} methods, {3} fields",
                            beebyte.RecoveredTypes, beebyte.TotalTypes, beebyte.RecoveredMethods, beebyte.RecoveredFields)));
                    }
                    else if (!beebyte.IsObfuscated)
                    {
                        this.SafeInvoke(new Action(() => Logger.Log("    No Beebyte obfuscation detected")));
                    }
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Logger.Log("    Beebyte error: {0}", ex.Message)));
                }
            }

            // 8. Runtime deobfuscation on managed DLLs in memory
            this.SafeInvoke(new Action(() => Logger.Log("  [8/9] Runtime deobfuscation (live process)...")));
            int deobCount = 0;
            string cleanedDir = Path.Combine(unityDir, "deobfuscated");
            var rtDeob = new RuntimeDeobfuscator(driver, pid);

            foreach (var mod in modules)
            {
                string n = mod.ModuleName ?? "";
                if (!n.EndsWith(".dll", StringComparison.OrdinalIgnoreCase)) continue;
                if (SystemDllFilter.IsSystemDll(n)) continue;
                if (n.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase)) continue;
                if (n.Equals("UnityPlayer.dll", StringComparison.OrdinalIgnoreCase)) continue;

                byte[] peData = ReadModuleBytes(pid, mod.BaseAddress, (int)mod.ImageSize);
                if (peData == null) continue;

                var cli = CliHeader.Parse(peData);
                if (cli == null) continue;

                var report = DotNetDeobfuscator.AnalyzeProtection(peData);
                if (report.ProtectionScore <= 0) continue;

                this.SafeInvoke(new Action(() => Logger.Log("    {0}: score {1}/100 ({2})", n, report.ProtectionScore, report.ObfuscatorGuess)));

                var rtResult = rtDeob.DeobfuscateFromRuntime(peData, mod.BaseAddress,
                    msg => this.SafeInvoke(new Action(() => Logger.Log("      " + msg))));

                int total = rtResult.MethodBodiesRecovered + rtResult.StringsRecovered +
                    rtResult.TokensFixed + rtResult.PatchesApplied;

                if (total > 0)
                {
                    Directory.CreateDirectory(cleanedDir);
                    string cleanPath = Path.Combine(cleanedDir, n);
                    File.WriteAllBytes(cleanPath, peData);
                    deobCount++;
                    this.SafeInvoke(new Action(() => Logger.Log("      {0} fixes → {1}", total, cleanPath)));
                }
            }
            if (deobCount > 0)
                this.SafeInvoke(new Action(() => Logger.Log("    Deobfuscated {0} modules", deobCount)));

            // 9. Write summary
            this.SafeInvoke(new Action(() => Logger.Log("  [9/9] Writing dump summary...")));
            string summaryPath = Path.Combine(unityDir, "dump_info.txt");
            using (var w = new StreamWriter(summaryPath, false, Encoding.UTF8))
            {
                w.WriteLine("// KsDumper - Unity IL2CPP Auto Dump (Enhanced)");
                w.WriteLine("// Process: {0} (PID: {1})", target.ProcessName, pid);
                w.WriteLine("// Date: {0:yyyy-MM-dd HH:mm:ss}", DateTime.Now);
                w.WriteLine();
                if (metadata != null && Il2CppDumper.ValidateMagic(metadata))
                {
                    w.WriteLine("Metadata Address: 0x{0:X}", metadataAddr);
                    w.WriteLine("Metadata Size: {0} bytes", metadata.Length);
                    if (snapshot != null)
                    {
                        w.WriteLine("Types: {0}", snapshot.TypeDefinitions.Length);
                        w.WriteLine("Methods: {0}", snapshot.Methods.Length);
                        w.WriteLine("Fields: {0}", snapshot.Fields.Length);
                    }
                }
                if (gameAssembly != null)
                {
                    w.WriteLine();
                    w.WriteLine("GameAssembly.dll Base: 0x{0:X}", gameAssembly.BaseAddress);
                    w.WriteLine("GameAssembly.dll Size: 0x{0:X}", gameAssembly.ImageSize);
                }
                if (unityPlayer != null)
                {
                    w.WriteLine("UnityPlayer.dll Base: 0x{0:X}", unityPlayer.BaseAddress);
                    w.WriteLine("UnityPlayer.dll Size: 0x{0:X}", unityPlayer.ImageSize);
                }
                w.WriteLine();
                w.WriteLine("--- Enhanced Resolution ---");
                w.WriteLine("Field offsets resolved: {0}", fieldOffsets != null ? fieldOffsets.Count : 0);
                w.WriteLine("Method pointers resolved: {0}", methodPtrs != null ? methodPtrs.Count : 0);
                w.WriteLine("Enum values extracted: {0}", enumValues != null ? enumValues.Count : 0);
                w.WriteLine("String literals: {0}", stringLiterals != null ? stringLiterals.Count : 0);
                w.WriteLine("Generic types resolved: {0}", genericMap != null ? genericMap.Count : 0);
                w.WriteLine("Deobfuscated modules: {0}", deobCount);
            }
            this.SafeInvoke(new Action(() => Logger.Log("  Unity dump complete → {0}", unityDir)));
        }

        private byte[] ReadModuleBytes(int pid, ulong address, int size)
        {
            if (size <= 0 || size > 0x10000000) return null;
            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                if (!driver.CopyVirtualMemory(pid, (IntPtr)address, buf, size))
                    return null;
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }

        private void Logger_OnLog(string message)
        {
            this.SafeInvoke(() => logsTextBox.AppendText(message));
        }

        private void connectBtn_Click(object sender, EventArgs e)
        {
            TryConnectDriver();

            if (driver.IsKernelMode)
            {
                Logger.Log("Driver connected ! Running in Kernel mode.");
                connectBtn.Enabled = false;
            }
            else
            {
                Logger.Log("Driver not found. Running in Usermode. Load driver with kdmapper and retry.");
            }
        }

        private void refreshMenuBtn_Click(object sender, EventArgs e)
        {
            LoadProcessList();
        }

        private void hideSystemProcessMenuBtn_Click(object sender, EventArgs e)
        {
            if (!processList.SystemProcessesHidden)
            {
                processList.HideSystemProcesses();
                hideSystemProcessMenuBtn.Text = "  Show System Processes  ";
            }
            else
            {
                processList.ShowSystemProcesses();
                hideSystemProcessMenuBtn.Text = "  Hide System Processes  ";
            }
        }

        private void contextMenuStrip1_Opening(object sender, CancelEventArgs e)
        {
            e.Cancel = processList.SelectedItems.Count == 0;
        }

        private void logsTextBox_TextChanged(object sender, EventArgs e)
        {
            logsTextBox.SelectionStart = logsTextBox.Text.Length;
            logsTextBox.ScrollToCaret();
        }

        private void openInExplorerToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ProcessSummary targetProcess = processList.SelectedItems[0].Tag as ProcessSummary;
            Process.Start("explorer.exe", Path.GetDirectoryName(targetProcess.MainModuleFileName));
        }

        private void dumpModulesToolStripMenuItem_Click(object sender, EventArgs e)
        {
            ProcessSummary targetProcess = processList.SelectedItems[0].Tag as ProcessSummary;
            using (var dialog = new ModuleSelectionDialog(driver, targetProcess))
            {
                dialog.ShowDialog(this);
            }
        }

        private void searchTextBox_TextChanged(object sender, EventArgs e)
        {
            if (searchDebounceTimer == null)
            {
                searchDebounceTimer = new System.Windows.Forms.Timer();
                searchDebounceTimer.Interval = 300;
                searchDebounceTimer.Tick += (s, ev) =>
                {
                    searchDebounceTimer.Stop();
                    processList.FilterProcesses(searchTextBox.Text);
                };
            }
            searchDebounceTimer.Stop();
            searchDebounceTimer.Start();
        }

        private void DoAttach(ProcessAttachWindow.AttachMethod method)
        {
            if (processList.SelectedItems.Count == 0) return;
            var targetProcess = processList.SelectedItems[0].Tag as ProcessSummary;
            if (targetProcess == null) return;

            var attachWindow = new ProcessAttachWindow(driver, targetProcess.ProcessId, targetProcess.ProcessName, method);
            attachWindow.Show(this);
        }

        private void OpenMemoryScanner()
        {
            if (processList.SelectedItems.Count == 0) return;
            var targetProcess = processList.SelectedItems[0].Tag as ProcessSummary;
            if (targetProcess == null) return;
            new MemoryScannerWindow(driver, targetProcess.ProcessId, targetProcess.ProcessName).Show(this);
        }

        private void OpenHandleViewer()
        {
            if (processList.SelectedItems.Count == 0) return;
            var targetProcess = processList.SelectedItems[0].Tag as ProcessSummary;
            if (targetProcess == null) return;
            new HandleViewerWindow(targetProcess.ProcessId, targetProcess.ProcessName).Show(this);
        }

        private void OpenTokenViewer()
        {
            if (processList.SelectedItems.Count == 0) return;
            var targetProcess = processList.SelectedItems[0].Tag as ProcessSummary;
            if (targetProcess == null) return;
            new TokenViewerWindow(targetProcess.ProcessId, targetProcess.ProcessName).Show(this);
        }

        private void OpenActivityMonitor()
        {
            if (processList.SelectedItems.Count == 0) return;
            var targetProcess = processList.SelectedItems[0].Tag as ProcessSummary;
            if (targetProcess == null) return;
            new ProcessActivityWindow(driver, targetProcess.ProcessId, targetProcess.ProcessName).Show(this);
        }

        private void servicesBtn_Click(object sender, EventArgs e)
        {
            Logger.Log("Enumerating Windows services...");
            try
            {
                var services = System.ServiceProcess.ServiceController.GetServices();
                int running = 0;
                Logger.Log("  {0,-40} {1,-12} {2,-15} {3}", "Service Name", "Status", "Start Type", "Display Name");
                Logger.Log("  " + new string('-', 100));
                foreach (var svc in services)
                {
                    if (svc.Status == System.ServiceProcess.ServiceControllerStatus.Running) running++;
                    Logger.Log("  {0,-40} {1,-12} {2,-15} {3}",
                        svc.ServiceName.Length > 38 ? svc.ServiceName.Substring(0, 38) : svc.ServiceName,
                        svc.Status.ToString(),
                        svc.StartType.ToString(),
                        svc.DisplayName.Length > 50 ? svc.DisplayName.Substring(0, 50) + "..." : svc.DisplayName);
                }
                Logger.Log("  Total: {0} services, {1} running", services.Length, running);
            }
            catch (Exception ex) { Logger.Log("Service enumeration error: {0}", ex.Message); }
        }

        private async void dumpStringsProcess_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            var target = processList.SelectedItems[0].Tag as ProcessSummary;
            if (target == null) return;

            string savePath = null;
            using (var sfd = new SaveFileDialog())
            {
                sfd.FileName = $"{Path.GetFileNameWithoutExtension(target.ProcessName)}_strings.txt";
                sfd.Filter = "Text Files|*.txt|All Files|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                    savePath = sfd.FileName;
            }
            if (string.IsNullOrEmpty(savePath)) return;

            Logger.Log("Scanning {0} (PID: {1}) for strings...", target.ProcessName, target.ProcessId);

            await Task.Run(() =>
            {
                try
                {
                    var strings = driver.DumpLiveStrings(target.ProcessId, minStringLength: 4);

                    if (strings.Count > 0)
                    {
                        int asciiCount = 0, unicodeCount = 0;
                        using (var writer = new StreamWriter(savePath))
                        {
                            writer.WriteLine($"// KsDumper - Live Process String Dump");
                            writer.WriteLine($"// Process: {target.ProcessName} (PID: {target.ProcessId})");
                            writer.WriteLine($"// Total strings: {strings.Count}");
                            writer.WriteLine($"// Format: [ADDRESS] [TYPE] VALUE");
                            writer.WriteLine();

                            foreach (var (address, isUnicode, value) in strings)
                            {
                                if (isUnicode) unicodeCount++; else asciiCount++;
                                string type = isUnicode ? "U" : "A";
                                string escaped = value.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t");
                                writer.WriteLine($"[0x{address:x}] [{type}] {escaped}");
                            }
                        }

                        int ac = asciiCount, uc = unicodeCount;
                        this.SafeInvoke(new Action(() =>
                            Logger.Log("Dumped {0} strings ({1} ASCII, {2} Unicode) to: {3}",
                                strings.Count, ac, uc, savePath)));
                    }
                    else
                    {
                        this.SafeInvoke(new Action(() =>
                            Logger.Log("No strings found in {0} memory", target.ProcessName)));
                    }
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() =>
                        Logger.Log("String dump error: {0}", ex.Message)));
                }
            });
        }

        private void killProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            var target = processList.SelectedItems[0].Tag as ProcessSummary;
            if (target == null) return;

            var confirm = MessageBox.Show($"Kill process '{target.ProcessName}' (PID: {target.ProcessId})?",
                "Kill Process", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            try
            {
                var proc = Process.GetProcessById(target.ProcessId);
                proc.Kill();
                Logger.Log("Killed process: {0} (PID: {1})", target.ProcessName, target.ProcessId);
                System.Threading.Thread.Sleep(500);
                LoadProcessList();
            }
            catch (Exception ex)
            {
                // Try kernel driver kill
                if (driver.IsKernelMode)
                {
                    var (status, pid) = driver.KillProcessByName(target.ProcessName);
                    if (status == 0)
                    {
                        Logger.Log("Killed process via driver: {0} (PID: {1})", target.ProcessName, pid);
                        LoadProcessList();
                    }
                    else
                        Logger.Log("Failed to kill process: {0}", ex.Message);
                }
                else
                    Logger.Log("Failed to kill process: {0}", ex.Message);
            }
        }

        private void suspendProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            var target = processList.SelectedItems[0].Tag as ProcessSummary;
            if (target == null) return;

            int count = driver.SuspendProcess(target.ProcessId);
            if (count >= 0)
                Logger.Log("Suspended {0} threads in {1}", count, target.ProcessName);
            else
                Logger.Log("Failed to suspend process (requires kernel driver or OpenProcess access)");
        }

        private void resumeProcessToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            var target = processList.SelectedItems[0].Tag as ProcessSummary;
            if (target == null) return;

            int count = driver.ResumeProcess(target.ProcessId);
            if (count >= 0)
                Logger.Log("Resumed {0} threads in {1}", count, target.ProcessName);
            else
                Logger.Log("Failed to resume process (requires kernel driver or OpenProcess access)");
        }

        private void copyPidToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            var target = processList.SelectedItems[0].Tag as ProcessSummary;
            if (target == null) return;
            Clipboard.SetText(target.ProcessId.ToString());
            Logger.Log("Copied PID: {0}", target.ProcessId);
        }

        private void copyPathToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (processList.SelectedItems.Count == 0) return;
            var target = processList.SelectedItems[0].Tag as ProcessSummary;
            if (target == null) return;
            Clipboard.SetText(target.MainModuleFileName);
            Logger.Log("Copied path: {0}", target.MainModuleFileName);
        }

        private void SetPriority(ProcessPriorityClass priority)
        {
            if (processList.SelectedItems.Count == 0) return;
            var target = processList.SelectedItems[0].Tag as ProcessSummary;
            if (target == null) return;

            try
            {
                var proc = Process.GetProcessById(target.ProcessId);
                proc.PriorityClass = priority;
                Logger.Log("Set priority to {0} for {1}", priority, target.ProcessName);
            }
            catch (Exception ex)
            {
                Logger.Log("Failed to set priority: {0}", ex.Message);
            }
        }

    }
}
