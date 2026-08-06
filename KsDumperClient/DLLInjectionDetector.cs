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
    /// <summary>
    /// DLL Injection Detector - monitors a process for newly loaded DLLs
    /// and flags suspicious injections (manual maps, unsigned DLLs, etc.)
    /// </summary>
    public class DLLInjectionDetector : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView dllList;
        private RichTextBox logBox;
        private Button startBtn;
        private Button stopBtn;
        private Button snapshotBtn;
        private Label statsLbl;
        private Label statusLbl;

        private class DllEntry
        {
            public ulong BaseAddress;
            public uint ImageSize;
            public string Name;
            public string Path;
            public bool IsSigned;
            public bool IsKnown;
            public bool IsHidden;
            public DateTime LoadTime;
            public string Suspicion;
        }

        private readonly HashSet<string> knownDlls;
        private readonly List<DllEntry> allDlls;
        private CancellationTokenSource cts;
        private bool isMonitoring;

        // Known system DLLs that are always present
        private static readonly HashSet<string> SystemDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
            "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll", "msvcrt.dll",
            "combase.dll", "rpcrt4.dll", "sechost.dll", "bcryptprimitives.dll",
            "ucrtbase.dll", "msvcp_win.dll", "win32u.dll", "gdi32full.dll",
            "imm32.dll", "ws2_32.dll", "nsi.dll", "crypt32.dll", "msasn1.dll",
            "mswsock.dll", "winhttp.dll", "wininet.dll", "shlwapi.dll",
            "comdlg32.dll", "comctl32.dll", "uxtheme.dll", "dwmapi.dll",
            "propsys.dll", "cfgmgr32.dll", "devobj.dll", "setupapi.dll",
            "version.dll", "wintrust.dll", "cryptbase.dll", "sspicli.dll",
            "wldp.dll", "ntmarta.dll", "wkscli.dll", "netapi32.dll",
            "userenv.dll", "profapi.dll", "windows.storage.dll", "bcrypt.dll",
            "clbcatq.dll", "mfplat.dll", "rtworkq.dll", "msmpeg2vdec.dll",
            "d3d11.dll", "dxgi.dll", "dcomp.dll", "d3d9.dll", "opengl32.dll",
            "glu32.dll", "msvfw32.dll", "avicap32.dll", "avifil32.dll",
            "psapi.dll", "dbghelp.dll", "imagehlp.dll", "pdh.dll",
            "mpr.dll", "winmm.dll", "iphlpapi.dll", "dhcpcsvc.dll",
            "dnsapi.dll", "rasadhlp.dll", "fwpuclnt.dll", "wshbth.dll",
            "msimg32.dll", "lz32.dll", "cabinet.dll", "msacm32.dll"
        };

        public DLLInjectionDetector(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            knownDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            allDlls = new List<DllEntry>();
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"DLL Injection Detector - {processName} (PID: {processId})";
            Size = new Size(1000, 650);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            snapshotBtn = CreateButton("Take Snapshot", 110);
            snapshotBtn.Click += Snapshot_Click;
            startBtn = CreateButton("Start Monitor", 110);
            startBtn.Click += Start_Click;
            stopBtn = CreateButton("Stop", 60);
            stopBtn.Enabled = false;
            stopBtn.Click += Stop_Click;
            statsLbl = new Label { Text = "DLLs: 0", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            statusLbl = new Label { Text = "Ready - Take a snapshot first", AutoSize = true, ForeColor = DarkTheme.TextMuted, Font = DarkTheme.UIFont, Margin = new Padding(16, 4, 0, 0) };

            toolbar.Controls.AddRange(new Control[] { snapshotBtn, startBtn, stopBtn, statsLbl, statusLbl });

            // DLL list
            dllList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            dllList.Columns.Add("Name", 200);
            dllList.Columns.Add("Base Address", 130);
            dllList.Columns.Add("Size", 80);
            dllList.Columns.Add("Status", 100);
            dllList.Columns.Add("Suspicion", 300);
            dllList.Resize += (s, e) => { if (dllList.Columns.Count > 0) dllList.Columns[dllList.Columns.Count - 1].Width = -2; };

            // Log
            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 120, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(dllList);
            Controls.Add(logPanel);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);

            FormClosing += (s, e) => { cts?.Cancel(); };
        }

        private void Snapshot_Click(object sender, EventArgs e)
        {
            dllList.Items.Clear();
            allDlls.Clear();
            knownDlls.Clear();

            var dlls = EnumerateModules();
            foreach (var dll in dlls)
            {
                knownDlls.Add(dll.Name);
                allDlls.Add(dll);
                AddDllToList(dll, false);
            }

            statsLbl.Text = $"DLLs: {allDlls.Count}";
            statusLbl.Text = $"Snapshot taken ({allDlls.Count} DLLs)";
            statusLbl.ForeColor = DarkTheme.Success;
            Log("Snapshot: {0} DLLs loaded", allDlls.Count);

            int suspicious = allDlls.Count(d => !string.IsNullOrEmpty(d.Suspicion));
            if (suspicious > 0)
                Log("Found {0} suspicious DLLs", suspicious);
        }

        private async void Start_Click(object sender, EventArgs e)
        {
            if (knownDlls.Count == 0)
            {
                Log("Take a snapshot first to establish baseline");
                return;
            }

            isMonitoring = true;
            startBtn.Enabled = false;
            stopBtn.Enabled = true;
            statusLbl.Text = "Monitoring for new DLLs...";
            statusLbl.ForeColor = DarkTheme.Success;

            cts = new CancellationTokenSource();
            var token = cts.Token;

            await Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(1000, token);
                        var currentDlls = EnumerateModules();

                        foreach (var dll in currentDlls)
                        {
                            if (!knownDlls.Contains(dll.Name))
                            {
                                knownDlls.Add(dll.Name);
                                dll.LoadTime = DateTime.Now;

                                // Analyze the new DLL for suspicion
                                AnalyzeDll(dll);
                                allDlls.Add(dll);

                                this.SafeInvoke(new Action(() =>
                                {
                                    AddDllToList(dll, true);
                                    statsLbl.Text = $"DLLs: {allDlls.Count}";

                                    string suspicion = string.IsNullOrEmpty(dll.Suspicion) ? "Clean" : dll.Suspicion;
                                    Log("NEW DLL: {0} @ 0x{1:X} ({2})", dll.Name, dll.BaseAddress, suspicion);
                                    statusLbl.Text = $"New DLL detected: {dll.Name}";
                                    statusLbl.ForeColor = string.IsNullOrEmpty(dll.Suspicion) ? DarkTheme.Success : DarkTheme.Warning;
                                }));
                            }
                        }
                    }
                    catch (OperationCanceledException) { break; }
                    catch { }
                }

                this.SafeInvoke(new Action(() =>
                {
                    isMonitoring = false;
                    startBtn.Enabled = true;
                    stopBtn.Enabled = false;
                    statusLbl.Text = "Monitoring stopped";
                    statusLbl.ForeColor = DarkTheme.TextMuted;
                }));
            }, token);
        }

        private void Stop_Click(object sender, EventArgs e)
        {
            cts?.Cancel();
            isMonitoring = false;
            startBtn.Enabled = true;
            stopBtn.Enabled = false;
            statusLbl.Text = "Monitoring stopped";
            statusLbl.ForeColor = DarkTheme.TextMuted;
        }

        private List<DllEntry> EnumerateModules()
        {
            var result = new List<DllEntry>();
            try
            {
                if (driver.GetModuleSummaryList(processId, out var modules) && modules != null)
                {
                    foreach (var mod in modules)
                    {
                        var entry = new DllEntry
                        {
                            BaseAddress = mod.BaseAddress,
                            ImageSize = mod.ImageSize,
                            Name = mod.ModuleName,
                            Path = mod.FileName,
                            IsKnown = SystemDlls.Contains(mod.ModuleName),
                            IsHidden = mod.IsHidden
                        };
                        AnalyzeDll(entry);
                        result.Add(entry);
                    }
                }
            }
            catch { }
            return result;
        }

        private void AnalyzeDll(DllEntry dll)
        {
            var suspicions = new List<string>();

            // Check if hidden from PEB
            if (dll.IsHidden)
                suspicions.Add("HIDDEN from PEB (manually mapped)");

            // Check if it's a known system DLL
            if (!dll.IsKnown && !SystemDlls.Contains(dll.Name))
            {
                // Check if it has no path (injected without file on disk)
                if (string.IsNullOrEmpty(dll.Path) || dll.Path == dll.Name)
                    suspicions.Add("No file path (possibly injected from memory)");

                // Check for suspicious naming patterns
                string lower = dll.Name.ToLower();
                if (lower.Contains("inject") || lower.Contains("hook") || lower.Contains("bypass") ||
                    lower.Contains("cheat") || lower.Contains("hack") || lower.Contains("crack"))
                    suspicions.Add("Suspicious name pattern");

                // Check for random-looking names (no common extension or pattern)
                if (!lower.EndsWith(".dll") && !lower.EndsWith(".sys") && !lower.EndsWith(".drv"))
                    suspicions.Add("Non-standard extension");
            }

            // Check for common injection DLL names
            string[] injectionDlls = { "dwmapi.dll", "version.dll", "winmm.dll", "dbghelp.dll", "winspool.drv" };
            if (!dll.IsKnown && injectionDlls.Any(d => d.Equals(dll.Name, StringComparison.OrdinalIgnoreCase)))
            {
                // These are commonly used for DLL hijacking
                if (!string.IsNullOrEmpty(dll.Path) && !dll.Path.ToLower().Contains("\\windows\\system32\\"))
                    suspicions.Add("Possible DLL hijack (not in System32)");
            }

            // Check for unusually small DLLs (shellcode loaders)
            if (dll.ImageSize > 0 && dll.ImageSize < 0x2000) // < 8KB
                suspicions.Add("Very small image (possible shellcode loader)");

            dll.Suspicion = string.Join("; ", suspicions);
        }

        private void AddDllToList(DllEntry dll, bool isNew)
        {
            var lvi = new ListViewItem(dll.Name);
            lvi.SubItems.Add($"0x{dll.BaseAddress:X}");
            lvi.SubItems.Add(dll.ImageSize > 0 ? $"{dll.ImageSize / 1024}KB" : "?");

            string status;
            if (dll.IsHidden) status = "Hidden";
            else if (dll.IsKnown) status = "System";
            else if (isNew) status = "NEW";
            else status = "Loaded";
            lvi.SubItems.Add(status);
            lvi.SubItems.Add(string.IsNullOrEmpty(dll.Suspicion) ? "Clean" : dll.Suspicion);

            if (dll.IsHidden) lvi.ForeColor = DarkTheme.Error;
            else if (!string.IsNullOrEmpty(dll.Suspicion)) lvi.ForeColor = DarkTheme.Warning;
            else if (dll.IsKnown) lvi.ForeColor = DarkTheme.TextMuted;
            else if (isNew) lvi.ForeColor = DarkTheme.Accent;
            else lvi.ForeColor = DarkTheme.TextPrimary;

            dllList.Items.Add(lvi);
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
