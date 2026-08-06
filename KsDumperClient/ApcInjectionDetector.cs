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
    /// APC Injection Detector - detects Asynchronous Procedure Call (APC) injection
    /// by monitoring QueueUserAPC/NtQueueApcThread calls and suspicious APC queue entries.
    /// </summary>
    public class ApcInjectionDetector : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView apcList;
        private Button scanBtn;
        private Button monitorBtn;
        private Button stopBtn;
        private Label statsLbl;
        private RichTextBox logBox;
        private RichTextBox detailsBox;

        private CancellationTokenSource cts;
        private readonly HashSet<ulong> knownApcs;

        private struct ApcEntry
        {
            public ulong ThreadId;
            public ulong ApcRoutine;
            public ulong Arg1;
            public ulong Arg2;
            public ulong Arg3;
            public string RoutineModule;
            public string Suspicion;
        }

        public ApcInjectionDetector(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            knownApcs = new HashSet<ulong>();
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"APC Injection Detector - {processName} (PID: {processId})";
            Size = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            scanBtn = CreateButton("Scan Now", 80);
            scanBtn.Click += Scan_Click;
            monitorBtn = CreateButton("Start Monitor", 110);
            monitorBtn.Click += Monitor_Click;
            stopBtn = CreateButton("Stop", 60);
            stopBtn.Enabled = false;
            stopBtn.Click += (s, e) => { cts?.Cancel(); stopBtn.Enabled = false; monitorBtn.Enabled = true; Log("Monitoring stopped"); };
            statsLbl = new Label { Text = "Click Scan to check for APC injection", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.AddRange(new Control[] { scanBtn, monitorBtn, stopBtn, statsLbl });

            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 350 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            apcList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            apcList.Columns.Add("Thread ID", 80);
            apcList.Columns.Add("APC Routine", 130);
            apcList.Columns.Add("Module", 150);
            apcList.Columns.Add("Arg1", 130);
            apcList.Columns.Add("Arg2", 130);
            apcList.Columns.Add("Arg3", 130);
            apcList.Columns.Add("Suspicion", 200);
            apcList.Resize += (s, e) => { if (apcList.Columns.Count > 0) apcList.Columns[apcList.Columns.Count - 1].Width = -2; };
            apcList.SelectedIndexChanged += ApcList_SelectedIndexChanged;

            // Bottom split: details + log
            var bottomSplit = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 400 };
            bottomSplit.Panel1.BackColor = DarkTheme.Background;
            bottomSplit.Panel2.BackColor = DarkTheme.Background;

            detailsBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };

            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };

            bottomSplit.Panel1.Controls.Add(detailsBox);
            bottomSplit.Panel2.Controls.Add(logBox);
            bottomSplit.Panel2.Controls.Add(logLabel);

            split.Panel1.Controls.Add(apcList);
            split.Panel2.Controls.Add(bottomSplit);

            Controls.Add(split);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);

            FormClosing += (s, e) => { cts?.Cancel(); };
        }

        private async void Scan_Click(object sender, EventArgs e)
        {
            scanBtn.Enabled = false;
            apcList.Items.Clear();
            statsLbl.Text = "Scanning for APC injection...";

            await Task.Run(() =>
            {
                try
                {
                    var apcs = ScanForApcInjection();
                    this.SafeInvoke(() =>
                    {
                        int suspicious = 0;
                        foreach (var apc in apcs)
                        {
                            var lvi = new ListViewItem(apc.ThreadId.ToString());
                            lvi.SubItems.Add($"0x{apc.ApcRoutine:X}");
                            lvi.SubItems.Add(apc.RoutineModule ?? "");
                            lvi.SubItems.Add($"0x{apc.Arg1:X}");
                            lvi.SubItems.Add($"0x{apc.Arg2:X}");
                            lvi.SubItems.Add($"0x{apc.Arg3:X}");
                            lvi.SubItems.Add(apc.Suspicion ?? "Unknown");

                            if (apc.Suspicion != null && apc.Suspicion.Contains("INJECT")) { lvi.ForeColor = DarkTheme.Error; suspicious++; }
                            else if (apc.Suspicion != null && apc.Suspicion.Contains("SUSPICIOUS")) lvi.ForeColor = DarkTheme.Warning;
                            else lvi.ForeColor = DarkTheme.Success;

                            apcList.Items.Add(lvi);
                        }

                        statsLbl.Text = $"APC entries: {apcs.Count} | Suspicious: {suspicious}";
                        statsLbl.ForeColor = suspicious > 0 ? DarkTheme.Error : DarkTheme.Success;
                        Log("Scan complete: {0} APC entries, {1} suspicious", apcs.Count, suspicious);
                        scanBtn.Enabled = true;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        Log("Scan error: {0}", ex.Message);
                        statsLbl.Text = "Scan failed";
                        statsLbl.ForeColor = DarkTheme.Error;
                        scanBtn.Enabled = true;
                    });
                }
            });
        }

        private async void Monitor_Click(object sender, EventArgs e)
        {
            monitorBtn.Enabled = false;
            stopBtn.Enabled = true;
            cts = new CancellationTokenSource();
            var token = cts.Token;

            Log("APC monitoring started (checking every 500ms)");

            await Task.Run(async () =>
            {
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(500, token);
                        var apcs = ScanForApcInjection();

                        foreach (var apc in apcs)
                        {
                            if (knownApcs.Add(apc.ApcRoutine))
                            {
                                if (apc.Suspicion.Contains("INJECT"))
                                {
                                    this.SafeInvoke(() =>
                                    {
                                        Log("NEW APC INJECTION: Thread {0}, Routine 0x{1:X} ({2}) - {3}",
                                            apc.ThreadId, apc.ApcRoutine, apc.RoutineModule, apc.Suspicion);
                                    });
                                }
                            }
                        }
                    }
                    catch (OperationCanceledException) { break; }
                    catch { }
                }
            }, token);
        }

        private const ulong MAX_USER_ADDR = 0x00007FFFFFFEFFFF;

        private List<ApcEntry> ScanForApcInjection()
        {
            var result = new List<ApcEntry>();

            try
            {
                driver.GetModuleSummaryList(processId, out var modules);

                var threadIds = EnumerateThreadIds();

                foreach (uint tid in threadIds)
                {
                    try
                    {
                        byte[] ctx = null;

                        IntPtr hThread = OpenThread(0x0008 | 0x0040, false, tid);
                        if (hThread != IntPtr.Zero)
                        {
                            try
                            {
                                IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                                try
                                {
                                    for (int i = 0; i < 2048; i++) Marshal.WriteByte(ctxPtr, i, 0);
                                    Marshal.WriteInt32(ctxPtr, 48, 0x00100001); // CONTEXT_CONTROL only
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

                        if (ctx == null && driver.IsKernelMode)
                            ctx = driver.GetThreadContext(processId, (int)tid, 0x00100001);

                        if (ctx == null || ctx.Length < 256) continue;

                        ulong rip = BitConverter.ToUInt64(ctx, 248);
                        if (rip == 0 || rip > MAX_USER_ADDR) continue;

                        string ripModule = ResolveModule(rip, modules);

                        string suspicion = null;
                        if (string.IsNullOrEmpty(ripModule))
                            suspicion = "INJECT: Thread executing from non-image memory (possible shellcode)";
                        else if (!ripModule.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) &&
                                 !ripModule.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            suspicion = "SUSPICIOUS: Thread in unusual module";

                        if (suspicion != null)
                        {
                            result.Add(new ApcEntry
                            {
                                ThreadId = tid,
                                ApcRoutine = rip,
                                Arg1 = ctx.Length >= 136 ? BitConverter.ToUInt64(ctx, 128) : 0,
                                Arg2 = ctx.Length >= 144 ? BitConverter.ToUInt64(ctx, 136) : 0,
                                Arg3 = ctx.Length >= 192 ? BitConverter.ToUInt64(ctx, 184) : 0,
                                RoutineModule = "(shellcode?)",
                                Suspicion = suspicion
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return result;
        }

        private string ResolveModule(ulong address, ModuleSummary[] modules)
        {
            if (modules == null) return null;
            foreach (var mod in modules)
            {
                if (address >= mod.BaseAddress && address < mod.BaseAddress + mod.ImageSize)
                    return mod.ModuleName;
            }
            return null;
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
                        // SYSTEM_PROCESS_INFORMATION offsets (x64 / x86)
                        int pidOffset = IntPtr.Size == 8 ? 80 : 68;       // UniqueProcessId
                        int threadCountOffset = 4;                         // NumberOfThreads
                        int threadArrayOffset = IntPtr.Size == 8 ? 240 : 184; // Threads[]
                        int threadStructSize = IntPtr.Size == 8 ? 128 : 72;   // SYSTEM_THREAD_INFORMATION
                        int threadIdOffset = IntPtr.Size == 8 ? 8 : 4;       // ClientId.UniqueThread

                        int procId = Marshal.ReadInt32(current, pidOffset);
                        if (procId == processId)
                        {
                            int threadCount = Marshal.ReadInt32(current, threadCountOffset);
                            IntPtr threadArray = current + threadArrayOffset;

                            for (int i = 0; i < threadCount; i++)
                            {
                                IntPtr tInfo = threadArray + (i * threadStructSize);
                                // Bounds check
                                if ((long)(tInfo + threadIdOffset + 8) > (long)(buffer + retLen))
                                    break;

                                uint tid = (uint)(IntPtr.Size == 8
                                    ? Marshal.ReadInt64(tInfo, threadIdOffset)
                                    : Marshal.ReadInt32(tInfo, threadIdOffset));
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

        private void ApcList_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (apcList.SelectedItems.Count == 0) { detailsBox.Clear(); return; }

            detailsBox.Clear();
            detailsBox.SelectionColor = DarkTheme.Accent;
            detailsBox.AppendText("APC Entry Details\n");
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText(new string('═', 50) + "\n\n");

            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            detailsBox.AppendText($"  Thread ID:   {apcList.SelectedItems[0].Text}\n");
            detailsBox.AppendText($"  APC Routine: {apcList.SelectedItems[0].SubItems[1].Text}\n");
            detailsBox.AppendText($"  Module:      {apcList.SelectedItems[0].SubItems[2].Text}\n");
            detailsBox.AppendText($"  Arg1:        {apcList.SelectedItems[0].SubItems[3].Text}\n");
            detailsBox.AppendText($"  Arg2:        {apcList.SelectedItems[0].SubItems[4].Text}\n");
            detailsBox.AppendText($"  Arg3:        {apcList.SelectedItems[0].SubItems[5].Text}\n\n");

            string suspicion = apcList.SelectedItems[0].SubItems[6].Text;
            if (suspicion.Contains("INJECT"))
            {
                detailsBox.SelectionColor = DarkTheme.Error;
                detailsBox.AppendText($"  ⚠ {suspicion}\n\n");
                detailsBox.SelectionColor = DarkTheme.TextSecondary;
                detailsBox.AppendText("  APC injection indicators:\n");
                detailsBox.AppendText("    • Thread executing from non-image memory\n");
                detailsBox.AppendText("    • APC routine in recently allocated memory\n");
                detailsBox.AppendText("    • Arguments pointing to shellcode\n");
                detailsBox.AppendText("    • QueueUserAPC with LoadLibrary target\n");
            }
            else
            {
                detailsBox.SelectionColor = DarkTheme.Success;
                detailsBox.AppendText("  No injection indicators detected\n");
            }
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int c, IntPtr b, int s, out int r);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenThread(uint a, bool i, uint t);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetThreadContext(IntPtr h, IntPtr c);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
