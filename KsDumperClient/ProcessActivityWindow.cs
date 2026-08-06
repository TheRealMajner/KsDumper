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
    public class ProcessActivityWindow : Form
    {
        public struct ActivityEvent
        {
            public DateTime Timestamp;
            public string Category;  // Module, API, Crypto, Network, File, Thread, Exception
            public string Action;    // Load, Unload, Call, Read, Write, etc.
            public string Target;    // DLL name, API name, address
            public string Details;   // Extra info
            public ulong Address;
        }

        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView activityList;
        private RichTextBox logBox;
        private ComboBox categoryFilter;
        private Button startBtn;
        private Button stopBtn;
        private Button clearBtn;
        private Label statusLbl;
        private CheckBox autoScrollCheck;

        private CancellationTokenSource cts;
        private bool isMonitoring;
        private readonly List<ActivityEvent> allEvents;
        private readonly HashSet<string> knownModules;
        private readonly object syncLock;

        // Crypto API addresses for breakpoint monitoring
        private static readonly string[] CryptoApis = {
            "CryptEncrypt", "CryptDecrypt", "CryptDeriveKey", "CryptGenKey",
            "CryptHashData", "CryptExportKey", "CryptImportKey",
            "BCryptEncrypt", "BCryptDecrypt", "BCryptGenerateKeyPair",
            "NCryptEncrypt", "NCryptDecrypt",
            "RtlEncryptMemory", "RtlDecryptMemory",
            "SystemFunction032", "SystemFunction033"
        };

        // Network API addresses
        private static readonly string[] NetworkApis = {
            "connect", "send", "recv", "WSAConnect", "WSASend", "WSARecv",
            "InternetOpen", "InternetConnect", "HttpOpenRequest", "HttpSendRequest",
            "URLDownloadToFile"
        };

        // File API addresses
        private static readonly string[] FileApis = {
            "CreateFileW", "CreateFileA", "ReadFile", "WriteFile",
            "NtCreateFile", "NtReadFile", "NtWriteFile",
            "DeleteFileW", "CopyFileW", "MoveFileW"
        };

        public ProcessActivityWindow(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            allEvents = new List<ActivityEvent>();
            knownModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            syncLock = new object();
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"Process Activity - {processName} (PID: {processId})";
            Size = new Size(1100, 700);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(900, 500);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };

            startBtn = CreateButton("Start Monitoring", 120);
            startBtn.Click += Start_Click;
            stopBtn = CreateButton("Stop", 60);
            stopBtn.Enabled = false;
            stopBtn.Click += Stop_Click;
            clearBtn = CreateButton("Clear", 60);
            clearBtn.Click += (s, e) => { lock (syncLock) { allEvents.Clear(); } activityList.VirtualListSize = 0; activityList.Invalidate(); statusLbl.Text = "Cleared"; };

            toolbar.Controls.Add(MakeLabel("Filter:"));
            categoryFilter = new DarkComboBox { Width = 120 };
            categoryFilter.Items.AddRange(new object[] { "All", "Module", "API", "Crypto", "Decrypt", "Network", "File", "Thread", "Exception" });
            categoryFilter.SelectedIndex = 0;
            categoryFilter.SelectedIndexChanged += (s, e) => ApplyFilter();

            autoScrollCheck = new CheckBox { Text = "Auto-scroll", AutoSize = true, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont, Checked = true, Margin = new Padding(12, 4, 0, 0) };

            statusLbl = new Label { Text = "Ready", AutoSize = true, ForeColor = DarkTheme.TextMuted, Font = DarkTheme.UIFont, Margin = new Padding(16, 4, 0, 0) };

            toolbar.Controls.AddRange(new Control[] { startBtn, stopBtn, clearBtn, categoryFilter, autoScrollCheck, statusLbl });

            // Activity list (virtual mode for performance)
            activityList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont, VirtualMode = true
            };
            activityList.Columns.Add("Time", 80);
            activityList.Columns.Add("Category", 80);
            activityList.Columns.Add("Action", 80);
            activityList.Columns.Add("Target", 280);
            activityList.Columns.Add("Details", 400);
            activityList.RetrieveVirtualItem += (s, e) =>
            {
                List<ActivityEvent> filtered = GetFilteredEvents();
                if (e.ItemIndex < 0 || e.ItemIndex >= filtered.Count) { e.Item = new ListViewItem(""); return; }
                var ev = filtered[e.ItemIndex];
                var lvi = new ListViewItem(ev.Timestamp.ToString("HH:mm:ss.fff"));
                lvi.SubItems.Add(ev.Category);
                lvi.SubItems.Add(ev.Action);
                lvi.SubItems.Add(ev.Target);
                lvi.SubItems.Add(ev.Details);

                // Color by category
                switch (ev.Category)
                {
                    case "Module": lvi.ForeColor = DarkTheme.Accent; break;
                    case "Crypto": lvi.ForeColor = DarkTheme.Warning; break;
                    case "Decrypt": lvi.ForeColor = Color.FromArgb(255, 165, 0); break; // Orange for decrypted strings
                    case "Network": lvi.ForeColor = DarkTheme.Success; break;
                    case "File": lvi.ForeColor = Color.FromArgb(180, 140, 255); break;
                    case "Exception": lvi.ForeColor = DarkTheme.Error; break;
                    case "Thread": lvi.ForeColor = DarkTheme.TextSecondary; break;
                    default: lvi.ForeColor = DarkTheme.TextPrimary; break;
                }
                e.Item = lvi;
            };
            activityList.Resize += (s, e) => { if (activityList.Columns.Count > 0) activityList.Columns[activityList.Columns.Count - 1].Width = -2; };

            // Log panel
            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 100, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Activity Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(activityList);
            Controls.Add(logPanel);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);

            FormClosing += (s, e) => { cts?.Cancel(); };
        }

        // ==================== Monitoring ====================

        private async void Start_Click(object sender, EventArgs e)
        {
            if (isMonitoring) return;
            isMonitoring = true;
            startBtn.Enabled = false;
            stopBtn.Enabled = true;
            statusLbl.Text = "Monitoring...";
            statusLbl.ForeColor = DarkTheme.Success;

            // Initial module snapshot
            SnapshotModules();

            cts = new CancellationTokenSource();
            var token = cts.Token;

            // Module polling task
            var moduleTask = Task.Run(() => MonitorModules(token), token);
            // API monitoring task (uses debug engine)
            var apiTask = Task.Run(() => MonitorApiCalls(token), token);
            // Kernel-mode string monitoring (detects newly decrypted strings)
            var stringTask = Task.Run(() => MonitorDecryptedStrings(token), token);
            // ETW tracing (file I/O, registry, handle/thread changes)
            var etwTask = Task.Run(() => MonitorEtwEvents(token), token);

            Log("Activity monitoring started for PID {0} (4 monitors active)", processId);
        }

        private void Stop_Click(object sender, EventArgs e)
        {
            cts?.Cancel();
            isMonitoring = false;
            startBtn.Enabled = true;
            stopBtn.Enabled = false;
            statusLbl.Text = "Stopped";
            statusLbl.ForeColor = DarkTheme.TextMuted;
            Log("Activity monitoring stopped. Total events: {0}", allEvents.Count);
        }

        // ==================== Module Monitor ====================

        private void SnapshotModules()
        {
            try
            {
                if (driver.GetModuleSummaryList(processId, out var modules))
                {
                    foreach (var mod in modules)
                        knownModules.Add(mod.ModuleName);
                }
            }
            catch { }
        }

        private async Task MonitorModules(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(500, token);
                    if (token.IsCancellationRequested) break;

                    if (driver.GetModuleSummaryList(processId, out var modules))
                    {
                        var currentModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        foreach (var mod in modules)
                            currentModules.Add(mod.ModuleName);

                        // Detect new modules (loads)
                        foreach (var mod in modules)
                        {
                            if (!knownModules.Contains(mod.ModuleName))
                            {
                                string type = mod.ModuleName.EndsWith(".sys", StringComparison.OrdinalIgnoreCase) ? "Driver" : "DLL";
                                AddEvent(new ActivityEvent
                                {
                                    Timestamp = DateTime.Now,
                                    Category = "Module",
                                    Action = "Load",
                                    Target = mod.ModuleName,
                                    Details = $"{type} @ 0x{mod.BaseAddress:X} ({mod.ImageSize / 1024}KB)",
                                    Address = mod.BaseAddress
                                });
                            }
                        }

                        // Detect unloaded modules
                        foreach (var name in knownModules)
                        {
                            if (!currentModules.Contains(name))
                            {
                                AddEvent(new ActivityEvent
                                {
                                    Timestamp = DateTime.Now,
                                    Category = "Module",
                                    Action = "Unload",
                                    Target = name,
                                    Details = "Module removed from process"
                                });
                            }
                        }

                        knownModules.Clear();
                        foreach (var name in currentModules) knownModules.Add(name);
                    }
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        // ==================== ETW Event Monitor ====================

        private async Task MonitorEtwEvents(CancellationToken token)
        {
            var etwTracer = new Utility.EtwTracer(processId);

            etwTracer.OnEvent += evt =>
            {
                AddEvent(new ActivityEvent
                {
                    Timestamp = evt.Timestamp,
                    Category = evt.Category,
                    Action = evt.Operation,
                    Target = evt.Target,
                    Details = evt.Details,
                    Address = 0
                });
            };

            try
            {
                etwTracer.StartTracing();
                Log("ETW monitoring started (file I/O, handles, threads)");

                // Wait until cancelled
                while (!token.IsCancellationRequested)
                {
                    await Task.Delay(1000, token);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) { Log("ETW monitor error: {0}", ex.Message); }
            finally
            {
                etwTracer.StopTracing();
                etwTracer.Dispose();
                Log("ETW monitoring stopped ({0} events captured)", etwTracer.EventCount);
            }
        }

        // ==================== Decrypted String Monitor ====================

        private readonly HashSet<string> knownStrings = new HashSet<string>();

        private async Task MonitorDecryptedStrings(CancellationToken token)
        {
            // Initial snapshot of existing strings
            try
            {
                var initial = driver.DumpLiveStrings(processId, 6);
                foreach (var (addr, isUnicode, value) in initial)
                    knownStrings.Add(value);
                Log("String monitor: {0} initial strings captured", knownStrings.Count);
            }
            catch (Exception ex)
            {
                Log("String monitor init error: {0}", ex.Message);
                return;
            }

            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(2000, token); // Poll every 2 seconds
                    if (token.IsCancellationRequested) break;

                    var currentStrings = driver.DumpLiveStrings(processId, 6);
                    int newCount = 0;

                    foreach (var (addr, isUnicode, value) in currentStrings)
                    {
                        if (knownStrings.Add(value))
                        {
                            newCount++;
                            if (newCount <= 50) // Limit events per cycle
                            {
                                string category = CategorizeString(value);
                                AddEvent(new ActivityEvent
                                {
                                    Timestamp = DateTime.Now,
                                    Category = category,
                                    Action = "Decrypt",
                                    Target = value.Length > 80 ? value.Substring(0, 80) + "..." : value,
                                    Details = $"New string at 0x{addr:X} ({(isUnicode ? "Unicode" : "ASCII")})",
                                    Address = addr
                                });
                            }
                        }
                    }

                    if (newCount > 0)
                        Log("String monitor: {0} new strings detected ({1} total known)", newCount, knownStrings.Count);
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }
        }

        private string CategorizeString(string value)
        {
            if (string.IsNullOrEmpty(value)) return "String";
            if (value.Contains("://") || value.StartsWith("http")) return "Network";
            if (value.Contains("\\") || value.Contains("/") && value.Length > 3) return "File";
            if (value.StartsWith("HKEY_") || value.Contains("\\Registry\\")) return "File";
            if (value.Contains("Crypt") || value.Contains("Encrypt") || value.Contains("Decrypt") ||
                value.Contains("Hash") || value.Contains("AES") || value.Contains("RSA"))
                return "Crypto";
            if (value.Contains("Error") || value.Contains("error") || value.Contains("Failed"))
                return "String";
            return "String";
        }

        // ==================== API Call Monitor ====================

        private async Task MonitorApiCalls(CancellationToken token)
        {
            Dictionary<ulong, string> apiAddresses = null;

            try
            {
                await Task.Delay(1000, token);
                apiAddresses = ResolveApiAddresses();

                if (apiAddresses.Count == 0)
                {
                    Log("No API addresses resolved - limited monitoring");
                    return;
                }

                Log("Resolved {0} API addresses for monitoring", apiAddresses.Count);
            }
            catch { return; }

            // Set hardware breakpoints on top 4 crypto APIs (DR0-DR3 limit)
            var cryptoAddresses = apiAddresses
                .Where(kvp => CryptoApis.Contains(kvp.Value.Split('!').Last()))
                .Take(4)
                .ToList();

            if (cryptoAddresses.Count > 0)
            {
                Log("Setting hardware breakpoints on {0} crypto APIs:", cryptoAddresses.Count);
                for (int i = 0; i < cryptoAddresses.Count; i++)
                {
                    bool ok = SetHWBreakpointOnAllThreads(cryptoAddresses[i].Key, i);
                    Log("  DR{0}: {1} {2}", i, cryptoAddresses[i].Value, ok ? "(OK)" : "(FAIL)");

                    if (ok)
                    {
                        AddEvent(new ActivityEvent
                        {
                            Timestamp = DateTime.Now,
                            Category = "API",
                            Action = "Hook",
                            Target = cryptoAddresses[i].Value,
                            Details = $"Hardware breakpoint set on DR{i} @ 0x{cryptoAddresses[i].Key:X}"
                        });
                    }
                }
            }

            // Poll for hardware breakpoint hits
            while (!token.IsCancellationRequested)
            {
                try
                {
                    await Task.Delay(100, token);
                    if (token.IsCancellationRequested) break;

                    // Check threads for DR6 hits
                    PollBreakpointHits(cryptoAddresses);

                    // Also monitor thread activity
                    MonitorThreadActivity();
                }
                catch (OperationCanceledException) { break; }
                catch { }
            }

            // Clear hardware breakpoints on stop
            ClearHWBreakpointsOnAllThreads();
        }

        private bool SetHWBreakpointOnAllThreads(ulong address, int drSlot)
        {
            try
            {
                var threadIds = EnumerateThreadIds();
                int set = 0;

                foreach (uint tid in threadIds)
                {
                    bool success = false;

                    // Prefer kernel driver for thread context (bypasses anti-debug)
                    if (driver.IsKernelMode)
                    {
                        byte[] ctx = driver.GetThreadContext(processId, (int)tid, 0x00100010); // CONTEXT_DEBUG_REGISTERS
                        if (ctx != null && ctx.Length >= 2048)
                        {
                            int drOffset = 72 + (drSlot * 8);
                            BitConverter.GetBytes((long)address).CopyTo(ctx, drOffset);

                            long dr7 = BitConverter.ToInt64(ctx, 112);
                            dr7 |= (1L << (drSlot * 2));
                            BitConverter.GetBytes(dr7).CopyTo(ctx, 112);

                            success = driver.SetThreadContext(processId, (int)tid, ctx);
                        }
                    }

                    // Fallback to user-mode
                    if (!success)
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
                                int drOffset = 72 + (drSlot * 8);
                                Marshal.WriteInt64(ctxPtr, drOffset, (long)address);

                                long dr7 = Marshal.ReadInt64(ctxPtr, 112);
                                dr7 |= (1L << (drSlot * 2));
                                Marshal.WriteInt64(ctxPtr, 112, dr7);

                                success = SetThreadContext(hThread, ctxPtr);
                            }
                            Marshal.FreeHGlobal(ctxPtr);
                        }
                        finally { CloseHandle(hThread); }
                    }

                    if (success) set++;
                }
                return set > 0;
            }
            catch { return false; }
        }

        private void ClearHWBreakpointsOnAllThreads()
        {
            try
            {
                var threadIds = EnumerateThreadIds();
                foreach (uint tid in threadIds)
                {
                    bool success = false;

                    // Prefer kernel driver
                    if (driver.IsKernelMode)
                    {
                        byte[] ctx = driver.GetThreadContext(processId, (int)tid, 0x00100010);
                        if (ctx != null && ctx.Length >= 2048)
                        {
                            for (int dr = 0; dr < 4; dr++)
                                BitConverter.GetBytes(0L).CopyTo(ctx, 72 + dr * 8);
                            BitConverter.GetBytes(0L).CopyTo(ctx, 112);
                            success = driver.SetThreadContext(processId, (int)tid, ctx);
                        }
                    }

                    // Fallback to user-mode
                    if (!success)
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
                                for (int dr = 0; dr < 4; dr++)
                                    Marshal.WriteInt64(ctxPtr, 72 + dr * 8, 0);
                                Marshal.WriteInt64(ctxPtr, 112, 0);
                                SetThreadContext(hThread, ctxPtr);
                            }
                            Marshal.FreeHGlobal(ctxPtr);
                        }
                        finally { CloseHandle(hThread); }
                    }
                }
            }
            catch { }
        }

        private void PollBreakpointHits(List<KeyValuePair<ulong, string>> cryptoAddresses)
        {
            try
            {
                var threadIds = EnumerateThreadIds();
                foreach (uint tid in threadIds)
                {
                    IntPtr hThread = OpenThread(0x0008 | 0x0040, false, tid); // GET_CONTEXT | QUERY
                    if (hThread == IntPtr.Zero) continue;
                    try
                    {
                        IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                        for (int i = 0; i < 2048; i++) Marshal.WriteByte(ctxPtr, i, 0);
                        Marshal.WriteInt32(ctxPtr, 48, 0x00100010);

                        if (GetThreadContext(hThread, ctxPtr))
                        {
                            long dr6 = Marshal.ReadInt64(ctxPtr, 104); // DR6 status
                            for (int dr = 0; dr < Math.Min(4, cryptoAddresses.Count); dr++)
                            {
                                if ((dr6 & (1L << dr)) != 0)
                                {
                                    AddEvent(new ActivityEvent
                                    {
                                        Timestamp = DateTime.Now,
                                        Category = "Crypto",
                                        Action = "Call",
                                        Target = cryptoAddresses[dr].Value,
                                        Details = $"Hardware breakpoint hit on TID {tid}, DR{dr} @ 0x{cryptoAddresses[dr].Key:X}",
                                        Address = cryptoAddresses[dr].Key
                                    });

                                    // Clear the DR6 bit
                                    dr6 &= ~(1L << dr);
                                    Marshal.WriteInt64(ctxPtr, 104, dr6);
                                    SetThreadContext(hThread, ctxPtr);
                                }
                            }
                        }
                        Marshal.FreeHGlobal(ctxPtr);
                    }
                    finally { CloseHandle(hThread); }
                }
            }
            catch { }
        }

        private List<uint> EnumerateThreadIds()
        {
            var result = new List<uint>();
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
            return result;
        }

        private Dictionary<ulong, string> ResolveApiAddresses()
        {
            var result = new Dictionary<ulong, string>();
            try
            {
                var exportMap = driver.GetExportMap(processId);
                var allApis = CryptoApis.Concat(NetworkApis).Concat(FileApis).ToHashSet();

                foreach (var kvp in exportMap)
                {
                    if (allApis.Contains(kvp.Value.funcName))
                        result[kvp.Key] = $"{kvp.Value.dllName}!{kvp.Value.funcName}";
                }
            }
            catch { }
            return result;
        }

        private HashSet<uint> knownThreadIds = new HashSet<uint>();

        private void MonitorThreadActivity()
        {
            try
            {
                var currentThreads = new HashSet<uint>(EnumerateThreadIds());

                // Detect new threads
                foreach (uint tid in currentThreads)
                {
                    if (!knownThreadIds.Contains(tid))
                    {
                        AddEvent(new ActivityEvent
                        {
                            Timestamp = DateTime.Now,
                            Category = "Thread",
                            Action = "Create",
                            Target = $"TID: {tid}",
                            Details = "New thread created in process"
                        });
                    }
                }

                // Detect exited threads
                foreach (uint tid in knownThreadIds)
                {
                    if (!currentThreads.Contains(tid))
                    {
                        AddEvent(new ActivityEvent
                        {
                            Timestamp = DateTime.Now,
                            Category = "Thread",
                            Action = "Exit",
                            Target = $"TID: {tid}",
                            Details = "Thread terminated"
                        });
                    }
                }

                knownThreadIds = currentThreads;
            }
            catch { }
        }

        // ==================== Event Management ====================

        private void AddEvent(ActivityEvent ev)
        {
            lock (syncLock) allEvents.Add(ev);
            try
            {
                this.SafeInvoke(() =>
                {
                    ApplyFilter();
                    Log("[{0}] {1}: {2} {3}", ev.Timestamp.ToString("HH:mm:ss"), ev.Category, ev.Action, ev.Target);
                    statusLbl.Text = $"Monitoring... ({allEvents.Count} events)";
                });
            }
            catch { }
        }

        private List<ActivityEvent> GetFilteredEvents()
        {
            string filter = categoryFilter.SelectedItem?.ToString() ?? "All";
            lock (syncLock)
            {
                if (filter == "All") return new List<ActivityEvent>(allEvents);
                return allEvents.Where(e => e.Category == filter).ToList();
            }
        }

        private void ApplyFilter()
        {
            var filtered = GetFilteredEvents();
            activityList.VirtualListSize = filtered.Count;
            activityList.Invalidate();
            if (autoScrollCheck.Checked && filtered.Count > 0)
            {
                try { activityList.EnsureVisible(filtered.Count - 1); } catch { }
            }
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        // ==================== Helpers ====================

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private Label MakeLabel(string text) => new Label { Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
