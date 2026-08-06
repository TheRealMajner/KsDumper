using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Hardware Breakpoint Manager - manages DR0-DR3 hardware breakpoints
    /// across all threads of a target process. Supports execution, write,
    /// and read/write breakpoints with real-time hit monitoring.
    /// </summary>
    public class HWBreakpointManager : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView bpList;
        private RichTextBox logBox;
        private TextBox addrBox;
        private ComboBox typeCombo;
        private ComboBox slotCombo;
        private ComboBox sizeCombo;
        private Button addBtn;
        private Button removeBtn;
        private Button clearAllBtn;
        private Button monitorBtn;
        private Label statusLbl;

        private struct HWBreakpoint
        {
            public int Slot; // 0-3 (DR0-DR3)
            public ulong Address;
            public string Type; // Execute, Write, ReadWrite
            public int Size; // 1, 2, 4, 8
            public bool Active;
            public int HitCount;
        }

        private readonly List<HWBreakpoint> breakpoints;
        private System.Windows.Forms.Timer monitorTimer;
        private bool isMonitoring;

        public HWBreakpointManager(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            breakpoints = new List<HWBreakpoint>();
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"HW Breakpoint Manager - {processName} (PID: {processId})";
            Size = new Size(900, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(8) };

            var row1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row1.Controls.Add(MakeLabel("Address:"));
            addrBox = CreateTextBox(140);
            addrBox.Font = DarkTheme.UIMonoFont;
            row1.Controls.Add(addrBox);
            row1.Controls.Add(MakeLabel("Type:"));
            typeCombo = new DarkComboBox { Width = 110 };
            typeCombo.Items.AddRange(new object[] { "Execute", "Write", "Read/Write" });
            typeCombo.SelectedIndex = 0;
            row1.Controls.Add(typeCombo);
            row1.Controls.Add(MakeLabel("Slot:"));
            slotCombo = new DarkComboBox { Width = 60 };
            slotCombo.Items.AddRange(new object[] { "DR0", "DR1", "DR2", "DR3", "Auto" });
            slotCombo.SelectedIndex = 4;
            row1.Controls.Add(slotCombo);
            row1.Controls.Add(MakeLabel("Size:"));
            sizeCombo = new DarkComboBox { Width = 55 };
            sizeCombo.Items.AddRange(new object[] { "1", "2", "4", "8" });
            sizeCombo.SelectedIndex = 2;
            row1.Controls.Add(sizeCombo);

            var row2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            addBtn = CreateButton("Add Breakpoint", 110);
            addBtn.Click += Add_Click;
            removeBtn = CreateButton("Remove Selected", 120);
            removeBtn.Click += Remove_Click;
            clearAllBtn = CreateButton("Clear All", 80);
            clearAllBtn.Click += ClearAll_Click;
            monitorBtn = CreateButton("Start Monitor", 110);
            monitorBtn.Click += Monitor_Click;
            statusLbl = new Label { Text = "Breakpoints: 0/4", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };

            row2.Controls.AddRange(new Control[] { addBtn, removeBtn, clearAllBtn, monitorBtn, statusLbl });

            toolbar.Controls.Add(row2);
            toolbar.Controls.Add(row1);

            // BP list
            bpList = new ListView
            {
                View = View.Details, FullRowSelect = true, MultiSelect = true,
                BorderStyle = BorderStyle.None, Dock = DockStyle.Fill,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            bpList.Columns.Add("Slot", 50);
            bpList.Columns.Add("Address", 140);
            bpList.Columns.Add("Type", 90);
            bpList.Columns.Add("Size", 50);
            bpList.Columns.Add("Status", 70);
            bpList.Columns.Add("Hits", 50);
            bpList.Resize += (s, e) => { if (bpList.Columns.Count > 0) bpList.Columns[bpList.Columns.Count - 1].Width = -2; };

            // Log
            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 120, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(bpList);
            Controls.Add(logPanel);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);

            FormClosing += (s, e) =>
            {
                monitorTimer?.Stop();
                if (breakpoints.Count > 0) ClearAllBreakpoints();
            };
        }

        private void Add_Click(object sender, EventArgs e)
        {
            string addrText = addrBox.Text.Trim().Replace("0x", "").Replace("0X", "");
            if (!ulong.TryParse(addrText, System.Globalization.NumberStyles.HexNumber, null, out ulong address))
            {
                Log("Invalid address");
                return;
            }

            if (breakpoints.Count >= 4)
            {
                Log("All 4 hardware breakpoint slots are in use");
                return;
            }

            int slot = slotCombo.SelectedIndex;
            if (slot == 4) // Auto
            {
                slot = -1;
                for (int i = 0; i < 4; i++)
                {
                    if (!breakpoints.Exists(bp => bp.Slot == i)) { slot = i; break; }
                }
                if (slot == -1) { Log("No free slots"); return; }
            }
            else
            {
                if (breakpoints.Exists(bp => bp.Slot == slot))
                {
                    Log("Slot DR{0} is already in use", slot);
                    return;
                }
            }

            string type = typeCombo.SelectedItem.ToString();
            int size = int.Parse(sizeCombo.SelectedItem.ToString());

            bool ok = SetHWBreakpoint(address, slot, type, size);
            if (ok)
            {
                breakpoints.Add(new HWBreakpoint { Slot = slot, Address = address, Type = type, Size = size, Active = true, HitCount = 0 });
                RefreshList();
                Log("Added HW breakpoint: DR{0} @ 0x{1:X} ({2}, {3} bytes)", slot, address, type, size);
            }
            else
            {
                Log("Failed to set HW breakpoint on DR{0}", slot);
            }
        }

        private void Remove_Click(object sender, EventArgs e)
        {
            if (bpList.SelectedItems.Count == 0) return;

            foreach (ListViewItem item in bpList.SelectedItems)
            {
                int slot = (int)item.Tag;
                ClearHWBreakpoint(slot);
                breakpoints.RemoveAll(bp => bp.Slot == slot);
                Log("Removed HW breakpoint DR{0}", slot);
            }
            RefreshList();
        }

        private void ClearAll_Click(object sender, EventArgs e)
        {
            ClearAllBreakpoints();
            breakpoints.Clear();
            RefreshList();
            Log("All hardware breakpoints cleared");
        }

        private void Monitor_Click(object sender, EventArgs e)
        {
            if (isMonitoring)
            {
                monitorTimer?.Stop();
                isMonitoring = false;
                monitorBtn.Text = "Start Monitor";
                Log("Monitoring stopped");
                return;
            }

            if (breakpoints.Count == 0) { Log("No breakpoints to monitor"); return; }

            isMonitoring = true;
            monitorBtn.Text = "Stop Monitor";

            monitorTimer = new System.Windows.Forms.Timer { Interval = 100 };
            monitorTimer.Tick += (s, ev) => PollBreakpointHits();
            monitorTimer.Start();
            Log("Monitoring started (polling every 100ms)");
        }

        private bool SetHWBreakpoint(ulong address, int slot, string type, int size)
        {
            var threadIds = EnumerateThreadIds();
            int set = 0;

            foreach (uint tid in threadIds)
            {
                byte[] ctx = null;
                if (driver.IsKernelMode)
                    ctx = driver.GetThreadContext(processId, (int)tid, 0x00100010);
                if (ctx == null)
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
                            ctx = new byte[2048];
                            Marshal.Copy(ctxPtr, ctx, 0, 2048);
                        }
                        Marshal.FreeHGlobal(ctxPtr);
                    }
                    finally { CloseHandle(hThread); }
                }

                if (ctx == null || ctx.Length < 2048) continue;

                // Set DRn to target address
                int drOffset = 72 + (slot * 8);
                BitConverter.GetBytes((long)address).CopyTo(ctx, drOffset);

                // Configure DR7
                long dr7 = BitConverter.ToInt64(ctx, 112);
                dr7 |= (1L << (slot * 2)); // Enable local

                // Condition bits: 16-17 for DR0, 20-21 for DR1, 24-25 for DR2, 28-29 for DR3
                int condShift = 16 + (slot * 4);
                dr7 &= ~(3L << condShift);
                long condValue = type == "Execute" ? 0L : type == "Write" ? 1L : 3L;
                dr7 |= (condValue << condShift);

                // Length bits: 18-19 for DR0, 22-23 for DR1, 26-27 for DR2, 30-31 for DR3
                int lenShift = 18 + (slot * 4);
                dr7 &= ~(3L << lenShift);
                long lenValue = size == 1 ? 0L : size == 2 ? 1L : size == 4 ? 3L : 2L;
                dr7 |= (lenValue << lenShift);

                BitConverter.GetBytes(dr7).CopyTo(ctx, 112);

                bool success = false;
                if (driver.IsKernelMode)
                    success = driver.SetThreadContext(processId, (int)tid, ctx);
                if (!success)
                {
                    IntPtr hThread = OpenThread(0x0008 | 0x0010 | 0x0040, false, tid);
                    if (hThread != IntPtr.Zero)
                    {
                        try
                        {
                            IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                            Marshal.Copy(ctx, 0, ctxPtr, 2048);
                            success = SetThreadContext(hThread, ctxPtr);
                            Marshal.FreeHGlobal(ctxPtr);
                        }
                        finally { CloseHandle(hThread); }
                    }
                }
                if (success) set++;
            }
            return set > 0;
        }

        private void ClearHWBreakpoint(int slot)
        {
            var threadIds = EnumerateThreadIds();
            foreach (uint tid in threadIds)
            {
                byte[] ctx = null;
                if (driver.IsKernelMode)
                    ctx = driver.GetThreadContext(processId, (int)tid, 0x00100010);
                if (ctx == null)
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
                            ctx = new byte[2048];
                            Marshal.Copy(ctxPtr, ctx, 0, 2048);
                        }
                        Marshal.FreeHGlobal(ctxPtr);
                    }
                    finally { CloseHandle(hThread); }
                }

                if (ctx == null || ctx.Length < 2048) continue;

                BitConverter.GetBytes(0L).CopyTo(ctx, 72 + (slot * 8));
                long dr7 = BitConverter.ToInt64(ctx, 112);
                dr7 &= ~(1L << (slot * 2));
                BitConverter.GetBytes(dr7).CopyTo(ctx, 112);

                if (driver.IsKernelMode)
                    driver.SetThreadContext(processId, (int)tid, ctx);
                else
                {
                    IntPtr hThread = OpenThread(0x0008 | 0x0010 | 0x0040, false, tid);
                    if (hThread != IntPtr.Zero)
                    {
                        try
                        {
                            IntPtr ctxPtr = Marshal.AllocHGlobal(2048);
                            Marshal.Copy(ctx, 0, ctxPtr, 2048);
                            SetThreadContext(hThread, ctxPtr);
                            Marshal.FreeHGlobal(ctxPtr);
                        }
                        finally { CloseHandle(hThread); }
                    }
                }
            }
        }

        private void ClearAllBreakpoints()
        {
            for (int i = 0; i < 4; i++)
                ClearHWBreakpoint(i);
        }

        private void PollBreakpointHits()
        {
            var threadIds = EnumerateThreadIds();
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
                        for (int i = 0; i < 2048; i++) Marshal.WriteByte(ctxPtr, i, 0);
                        Marshal.WriteInt32(ctxPtr, 48, 0x00100010);
                        if (GetThreadContext(hThread, ctxPtr))
                        {
                            ctx = new byte[2048];
                            Marshal.Copy(ctxPtr, ctx, 0, 2048);
                        }
                        Marshal.FreeHGlobal(ctxPtr);
                    }
                    finally { CloseHandle(hThread); }
                }

                if (ctx == null || ctx.Length < 2048) continue;

                long dr6 = BitConverter.ToInt64(ctx, 104);
                for (int dr = 0; dr < 4; dr++)
                {
                    if ((dr6 & (1L << dr)) != 0)
                    {
                        var bp = breakpoints.Find(b => b.Slot == dr);
                        if (bp.Active)
                        {
                            bp.HitCount++;
                            ulong rip = BitConverter.ToUInt64(ctx, 248);
                            Log("HIT: DR{0} @ 0x{1:X} on TID {2} (RIP: 0x{3:X}) - total hits: {4}", dr, bp.Address, tid, rip, bp.HitCount);

                            // Clear DR6 bit
                            dr6 &= ~(1L << dr);
                            BitConverter.GetBytes(dr6).CopyTo(ctx, 104);
                            if (driver.IsKernelMode)
                                driver.SetThreadContext(processId, (int)tid, ctx);
                        }
                    }
                }
            }
            RefreshList();
        }

        private void RefreshList()
        {
            bpList.Items.Clear();
            foreach (var bp in breakpoints)
            {
                var lvi = new ListViewItem($"DR{bp.Slot}");
                lvi.SubItems.Add($"0x{bp.Address:X}");
                lvi.SubItems.Add(bp.Type);
                lvi.SubItems.Add($"{bp.Size}");
                lvi.SubItems.Add(bp.Active ? "Active" : "Inactive");
                lvi.SubItems.Add(bp.HitCount.ToString());
                lvi.Tag = bp.Slot;

                lvi.ForeColor = bp.HitCount > 0 ? DarkTheme.Warning : (bp.Active ? DarkTheme.Success : DarkTheme.TextMuted);
                bpList.Items.Add(lvi);
            }
            statusLbl.Text = $"Breakpoints: {breakpoints.Count}/4";
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
                                uint tid = (uint)(IntPtr.Size == 8 ? Marshal.ReadInt64(tInfo, offThreadId) : Marshal.ReadInt32(tInfo, offThreadId));
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

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        // ==================== P/Invoke ====================

        [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int c, IntPtr b, int s, out int r);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenThread(uint a, bool i, uint t);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool GetThreadContext(IntPtr h, IntPtr c);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool SetThreadContext(IntPtr h, IntPtr c);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        private TextBox CreateTextBox(int w) => new TextBox { Width = w, Margin = new Padding(2, 0, 4, 0), BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.FixedSingle, Font = DarkTheme.UIFont };
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
