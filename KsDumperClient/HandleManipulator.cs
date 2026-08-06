using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Handle Manipulator - close, duplicate, or change protection on process handles.
    /// </summary>
    public class HandleManipulator : Form
    {
        private readonly int processId;
        private readonly string processName;

        private ListView handleList;
        private Button closeBtn;
        private Button duplicateBtn;
        private Button refreshBtn;
        private ComboBox filterCombo;
        private Label statsLbl;
        private RichTextBox logBox;

        public HandleManipulator(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            RefreshHandles();
        }

        private void InitializeComponent()
        {
            Text = $"Handle Manipulator - {processName} (PID: {processId})";
            Size = new Size(900, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshHandles();
            closeBtn = CreateButton("Close Handle", 100);
            closeBtn.Click += CloseHandle_Click;
            duplicateBtn = CreateButton("Duplicate", 80);
            duplicateBtn.Click += Duplicate_Click;
            toolbar.Controls.Add(MakeLabel("Filter:"));
            filterCombo = new DarkComboBox { Width = 100 };
            filterCombo.Items.AddRange(new object[] { "All", "File", "Mutant", "Event", "Section", "Thread", "Process", "Key" });
            filterCombo.SelectedIndex = 0;
            filterCombo.SelectedIndexChanged += (s, e) => RefreshHandles();
            toolbar.Controls.Add(filterCombo);
            statsLbl = new Label { Text = "", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.AddRange(new Control[] { refreshBtn, closeBtn, duplicateBtn, statsLbl });

            handleList = new ListView
            {
                View = View.Details, FullRowSelect = true, MultiSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            handleList.Columns.Add("Handle", 80);
            handleList.Columns.Add("Type", 100);
            handleList.Columns.Add("Name", 350);
            handleList.Columns.Add("Access", 100);
            handleList.Resize += (s, e) => { if (handleList.Columns.Count > 0) handleList.Columns[handleList.Columns.Count - 1].Width = -2; };

            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 100, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(handleList);
            Controls.Add(logPanel);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshHandles()
        {
            handleList.Items.Clear();
            string filter = filterCombo.SelectedItem?.ToString() ?? "All";
            var handles = EnumerateHandles();
            int count = 0;

            foreach (var (handle, typeName, name, access) in handles)
            {
                if (filter != "All" && !typeName.Equals(filter, StringComparison.OrdinalIgnoreCase))
                    continue;

                var lvi = new ListViewItem($"0x{handle:X4}");
                lvi.SubItems.Add(typeName);
                lvi.SubItems.Add(name);
                lvi.SubItems.Add($"0x{access:X8}");
                lvi.Tag = handle;

                switch (typeName)
                {
                    case "File": lvi.ForeColor = Color.FromArgb(88, 166, 255); break;
                    case "Mutant": lvi.ForeColor = Color.FromArgb(210, 153, 34); break;
                    case "Event": lvi.ForeColor = Color.FromArgb(63, 185, 80); break;
                    case "Thread": lvi.ForeColor = Color.FromArgb(180, 140, 255); break;
                    case "Process": lvi.ForeColor = DarkTheme.Error; break;
                    case "Key": lvi.ForeColor = Color.FromArgb(255, 165, 0); break;
                    default: lvi.ForeColor = DarkTheme.TextPrimary; break;
                }

                handleList.Items.Add(lvi);
                count++;
            }

            statsLbl.Text = $"Handles: {count}";
        }

        private void CloseHandle_Click(object sender, EventArgs e)
        {
            if (handleList.SelectedItems.Count == 0) return;
            var confirm = MessageBox.Show($"Close {handleList.SelectedItems.Count} handle(s)?", "Close Handles", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            IntPtr hProc = OpenProcess(0x0040, false, processId); // PROCESS_DUP_HANDLE
            if (hProc == IntPtr.Zero) { Log("Failed to open process"); return; }

            int closed = 0;
            foreach (ListViewItem item in handleList.SelectedItems)
            {
                int hValue = (int)item.Tag;
                // Close by duplicating with DUPLICATE_CLOSE_SOURCE
                IntPtr hDup;
                if (DuplicateHandle(hProc, (IntPtr)hValue, IntPtr.Zero, out hDup, 0, false, 0x00000001)) // DUPLICATE_CLOSE_SOURCE
                {
                    closed++;
                    Log("Closed handle 0x{0:X4}", hValue);
                }
            }
            CloseHandle(hProc);
            Log("Closed {0} handle(s)", closed);
            RefreshHandles();
        }

        private void Duplicate_Click(object sender, EventArgs e)
        {
            if (handleList.SelectedItems.Count == 0) return;

            IntPtr hProc = OpenProcess(0x0040, false, processId);
            if (hProc == IntPtr.Zero) { Log("Failed to open process"); return; }

            foreach (ListViewItem item in handleList.SelectedItems)
            {
                int hValue = (int)item.Tag;
                IntPtr hDup;
                if (DuplicateHandle(hProc, (IntPtr)hValue, GetCurrentProcess(), out hDup, 0, false, 0x00000002))
                {
                    Log("Duplicated 0x{0:X4} -> 0x{1:X} (in this process)", hValue, hDup.ToInt64());
                    CloseHandle(hDup); // Close our copy after logging
                }
                else
                {
                    Log("Failed to duplicate 0x{0:X4}", hValue);
                }
            }
            CloseHandle(hProc);
        }

        private List<(int handle, string typeName, string name, uint access)> EnumerateHandles()
        {
            var result = new List<(int, string, string, uint)>();
            int bufSize = 0x400000;
            IntPtr buffer = Marshal.AllocHGlobal(bufSize);
            try
            {
                int status = NtQuerySystemInformation(16, buffer, bufSize, out int retLen);
                if (status == unchecked((int)0xC0000004))
                {
                    bufSize = retLen + 0x10000;
                    Marshal.FreeHGlobal(buffer);
                    buffer = Marshal.AllocHGlobal(bufSize);
                    status = NtQuerySystemInformation(16, buffer, bufSize, out retLen);
                }
                if (status != 0) return result;

                long numHandles = Marshal.ReadInt64(buffer, 0);
                int entrySize = IntPtr.Size == 8 ? 24 : 16;

                IntPtr hProc = OpenProcess(0x0040, false, processId);
                if (hProc == IntPtr.Zero) { Marshal.FreeHGlobal(buffer); return result; }

                for (long i = 0; i < Math.Min(numHandles, 100000); i++)
                {
                    int off = 8 + (int)(i * entrySize);
                    if (off + entrySize > retLen) break;

                    int pid = Marshal.ReadInt32(buffer, off);
                    if (pid != processId) continue;

                    short hValue = Marshal.ReadInt16(buffer, off + (IntPtr.Size == 8 ? 8 : 4));
                    uint access = (uint)Marshal.ReadInt32(buffer, off + (IntPtr.Size == 8 ? 12 : 8));

                    string typeName = "";
                    string name = "";

                    IntPtr hDup;
                    if (DuplicateHandle(hProc, (IntPtr)hValue, GetCurrentProcess(), out hDup, 0, false, 0x00000002))
                    {
                        try
                        {
                            byte[] typeBuf = new byte[512];
                            if (NtQueryObject(hDup, 2, typeBuf, 512, out int typeLen) == 0)
                            {
                                int nLen = Marshal.ReadInt32(typeBuf, 0);
                                if (nLen > 0 && nLen < 256)
                                {
                                    IntPtr nPtr = Marshal.ReadIntPtr(typeBuf, IntPtr.Size);
                                    if (nPtr != IntPtr.Zero)
                                        typeName = Marshal.PtrToStringUni(nPtr, nLen / 2);
                                }
                            }

                            byte[] nameBuf = new byte[1024];
                            if (NtQueryObject(hDup, 1, nameBuf, 1024, out int nameLen) == 0)
                            {
                                int nLen = Marshal.ReadInt32(nameBuf, 0);
                                if (nLen > 0 && nLen < 512)
                                {
                                    IntPtr nPtr = Marshal.ReadIntPtr(nameBuf, IntPtr.Size);
                                    if (nPtr != IntPtr.Zero)
                                        name = Marshal.PtrToStringUni(nPtr, nLen / 2);
                                }
                            }
                        }
                        finally { CloseHandle(hDup); }
                    }

                    result.Add((hValue, typeName, name, access));
                }
                CloseHandle(hProc);
            }
            finally { Marshal.FreeHGlobal(buffer); }
            return result;
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int c, IntPtr b, int s, out int r);
        [DllImport("ntdll.dll")] private static extern int NtQueryObject(IntPtr h, int c, byte[] b, int s, out int r);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint a, bool i, int p);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DuplicateHandle(IntPtr hp, IntPtr h, IntPtr ht, out IntPtr hd, uint a, bool i, uint o);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
    }
}
