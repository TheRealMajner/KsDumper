using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Environment Variable Viewer - reads and displays environment variables
    /// from a target process's PEB.
    /// </summary>
    public class EnvVariableViewer : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView envList;
        private RichTextBox detailsBox;
        private Button refreshBtn;
        private TextBox searchBox;
        private Label statsLbl;

        public EnvVariableViewer(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            RefreshEnv();
        }

        private void InitializeComponent()
        {
            Text = $"Environment Variables - {processName} (PID: {processId})";
            Size = new Size(800, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshEnv();
            toolbar.Controls.Add(MakeLabel("Search:"));
            searchBox = CreateTextBox(200);
            searchBox.TextChanged += (s, e) => FilterList();
            toolbar.Controls.Add(searchBox);
            statsLbl = new Label { Text = "", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.Add(statsLbl);

            // Split
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 400 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            envList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            envList.Columns.Add("Variable", 250);
            envList.Columns.Add("Value", 500);
            envList.Resize += (s, e) => { if (envList.Columns.Count > 0) envList.Columns[envList.Columns.Count - 1].Width = -2; };

            detailsBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            split.Panel1.Controls.Add(envList);
            split.Panel2.Controls.Add(detailsBox);

            Controls.Add(split);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshEnv()
        {
            envList.Items.Clear();
            var envVars = ReadProcessEnvironment();

            foreach (var kvp in envVars)
            {
                var lvi = new ListViewItem(kvp.Key);
                lvi.SubItems.Add(kvp.Value);

                // Color sensitive variables
                string lower = kvp.Key.ToLower();
                if (lower.Contains("password") || lower.Contains("secret") || lower.Contains("token") || lower.Contains("key"))
                    lvi.ForeColor = DarkTheme.Error;
                else if (lower.Contains("path"))
                    lvi.ForeColor = Color.FromArgb(88, 166, 255);
                else if (lower.Contains("temp") || lower.Contains("tmp"))
                    lvi.ForeColor = Color.FromArgb(210, 153, 34);
                else
                    lvi.ForeColor = DarkTheme.TextPrimary;

                envList.Items.Add(lvi);
            }

            statsLbl.Text = $"Variables: {envVars.Count}";

            detailsBox.Clear();
            detailsBox.SelectionColor = DarkTheme.Accent;
            detailsBox.AppendText("Process Environment Block\n");
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText(new string('═', 50) + "\n\n");
            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            detailsBox.AppendText($"  Process:  {processName}\n");
            detailsBox.AppendText($"  PID:      {processId}\n");
            detailsBox.AppendText($"  Variables: {envVars.Count}\n\n");
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText("  Color legend:\n");
            detailsBox.SelectionColor = DarkTheme.Error;
            detailsBox.AppendText("    Red    = Sensitive (password, secret, token, key)\n");
            detailsBox.SelectionColor = Color.FromArgb(88, 166, 255);
            detailsBox.AppendText("    Blue   = Path variables\n");
            detailsBox.SelectionColor = Color.FromArgb(210, 153, 34);
            detailsBox.AppendText("    Yellow = Temp/tmp directories\n");
        }

        private void FilterList()
        {
            string search = searchBox.Text.Trim().ToLower();
            foreach (ListViewItem item in envList.Items)
            {
                item.BackColor = Color.Transparent;
                if (string.IsNullOrEmpty(search))
                {
                    item.ForeColor = GetItemColor(item.Text.ToLower());
                }
                else
                {
                    bool match = item.Text.ToLower().Contains(search) || item.SubItems[1].Text.ToLower().Contains(search);
                    item.ForeColor = match ? DarkTheme.Accent : DarkTheme.TextMuted;
                }
            }
        }

        private Color GetItemColor(string key)
        {
            if (key.Contains("password") || key.Contains("secret") || key.Contains("token") || key.Contains("key"))
                return DarkTheme.Error;
            if (key.Contains("path"))
                return Color.FromArgb(88, 166, 255);
            if (key.Contains("temp") || key.Contains("tmp"))
                return Color.FromArgb(210, 153, 34);
            return DarkTheme.TextPrimary;
        }

        private List<KeyValuePair<string, string>> ReadProcessEnvironment()
        {
            var result = new List<KeyValuePair<string, string>>();

            try
            {
                IntPtr hProc = WinApi.OpenProcess(0x0400 | 0x0010, false, processId); // QUERY + VM_READ
                if (hProc == IntPtr.Zero) return result;

                try
                {
                    // Get PEB address
                    byte[] pbi = new byte[48];
                    int retLen = 0;
                    if (NtQueryInformationProcess(hProc, 0, pbi, pbi.Length, ref retLen) != 0) return result;
                    ulong pebAddr = BitConverter.ToUInt64(pbi, 8);
                    if (pebAddr == 0) return result;

                    // Read PEB to get ProcessParameters
                    // PEB.ProcessParameters is at offset 0x20 on x64
                    byte[] pebBuf = new byte[8];
                    IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)8, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) return result;
                    try
                    {
                        if (!driver.CopyVirtualMemory(processId, (IntPtr)(pebAddr + 0x20), buf, 8))
                            return result;
                        Marshal.Copy(buf, pebBuf, 0, 8);
                    }
                    finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }

                    ulong processParams = BitConverter.ToUInt64(pebBuf, 0);
                    if (processParams == 0) return result;

                    // RTL_USER_PROCESS_PARAMETERS.Environment is at offset 0x80 on x64
                    // Environment is a pointer to a block of null-terminated Unicode strings
                    // terminated by a double null
                    byte[] envPtrBuf = new byte[8];
                    buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)8, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) return result;
                    try
                    {
                        if (!driver.CopyVirtualMemory(processId, (IntPtr)(processParams + 0x80), buf, 8))
                            return result;
                        Marshal.Copy(buf, envPtrBuf, 0, 8);
                    }
                    finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }

                    ulong envBlock = BitConverter.ToUInt64(envPtrBuf, 0);
                    if (envBlock == 0) return result;

                    // Read environment block (up to 64KB)
                    int envSize = 0x10000;
                    byte[] envData = new byte[envSize];
                    buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)envSize, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) return result;
                    try
                    {
                        if (!driver.CopyVirtualMemory(processId, (IntPtr)envBlock, buf, envSize))
                            return result;
                        Marshal.Copy(buf, envData, 0, envSize);
                    }
                    finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }

                    // Parse Unicode environment block
                    // Format: VAR1=VALUE1\0VAR2=VALUE2\0\0
                    int offset = 0;
                    while (offset < envSize - 4)
                    {
                        // Find end of current string (double null terminator)
                        int strEnd = offset;
                        while (strEnd < envSize - 1)
                        {
                            if (envData[strEnd] == 0 && envData[strEnd + 1] == 0)
                                break;
                            strEnd += 2;
                        }

                        if (strEnd >= envSize - 1 || strEnd == offset) break;

                        string envStr = Encoding.Unicode.GetString(envData, offset, strEnd - offset);
                        offset = strEnd + 2; // Skip null terminator

                        if (string.IsNullOrEmpty(envStr)) break; // Double null = end

                        int eqIdx = envStr.IndexOf('=');
                        if (eqIdx > 0)
                        {
                            string key = envStr.Substring(0, eqIdx);
                            string value = envStr.Substring(eqIdx + 1);
                            result.Add(new KeyValuePair<string, string>(key, value));
                        }
                    }
                }
                finally { CloseHandle(hProc); }
            }
            catch { }

            return result;
        }

        // ==================== P/Invoke ====================

        [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(IntPtr h, int c, byte[] b, int s, ref int r);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        private TextBox CreateTextBox(int w) => new TextBox { Width = w, Margin = new Padding(2, 0, 4, 0), BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.FixedSingle, Font = DarkTheme.UIFont };
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
