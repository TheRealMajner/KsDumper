using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Token Privilege Enumerator - enumerates all token privileges and flags
    /// for a process, with enable/disable capability.
    /// </summary>
    public class TokenPrivilegeViewer : Form
    {
        private readonly int processId;
        private readonly string processName;

        private ListView privList;
        private Button enableBtn;
        private Button disableBtn;
        private Button refreshBtn;
        private Label statsLbl;
        private RichTextBox detailsBox;

        private struct TokenPrivilege
        {
            public string Name;
            public string DisplayName;
            public long Luid;
            public uint Attributes;
            public bool Enabled;
        }

        public TokenPrivilegeViewer(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            RefreshPrivileges();
        }

        private void InitializeComponent()
        {
            Text = $"Token Privileges - {processName} (PID: {processId})";
            Size = new Size(900, 650);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshPrivileges();
            enableBtn = CreateButton("Enable", 60);
            enableBtn.Click += Enable_Click;
            disableBtn = CreateButton("Disable", 70);
            disableBtn.Click += Disable_Click;
            statsLbl = new Label { Text = "", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.AddRange(new Control[] { refreshBtn, enableBtn, disableBtn, statsLbl });

            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 400 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            privList = new ListView
            {
                View = View.Details, FullRowSelect = true, MultiSelect = true,
                BorderStyle = BorderStyle.None, Dock = DockStyle.Fill,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            privList.Columns.Add("Privilege", 250);
            privList.Columns.Add("Display Name", 200);
            privList.Columns.Add("Status", 80);
            privList.Columns.Add("LUID", 120);
            privList.Columns.Add("Attributes", 120);
            privList.Resize += (s, e) => { if (privList.Columns.Count > 0) privList.Columns[privList.Columns.Count - 1].Width = -2; };
            privList.SelectedIndexChanged += PrivList_SelectedIndexChanged;

            detailsBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            split.Panel1.Controls.Add(privList);
            split.Panel2.Controls.Add(detailsBox);

            Controls.Add(split);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshPrivileges()
        {
            privList.Items.Clear();

            try
            {
                IntPtr hProc = OpenProcess(0x0400, false, processId);
                if (hProc == IntPtr.Zero) return;

                try
                {
                    IntPtr hToken;
                    if (!OpenProcessToken(hProc, 0x0008 | 0x0020, out hToken)) // QUERY | ADJUST
                        return;

                    try
                    {
                        // Get token privileges
                        byte[] privBuf = new byte[4096];
                        uint retLen;
                        if (!GetTokenInformation(hToken, 3, privBuf, 4096, out retLen)) // TokenPrivileges = 3
                            return;

                        int privCount = BitConverter.ToInt32(privBuf, 0);
                        int enabled = 0;

                        for (int i = 0; i < privCount; i++)
                        {
                            int off = 4 + i * 12; // LUID (8) + Attributes (4)
                            if (off + 12 > privBuf.Length) break;

                            long luid = BitConverter.ToInt64(privBuf, off);
                            uint attrs = BitConverter.ToUInt32(privBuf, off + 8);
                            bool isEnabled = (attrs & 0x00000002) != 0; // SE_PRIVILEGE_ENABLED

                            // Lookup privilege name
                            StringBuilder nameBuf = new StringBuilder(256);
                            uint nameLen = 256;
                            LookupPrivilegeName(null, ref luid, nameBuf, ref nameLen);
                            string privName = nameBuf.ToString();

                            // Lookup display name
                            StringBuilder displayBuf = new StringBuilder(256);
                            uint displayLen = 256;
                            uint langId;
                            LookupPrivilegeDisplayName(null, privName, displayBuf, ref displayLen, out langId);
                            string displayName = displayBuf.ToString();

                            var lvi = new ListViewItem(privName);
                            lvi.SubItems.Add(displayName);
                            lvi.SubItems.Add(isEnabled ? "Enabled" : "Disabled");
                            lvi.SubItems.Add($"0x{luid:X}");
                            lvi.SubItems.Add($"0x{attrs:X8}");
                            lvi.Tag = luid;

                            lvi.ForeColor = isEnabled ? DarkTheme.Success : DarkTheme.TextMuted;

                            // Highlight dangerous privileges
                            string lower = privName.ToLower();
                            if (lower.Contains("debug") || lower.Contains("impersonate") || lower.Contains("tcb") || lower.Contains("assignprimarytoken"))
                                lvi.ForeColor = isEnabled ? DarkTheme.Error : DarkTheme.Warning;

                            privList.Items.Add(lvi);
                            if (isEnabled) enabled++;
                        }

                        statsLbl.Text = $"Privileges: {privCount} (Enabled: {enabled}, Disabled: {privCount - enabled})";
                    }
                    finally { CloseHandle(hToken); }
                }
                finally { CloseHandle(hProc); }
            }
            catch (Exception ex) { detailsBox.Text = $"Error: {ex.Message}"; }
        }

        private void PrivList_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (privList.SelectedItems.Count == 0) { detailsBox.Clear(); return; }
            var item = privList.SelectedItems[0];

            detailsBox.Clear();
            detailsBox.SelectionColor = DarkTheme.Accent;
            detailsBox.AppendText($"{item.Text}\n");
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText(new string('═', 50) + "\n\n");

            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            detailsBox.AppendText($"  Privilege:    {item.Text}\n");
            detailsBox.AppendText($"  Display Name: {item.SubItems[1].Text}\n");
            detailsBox.AppendText($"  Status:       {item.SubItems[2].Text}\n");
            detailsBox.AppendText($"  LUID:         {item.SubItems[3].Text}\n");
            detailsBox.AppendText($"  Attributes:   {item.SubItems[4].Text}\n\n");

            // Show risk assessment
            string lower = item.Text.ToLower();
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText("  Risk Assessment:\n");

            if (lower.Contains("debug"))
            {
                detailsBox.SelectionColor = DarkTheme.Error;
                detailsBox.AppendText("    CRITICAL: Allows debugging any process. Full memory access.\n");
            }
            else if (lower.Contains("tcb"))
            {
                detailsBox.SelectionColor = DarkTheme.Error;
                detailsBox.AppendText("    CRITICAL: Act as part of the operating system.\n");
            }
            else if (lower.Contains("impersonate"))
            {
                detailsBox.SelectionColor = DarkTheme.Error;
                detailsBox.AppendText("    HIGH: Impersonate any user/security context.\n");
            }
            else if (lower.Contains("assignprimarytoken"))
            {
                detailsBox.SelectionColor = DarkTheme.Error;
                detailsBox.AppendText("    HIGH: Replace process-level token.\n");
            }
            else if (lower.Contains("backup") || lower.Contains("restore"))
            {
                detailsBox.SelectionColor = DarkTheme.Warning;
                detailsBox.AppendText("    MEDIUM: Bypass file access checks for backup/restore.\n");
            }
            else if (lower.Contains("takeownership"))
            {
                detailsBox.SelectionColor = DarkTheme.Warning;
                detailsBox.AppendText("    MEDIUM: Take ownership of any object.\n");
            }
            else if (lower.Contains("shutdown"))
            {
                detailsBox.SelectionColor = DarkTheme.Warning;
                detailsBox.AppendText("    MEDIUM: Shut down the system.\n");
            }
            else
            {
                detailsBox.SelectionColor = DarkTheme.Success;
                detailsBox.AppendText("    LOW: Standard privilege.\n");
            }

            // Attribute flags
            uint attrs = uint.Parse(item.SubItems[4].Text.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber);
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText("\n  Attribute Flags:\n");
            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            if ((attrs & 0x00000001) != 0) detailsBox.AppendText("    SE_PRIVILEGE_ENABLED_BY_DEFAULT\n");
            if ((attrs & 0x00000002) != 0) detailsBox.AppendText("    SE_PRIVILEGE_ENABLED\n");
            if ((attrs & 0x80000000) != 0) detailsBox.AppendText("    SE_PRIVILEGE_REMOVED\n");
        }

        private void Enable_Click(object sender, EventArgs e) { AdjustPrivileges(true); }
        private void Disable_Click(object sender, EventArgs e) { AdjustPrivileges(false); }

        private void AdjustPrivileges(bool enable)
        {
            if (privList.SelectedItems.Count == 0) return;

            IntPtr hProc = OpenProcess(0x0400, false, processId);
            if (hProc == IntPtr.Zero) return;

            IntPtr hToken;
            if (!OpenProcessToken(hProc, 0x0020, out hToken)) { CloseHandle(hProc); return; }

            int adjusted = 0;
            foreach (ListViewItem item in privList.SelectedItems)
            {
                long luid = (long)item.Tag;
                TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount = 1;
                tp.Luid = luid;
                tp.Attributes = (uint)(enable ? 0x00000002 : 0x00000000);

                if (AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
                    adjusted++;
            }

            CloseHandle(hToken);
            CloseHandle(hProc);
            RefreshPrivileges();
        }

        // ==================== P/Invoke ====================

        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint a, bool i, int p);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr t, int c, byte[] b, uint s, out uint r);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TOKEN_PRIVILEGES p, uint s, IntPtr prev, IntPtr retLen);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool LookupPrivilegeName(string sys, ref long luid, StringBuilder name, ref uint nameLen);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool LookupPrivilegeDisplayName(string sys, string name, StringBuilder display, ref uint displayLen, out uint langId);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public long Luid; public uint Attributes; }

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
