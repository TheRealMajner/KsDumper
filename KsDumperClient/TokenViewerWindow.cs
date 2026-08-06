using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class TokenViewerWindow : Form
    {
        private readonly int processId;
        private readonly string processName;
        private ListView privList;
        private ListView groupList;
        private Label integrityLbl;
        private Label userLbl;

        public TokenViewerWindow(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            LoadTokenInfo();
        }

        private void InitializeComponent()
        {
            Text = $"Token - {processName} (PID: {processId})";
            Size = new Size(800, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var splitContainer = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3 };
            splitContainer.Panel1.BackColor = DarkTheme.Background;
            splitContainer.Panel2.BackColor = DarkTheme.Background;

            // Top: Privileges
            var privToolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            var enableBtn = CreateButton("Enable", 65);
            enableBtn.Click += EnablePriv_Click;
            var disableBtn = CreateButton("Disable", 70);
            disableBtn.Click += DisablePriv_Click;
            var refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => LoadTokenInfo();
            privToolbar.Controls.AddRange(new Control[] { enableBtn, disableBtn, refreshBtn });

            userLbl = new Label { Text = "User: ...", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFont, Margin = new Padding(16, 6, 0, 0) };
            integrityLbl = new Label { Text = "Integrity: ...", AutoSize = true, ForeColor = DarkTheme.Warning, Font = DarkTheme.UIFont, Margin = new Padding(16, 6, 0, 0) };
            privToolbar.Controls.AddRange(new Control[] { userLbl, integrityLbl });

            privList = CreateListView();
            privList.Columns.Add("Privilege", 300);
            privList.Columns.Add("Status", 100);
            privList.Columns.Add("LUID", 120);
            splitContainer.Panel1.Controls.Add(privList);
            splitContainer.Panel1.Controls.Add(privToolbar);

            // Bottom: Groups
            var groupToolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 28, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            groupToolbar.Controls.Add(new Label { Text = "Groups:", AutoSize = true, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold });

            groupList = CreateListView();
            groupList.Columns.Add("SID / Name", 400);
            groupList.Columns.Add("Attributes", 200);
            splitContainer.Panel2.Controls.Add(groupList);
            splitContainer.Panel2.Controls.Add(groupToolbar);

            Controls.Add(splitContainer);
            DarkTheme.ApplyTo(this);
        }

        private void LoadTokenInfo()
        {
            privList.Items.Clear();
            groupList.Items.Clear();

            IntPtr hProcess = OpenProcess(0x0400, false, processId); // PROCESS_QUERY_INFORMATION
            if (hProcess == IntPtr.Zero) { userLbl.Text = "Access denied"; return; }

            IntPtr hToken;
            if (!OpenProcessToken(hProcess, 0x00020008, out hToken)) // TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES
            {
                CloseHandle(hProcess);
                userLbl.Text = "Cannot open token";
                return;
            }

            try
            {
                // Token User
                byte[] userInfo = QueryToken(hToken, 1, 256); // TokenUser
                if (userInfo != null)
                {
                    IntPtr sidPtr = Marshal.ReadIntPtr(Marshal.UnsafeAddrOfPinnedArrayElement(userInfo, 0), 0);
                    StringBuilder name = new StringBuilder(256);
                    StringBuilder domain = new StringBuilder(256);
                    int nameSize = 256, domainSize = 256;
                    int sidType;
                    if (LookupAccountSid(null, sidPtr, name, ref nameSize, domain, ref domainSize, out sidType))
                        userLbl.Text = $"User: {domain}\\{name}";
                }

                // Token Integrity
                byte[] intInfo = QueryToken(hToken, 25, 256); // TokenIntegrityLevel
                if (intInfo != null)
                {
                    IntPtr sidPtr = Marshal.ReadIntPtr(Marshal.UnsafeAddrOfPinnedArrayElement(intInfo, 0), 0);
                    IntPtr subAuth = GetSidSubAuthority(sidPtr, 0);
                    int rid = Marshal.ReadInt32(subAuth);
                    string level = rid >= 0x4000 ? "System" : rid >= 0x2000 ? "High" : rid >= 0x1000 ? "Medium" : rid >= 0x200 ? "Low" : "Untrusted";
                    integrityLbl.Text = $"Integrity: {level} (0x{rid:X})";
                }

                // Token Privileges
                byte[] privInfo = QueryToken(hToken, 3, 4096); // TokenPrivileges
                if (privInfo != null)
                {
                    int privCount = BitConverter.ToInt32(privInfo, 0);
                    for (int i = 0; i < privCount; i++)
                    {
                        int off = 4 + i * 12; // LUID (8) + Attributes (4)
                        long luid = BitConverter.ToInt64(privInfo, off);
                        uint attrs = BitConverter.ToUInt32(privInfo, off + 8);

                        StringBuilder privName = new StringBuilder(256);
                        int nameLen = 256;
                        TOKEN_LUID tl; tl.LowPart = (uint)(luid & 0xFFFFFFFF); tl.HighPart = (int)(luid >> 32);
                        if (LookupPrivilegeName(null, ref tl, privName, ref nameLen))
                        {
                            string status = (attrs & 0x00000002) != 0 ? "Enabled" : (attrs & 0x80000000u) != 0 ? "Removed" : "Disabled";
                            var lvi = new ListViewItem(privName.ToString());
                            lvi.SubItems.Add(status);
                            lvi.SubItems.Add($"0x{luid:X}");
                            lvi.ForeColor = status == "Enabled" ? DarkTheme.Success : DarkTheme.TextMuted;
                            privList.Items.Add(lvi);
                        }
                    }
                }
            }
            finally
            {
                CloseHandle(hToken);
                CloseHandle(hProcess);
            }
        }

        private void EnablePriv_Click(object sender, EventArgs e) { AdjustSelectedPriv(true); }
        private void DisablePriv_Click(object sender, EventArgs e) { AdjustSelectedPriv(false); }

        private void AdjustSelectedPriv(bool enable)
        {
            if (privList.SelectedItems.Count == 0) return;
            string privName = privList.SelectedItems[0].Text;

            IntPtr hProcess = OpenProcess(0x0400, false, processId);
            if (hProcess == IntPtr.Zero) return;
            IntPtr hToken;
            if (!OpenProcessToken(hProcess, 0x0020, out hToken)) { CloseHandle(hProcess); return; } // TOKEN_ADJUST_PRIVILEGES

            try
            {
                TOKEN_LUID luid;
                if (!LookupPrivilegeValue(null, privName, out luid)) return;

                TOKEN_PRIVILEGES tp;
                tp.PrivilegeCount = 1;
                tp.Luid = luid;
                tp.Attributes = (uint)(enable ? 0x00000002 : 0); // SE_PRIVILEGE_ENABLED

                AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
                LoadTokenInfo();
            }
            finally
            {
                CloseHandle(hToken);
                CloseHandle(hProcess);
            }
        }

        private byte[] QueryToken(IntPtr hToken, int infoClass, int bufSize)
        {
            IntPtr buf = Marshal.AllocHGlobal(bufSize);
            try
            {
                if (GetTokenInformation(hToken, infoClass, buf, bufSize, out int retLen))
                {
                    byte[] data = new byte[retLen];
                    Marshal.Copy(buf, data, 0, retLen);
                    return data;
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
            return null;
        }

        // ==================== P/Invoke ====================

        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr hProcess, uint access, out IntPtr hToken);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr hToken, int infoClass, IntPtr buffer, int bufSize, out int retLen);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool LookupPrivilegeName(string system, ref TOKEN_LUID luid, StringBuilder name, ref int nameLen);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] private static extern bool LookupPrivilegeValue(string system, string name, out TOKEN_LUID luid);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool AdjustTokenPrivileges(IntPtr hToken, bool disableAll, ref TOKEN_PRIVILEGES newState, int bufLen, IntPtr prevState, IntPtr retLen);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool LookupAccountSid(string system, IntPtr sid, StringBuilder name, ref int nameLen, StringBuilder domain, ref int domainLen, out int sidType);
        [DllImport("advapi32.dll")] private static extern IntPtr GetSidSubAuthority(IntPtr sid, int index);
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);

        [StructLayout(LayoutKind.Sequential)] private struct TOKEN_LUID { public uint LowPart; public int HighPart; }
        [StructLayout(LayoutKind.Sequential)] private struct TOKEN_PRIVILEGES { public int PrivilegeCount; public TOKEN_LUID Luid; public uint Attributes; }

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private ListView CreateListView()
        {
            var lv = new ListView { View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None, Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont };
            lv.Resize += (s, e) => { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; };
            lv.HandleCreated += (s, e) => { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; };
            return lv;
        }
    }
}
