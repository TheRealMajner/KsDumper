using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Integrity Level Modifier - views and modifies the integrity level
    /// of a process token (Untrusted, Low, Medium, High, System).
    /// </summary>
    public class IntegrityModifier : Form
    {
        private readonly int processId;
        private readonly string processName;

        private Label currentLevelLbl;
        private ComboBox newLevelCombo;
        private Button applyBtn;
        private Button refreshBtn;
        private RichTextBox logBox;
        private RichTextBox detailsBox;

        private string currentLevel = "Unknown";

        private static readonly string[] IntegrityLevels = { "Untrusted", "Low", "Medium", "High", "System" };
        private static readonly uint[] IntegrityRids = { 0x0000, 0x1000, 0x2000, 0x3000, 0x4000 };

        public IntegrityModifier(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            RefreshLevel();
        }

        private void InitializeComponent()
        {
            Text = $"Integrity Level - {processName} (PID: {processId})";
            Size = new Size(600, 500);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Main panel
            var mainPanel = new Panel { Dock = DockStyle.Top, Height = 180, BackColor = DarkTheme.Surface, Padding = new Padding(12) };

            var titleLbl = new Label { Text = "Process Integrity Level", Dock = DockStyle.Top, Height = 30, ForeColor = DarkTheme.Accent, Font = new Font("Segoe UI", 12, FontStyle.Bold) };

            // Current level display
            var currentPanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            currentPanel.Controls.Add(new Label { Text = "Current Level:", Font = DarkTheme.UIFontBold, ForeColor = DarkTheme.TextSecondary, AutoSize = true, Margin = new Padding(0, 6, 8, 0) });
            currentLevelLbl = new Label { Text = "Unknown", Font = new Font("Segoe UI", 14, FontStyle.Bold), ForeColor = DarkTheme.Accent, AutoSize = true, Margin = new Padding(0, 2, 0, 0) };
            currentPanel.Controls.Add(currentLevelLbl);

            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshLevel();
            currentPanel.Controls.Add(new Label { Text = "", Width = 100 }); // spacer
            currentPanel.Controls.Add(refreshBtn);

            // New level selector
            var newPanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 40, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            newPanel.Controls.Add(new Label { Text = "Set to:", Font = DarkTheme.UIFontBold, ForeColor = DarkTheme.TextSecondary, AutoSize = true, Margin = new Padding(0, 6, 8, 0) });
            newLevelCombo = new DarkComboBox { Width = 120 };
            newLevelCombo.Items.AddRange(IntegrityLevels);
            newLevelCombo.SelectedIndex = 2; // Medium
            newPanel.Controls.Add(newLevelCombo);

            applyBtn = CreateButton("Apply", 70);
            applyBtn.Click += Apply_Click;
            newPanel.Controls.Add(new Label { Text = "", Width = 20 });
            newPanel.Controls.Add(applyBtn);

            // Warning
            var warningLbl = new Label
            {
                Text = "WARNING: Changing integrity level may destabilize the process. Use with caution.",
                Dock = DockStyle.Top, Height = 25, ForeColor = DarkTheme.Warning, Font = DarkTheme.UIFontSmall
            };

            mainPanel.Controls.Add(warningLbl);
            mainPanel.Controls.Add(newPanel);
            mainPanel.Controls.Add(currentPanel);
            mainPanel.Controls.Add(titleLbl);

            // Details + Log
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 200 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            detailsBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };

            split.Panel1.Controls.Add(detailsBox);
            split.Panel2.Controls.Add(logBox);
            split.Panel2.Controls.Add(logLabel);

            Controls.Add(split);
            Controls.Add(mainPanel);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshLevel()
        {
            try
            {
                IntPtr hProc = OpenProcess(0x0400, false, processId); // PROCESS_QUERY_INFORMATION
                if (hProc == IntPtr.Zero)
                {
                    hProc = OpenProcess(0x1000, false, processId); // PROCESS_QUERY_LIMITED_INFORMATION
                    if (hProc == IntPtr.Zero)
                    {
                        currentLevelLbl.Text = "Access Denied";
                        currentLevelLbl.ForeColor = DarkTheme.Error;
                        return;
                    }
                }

                try
                {
                    IntPtr hToken;
                    if (!OpenProcessToken(hProc, 0x0008, out hToken)) // TOKEN_QUERY
                    {
                        currentLevelLbl.Text = "Cannot open token";
                        currentLevelLbl.ForeColor = DarkTheme.Error;
                        return;
                    }

                    try
                    {
                        byte[] intBuf = new byte[256];
                        uint retLen;
                        if (GetTokenInformation(hToken, 25, intBuf, 256, out retLen)) // TokenIntegrityLevel = 25
                        {
                            IntPtr pSid = Marshal.ReadIntPtr(intBuf, 0);
                            if (pSid != IntPtr.Zero)
                            {
                                int subAuthCount = Marshal.ReadByte(pSid, 1);
                                if (subAuthCount > 0)
                                {
                                    uint rid = (uint)Marshal.ReadInt32(pSid, 8 + (subAuthCount - 1) * 4);

                                    if (rid >= 0x4000) currentLevel = "System";
                                    else if (rid >= 0x3000) currentLevel = "High";
                                    else if (rid >= 0x2000) currentLevel = "Medium";
                                    else if (rid >= 0x1000) currentLevel = "Low";
                                    else currentLevel = "Untrusted";

                                    currentLevelLbl.Text = $"{currentLevel} (RID: 0x{rid:X4})";
                                    currentLevelLbl.ForeColor = GetLevelColor(currentLevel);

                                    // Update combo to match
                                    for (int i = 0; i < IntegrityLevels.Length; i++)
                                    {
                                        if (IntegrityLevels[i] == currentLevel)
                                        {
                                            newLevelCombo.SelectedIndex = i;
                                            break;
                                        }
                                    }

                                    // Update details
                                    UpdateDetails(rid, subAuthCount, pSid);
                                }
                            }
                        }
                    }
                    finally { CloseHandle(hToken); }
                }
                finally { CloseHandle(hProc); }
            }
            catch (Exception ex)
            {
                Log("Error: {0}", ex.Message);
            }
        }

        private void UpdateDetails(uint rid, int subAuthCount, IntPtr pSid)
        {
            detailsBox.Clear();
            detailsBox.SelectionColor = DarkTheme.Accent;
            detailsBox.AppendText("Token Integrity Details\n");
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText(new string('═', 50) + "\n\n");

            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            detailsBox.AppendText($"  Process:         {processName}\n");
            detailsBox.AppendText($"  PID:             {processId}\n");
            detailsBox.AppendText($"  Integrity Level: {currentLevel}\n");
            detailsBox.AppendText($"  SID RID:         0x{rid:X4}\n");
            detailsBox.AppendText($"  SID SubAuths:    {subAuthCount}\n\n");

            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText("  Integrity Level Reference:\n");
            detailsBox.SelectionColor = Color.FromArgb(110, 118, 129);
            detailsBox.AppendText("    0x0000 = Untrusted (sandboxed)\n");
            detailsBox.SelectionColor = Color.FromArgb(210, 153, 34);
            detailsBox.AppendText("    0x1000 = Low (IE Protected Mode)\n");
            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            detailsBox.AppendText("    0x2000 = Medium (normal user)\n");
            detailsBox.SelectionColor = Color.FromArgb(88, 166, 255);
            detailsBox.AppendText("    0x3000 = High (elevated/admin)\n");
            detailsBox.SelectionColor = Color.FromArgb(188, 140, 255);
            detailsBox.AppendText("    0x4000 = System (SYSTEM account)\n");
        }

        private void Apply_Click(object sender, EventArgs e)
        {
            int selectedIndex = newLevelCombo.SelectedIndex;
            string targetLevel = IntegrityLevels[selectedIndex];
            uint targetRid = IntegrityRids[selectedIndex];

            if (targetLevel == currentLevel)
            {
                Log("Already at {0} integrity level", targetLevel);
                return;
            }

            Log("Changing integrity from {0} to {1} (RID 0x{2:X4})...", currentLevel, targetLevel, targetRid);

            try
            {
                IntPtr hProc = OpenProcess(0x0400, false, processId);
                if (hProc == IntPtr.Zero)
                {
                    Log("Failed to open process");
                    return;
                }

                try
                {
                    IntPtr hToken;
                    // Need TOKEN_ADJUST_DEFAULT to change integrity
                    if (!OpenProcessToken(hProc, 0x0100 | 0x0008, out hToken)) // ADJUST_DEFAULT | QUERY
                    {
                        Log("Failed to open token with TOKEN_ADJUST_DEFAULT");
                        return;
                    }

                    try
                    {
                        // Build TOKEN_MANDATORY_LABEL structure
                        // TOKEN_MANDATORY_LABEL = SID_AND_ATTRIBUTES + DWORD padding
                        // SID: Revision(1) + SubAuthCount(1) + Authority(6) + SubAuth(SubAuthCount*4)
                        int sidSize = 8 + 4; // 8 byte header + 1 sub-authority
                        int labelSize = sidSize + IntPtr.Size; // SID + Attributes DWORD + padding

                        byte[] label = new byte[labelSize];

                        // SID header
                        label[0] = 1; // Revision
                        label[1] = 1; // SubAuthCount = 1

                        // Authority: SECURITY_MANDATORY_LABEL_AUTHORITY = {0,0,0,0,0,16}
                        label[7] = 16;

                        // Sub-authority: the RID
                        byte[] ridBytes = BitConverter.GetBytes(targetRid);
                        Array.Copy(ridBytes, 0, label, 8, 4);

                        // SID_AND_ATTRIBUTES: Sid pointer + Attributes
                        // We need to build this in unmanaged memory
                        IntPtr labelPtr = Marshal.AllocHGlobal(labelSize);
                        Marshal.Copy(label, 0, labelPtr, labelSize);

                        IntPtr structPtr = Marshal.AllocHGlobal(IntPtr.Size + 4);
                        Marshal.WriteIntPtr(structPtr, 0, labelPtr);
                        Marshal.WriteInt32(structPtr, IntPtr.Size, 0x20); // SE_GROUP_INTEGRITY = 0x20

                        if (SetTokenInformation(hToken, 25, structPtr, (uint)(IntPtr.Size + 4))) // TokenIntegrityLevel = 25
                        {
                            Log("SUCCESS: Integrity level changed to {0} (RID 0x{1:X4})", targetLevel, targetRid);
                            currentLevel = targetLevel;
                            currentLevelLbl.Text = $"{currentLevel} (RID: 0x{targetRid:X4})";
                            currentLevelLbl.ForeColor = GetLevelColor(currentLevel);
                            RefreshLevel();
                        }
                        else
                        {
                            int err = Marshal.GetLastWin32Error();
                            Log("FAILED: SetTokenInformation error {0}", err);
                        }

                        Marshal.FreeHGlobal(structPtr);
                        Marshal.FreeHGlobal(labelPtr);
                    }
                    finally { CloseHandle(hToken); }
                }
                finally { CloseHandle(hProc); }
            }
            catch (Exception ex)
            {
                Log("Error: {0}", ex.Message);
            }
        }

        private Color GetLevelColor(string level)
        {
            switch (level)
            {
                case "System": return Color.FromArgb(188, 140, 255);
                case "High": return Color.FromArgb(88, 166, 255);
                case "Medium": return DarkTheme.Accent;
                case "Low": return Color.FromArgb(210, 153, 34);
                case "Untrusted": return Color.FromArgb(110, 118, 129);
                default: return DarkTheme.TextPrimary;
            }
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        // ==================== P/Invoke ====================

        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint a, bool i, int p);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool OpenProcessToken(IntPtr h, uint a, out IntPtr t);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool GetTokenInformation(IntPtr t, int c, byte[] b, uint s, out uint r);
        [DllImport("advapi32.dll", SetLastError = true)] private static extern bool SetTokenInformation(IntPtr t, int c, IntPtr b, uint s);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
