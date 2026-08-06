using System;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// GDI/USER Object Leak Detector - monitors GDI and USER object counts
    /// over time to detect resource leaks in a process.
    /// </summary>
    public class GdiLeakDetector : Form
    {
        private readonly int processId;
        private readonly string processName;

        private Label gdiCountLbl;
        private Label userCountLbl;
        private Label gdiDeltaLbl;
        private Label userDeltaLbl;
        private RichTextBox logBox;
        private Button startBtn;
        private Button stopBtn;
        private NumericUpDown intervalBox;
        private NumericUpDown thresholdBox;
        private System.Windows.Forms.Timer monitorTimer;
        private int lastGdiCount;
        private int lastUserCount;
        private int peakGdi;
        private int peakUser;
        private int scanCount;

        public GdiLeakDetector(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            UpdateCounts();
        }

        private void InitializeComponent()
        {
            Text = $"GDI/USER Leak Detector - {processName} (PID: {processId})";
            Size = new Size(600, 500);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Main panel
            var mainPanel = new Panel { Dock = DockStyle.Top, Height = 200, BackColor = DarkTheme.Surface, Padding = new Padding(12) };

            // Title
            var titleLbl = new Label { Text = "GDI & USER Object Monitor", Dock = DockStyle.Top, Height = 30, ForeColor = DarkTheme.Accent, Font = new Font("Segoe UI", 12, FontStyle.Bold) };

            // Counters
            var counterPanel = new TableLayoutPanel { Dock = DockStyle.Top, Height = 120, ColumnCount = 3, RowCount = 3 };
            counterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            counterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));
            counterPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 30));

            // Headers
            counterPanel.Controls.Add(new Label { Text = "", Font = DarkTheme.UIFontBold, ForeColor = DarkTheme.TextSecondary }, 0, 0);
            counterPanel.Controls.Add(new Label { Text = "Current", Font = DarkTheme.UIFontBold, ForeColor = DarkTheme.TextSecondary, TextAlign = ContentAlignment.MiddleCenter }, 1, 0);
            counterPanel.Controls.Add(new Label { Text = "Delta", Font = DarkTheme.UIFontBold, ForeColor = DarkTheme.TextSecondary, TextAlign = ContentAlignment.MiddleCenter }, 2, 0);

            // GDI row
            counterPanel.Controls.Add(new Label { Text = "GDI Objects:", Font = DarkTheme.UIFont, ForeColor = DarkTheme.TextPrimary, TextAlign = ContentAlignment.MiddleLeft }, 0, 1);
            gdiCountLbl = new Label { Text = "0", Font = new Font("Segoe UI", 14, FontStyle.Bold), ForeColor = DarkTheme.Accent, TextAlign = ContentAlignment.MiddleCenter };
            counterPanel.Controls.Add(gdiCountLbl, 1, 1);
            gdiDeltaLbl = new Label { Text = "+0", Font = DarkTheme.UIFont, ForeColor = DarkTheme.TextMuted, TextAlign = ContentAlignment.MiddleCenter };
            counterPanel.Controls.Add(gdiDeltaLbl, 2, 1);

            // USER row
            counterPanel.Controls.Add(new Label { Text = "USER Objects:", Font = DarkTheme.UIFont, ForeColor = DarkTheme.TextPrimary, TextAlign = ContentAlignment.MiddleLeft }, 0, 2);
            userCountLbl = new Label { Text = "0", Font = new Font("Segoe UI", 14, FontStyle.Bold), ForeColor = DarkTheme.Accent, TextAlign = ContentAlignment.MiddleCenter };
            counterPanel.Controls.Add(userCountLbl, 1, 2);
            userDeltaLbl = new Label { Text = "+0", Font = DarkTheme.UIFont, ForeColor = DarkTheme.TextMuted, TextAlign = ContentAlignment.MiddleCenter };
            counterPanel.Controls.Add(userDeltaLbl, 2, 2);

            // Controls
            var controlPanel = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            startBtn = CreateButton("Start Monitor", 110);
            startBtn.Click += Start_Click;
            stopBtn = CreateButton("Stop", 60);
            stopBtn.Enabled = false;
            stopBtn.Click += Stop_Click;
            controlPanel.Controls.Add(MakeLabel("Interval (s):"));
            intervalBox = new DarkNumericUpDown { Width = 55, Minimum = 1, Maximum = 60, Value = 2 };
            controlPanel.Controls.Add(intervalBox);
            controlPanel.Controls.Add(MakeLabel("Alert if delta >"));
            thresholdBox = new DarkNumericUpDown { Width = 55, Minimum = 1, Maximum = 1000, Value = 10 };
            controlPanel.Controls.Add(thresholdBox);
            controlPanel.Controls.AddRange(new Control[] { startBtn, stopBtn });

            mainPanel.Controls.Add(counterPanel);
            mainPanel.Controls.Add(controlPanel);
            mainPanel.Controls.Add(titleLbl);

            // Log
            var logPanel = new Panel { Dock = DockStyle.Fill, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Leak Detection Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(logPanel);
            Controls.Add(mainPanel);
            DarkTheme.ApplyTo(this);

            FormClosing += (s, e) => { monitorTimer?.Stop(); };
        }

        private void UpdateCounts()
        {
            try
            {
                using (var proc = Process.GetProcessById(processId))
                {
                    int gdi = GetGuiResources(proc.Handle, 0); // GR_GDIOBJECTS
                    int user = GetGuiResources(proc.Handle, 1); // GR_USEROBJECTS

                    int gdiDelta = gdi - lastGdiCount;
                    int userDelta = user - lastUserCount;

                    if (gdi > peakGdi) peakGdi = gdi;
                    if (user > peakUser) peakUser = user;

                    gdiCountLbl.Text = gdi.ToString();
                    userCountLbl.Text = user.ToString();

                    gdiDeltaLbl.Text = gdiDelta >= 0 ? $"+{gdiDelta}" : gdiDelta.ToString();
                    userDeltaLbl.Text = userDelta >= 0 ? $"+{userDelta}" : userDelta.ToString();

                    int threshold = (int)thresholdBox.Value;

                    // Color based on delta
                    gdiDeltaLbl.ForeColor = Math.Abs(gdiDelta) > threshold ? DarkTheme.Error : (gdiDelta > 0 ? DarkTheme.Warning : (gdiDelta < 0 ? DarkTheme.Success : DarkTheme.TextMuted));
                    userDeltaLbl.ForeColor = Math.Abs(userDelta) > threshold ? DarkTheme.Error : (userDelta > 0 ? DarkTheme.Warning : (userDelta < 0 ? DarkTheme.Success : DarkTheme.TextMuted));

                    gdiCountLbl.ForeColor = gdi > 5000 ? DarkTheme.Error : (gdi > 2000 ? DarkTheme.Warning : DarkTheme.Accent);
                    userCountLbl.ForeColor = user > 5000 ? DarkTheme.Error : (user > 2000 ? DarkTheme.Warning : DarkTheme.Accent);

                    // Log significant changes
                    if (Math.Abs(gdiDelta) > threshold || Math.Abs(userDelta) > threshold)
                    {
                        Log("LEAK ALERT: GDI delta={0:+0;-0;0}, USER delta={1:+0;-0;0} (GDI={2}, USER={3})", gdiDelta, userDelta, gdi, user);
                    }
                    else if (gdiDelta != 0 || userDelta != 0)
                    {
                        scanCount++;
                        if (scanCount % 5 == 0) // Log every 5th scan
                            Log("Scan #{0}: GDI={1} ({2:+0;-0;0}), USER={3} ({4:+0;-0;0}) | Peak: GDI={5}, USER={6}", scanCount, gdi, gdiDelta, user, userDelta, peakGdi, peakUser);
                    }

                    lastGdiCount = gdi;
                    lastUserCount = user;
                }
            }
            catch (Exception ex)
            {
                Log("Error: {0}", ex.Message);
            }
        }

        private void Start_Click(object sender, EventArgs e)
        {
            startBtn.Enabled = false;
            stopBtn.Enabled = true;
            scanCount = 0;
            Log("Monitoring started (interval: {0}s, alert threshold: {1})", intervalBox.Value, thresholdBox.Value);

            monitorTimer = new System.Windows.Forms.Timer { Interval = (int)intervalBox.Value * 1000 };
            monitorTimer.Tick += (s, ev) => UpdateCounts();
            monitorTimer.Start();
        }

        private void Stop_Click(object sender, EventArgs e)
        {
            monitorTimer?.Stop();
            startBtn.Enabled = true;
            stopBtn.Enabled = false;
            Log("Monitoring stopped. Peak GDI={0}, Peak USER={1}", peakGdi, peakUser);
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        [DllImport("user32.dll")] private static extern int GetGuiResources(IntPtr hProcess, uint uiFlags);

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
    }
}
