using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class ProcessCloner : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private TextBox pidBox;
        private Button cloneBtn;
        private Button killCloneBtn;
        private Label statusLbl;
        private RichTextBox logBox;
        private int clonedPid = -1;

        public ProcessCloner(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"Process Cloner - {processName} (PID: {processId})";
            Size = new Size(700, 450);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 6, 8, 4) };

            toolbar.Controls.Add(MakeLabel("Target PID:"));
            pidBox = new TextBox { Width = 80, Text = processId.ToString(), Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.None };
            toolbar.Controls.Add(pidBox);

            cloneBtn = CreateButton("Clone Process", 120);
            cloneBtn.Click += Clone_Click;
            toolbar.Controls.Add(cloneBtn);

            killCloneBtn = CreateButton("Kill Clone", 100);
            killCloneBtn.Click += KillClone_Click;
            killCloneBtn.Enabled = false;
            toolbar.Controls.Add(killCloneBtn);

            statusLbl = new Label { Text = "Ready to clone", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.Add(statusLbl);

            logBox = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIMonoFont,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };

            var infoPanel = new Panel { Dock = DockStyle.Top, Height = 60, BackColor = DarkTheme.Surface, Padding = new Padding(12, 8, 12, 8) };
            var infoLbl = new Label
            {
                Dock = DockStyle.Fill,
                Text = "Process Cloning creates a memory-shared clone of the target process using NtCreateProcessEx.\n" +
                       "The clone shares the same address space but has its own handles, allowing safe memory reads\n" +
                       "without suspending threads or triggering anti-cheat detection.",
                ForeColor = DarkTheme.TextSecondary,
                Font = DarkTheme.UIFont
            };
            infoPanel.Controls.Add(infoLbl);

            Controls.Add(logBox);
            Controls.Add(infoPanel);
            Controls.Add(toolbar);

            DarkTheme.ApplyTo(this);
            Log("Target: {0} (PID: {1})", processName, processId);
        }

        private async void Clone_Click(object sender, EventArgs e)
        {
            int targetPid;
            if (!int.TryParse(pidBox.Text.Trim(), out targetPid) || targetPid <= 0)
            {
                Log("Invalid PID");
                return;
            }

            cloneBtn.Enabled = false;
            killCloneBtn.Enabled = false;
            statusLbl.Text = "Cloning process...";
            Log("Cloning PID {0}...", targetPid);

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var (status, pid) = driver.CloneProcess(targetPid);

                    this.SafeInvoke(() =>
                    {
                        if (status == 0 && pid > 0)
                        {
                            clonedPid = pid;
                            statusLbl.Text = $"Clone created: PID {pid}";
                            statusLbl.ForeColor = DarkTheme.Success;
                            Log("Process cloned successfully! Clone PID: {0}", pid);
                            Log("The clone shares the same address space as the original.");
                            Log("You can now read memory from the clone safely.");
                            killCloneBtn.Enabled = true;
                        }
                        else if (status == 1)
                        {
                            statusLbl.Text = "Process not found";
                            statusLbl.ForeColor = DarkTheme.Error;
                            Log("Process PID {0} not found", targetPid);
                        }
                        else if (status == 3)
                        {
                            statusLbl.Text = "ZwOpenProcess failed";
                            statusLbl.ForeColor = DarkTheme.Error;
                            Log("ZwOpenProcess failed. NTSTATUS=0x{0:X8}", unchecked((uint)pid));
                        }
                        else if (status == 4)
                        {
                            statusLbl.Text = "NtCreateProcessEx failed";
                            statusLbl.ForeColor = DarkTheme.Error;
                            Log("NtCreateProcessEx failed. NTSTATUS=0x{0:X8}", unchecked((uint)pid));
                        }
                        else
                        {
                            string detail = "";
                            if (status == 5) detail = "MmGetSystemRoutineAddress(NtCreateProcessEx) returned NULL";
                            else if (status == 6) detail = $"NtQueryInformationProcess failed NTSTATUS=0x{unchecked((uint)pid):X8}";
                            else if (status == 7) detail = "MmGetSystemRoutineAddress(NtQueryInformationProcess) returned NULL";
                            else detail = $"Unknown error code={status} pid={pid}";
                            statusLbl.Text = $"Failed (code {status})";
                            statusLbl.ForeColor = DarkTheme.Error;
                            Log("Clone failed: {0}", detail);
                        }
                        cloneBtn.Enabled = true;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        Log("Error: {0}", ex.Message);
                        statusLbl.Text = "Clone failed";
                        statusLbl.ForeColor = DarkTheme.Error;
                        cloneBtn.Enabled = true;
                    });
                }
            });
        }

        private async void KillClone_Click(object sender, EventArgs e)
        {
            if (clonedPid <= 0) return;

            if (MessageBox.Show($"Kill cloned process PID {clonedPid}?",
                "Confirm Kill", MessageBoxButtons.YesNo, MessageBoxIcon.Question) != DialogResult.Yes)
                return;

            killCloneBtn.Enabled = false;
            statusLbl.Text = "Killing clone...";

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var proc = Process.GetProcessById(clonedPid);
                    proc.Kill();
                    proc.WaitForExit(5000);

                    this.SafeInvoke(() =>
                    {
                        Log("Clone PID {0} terminated", clonedPid);
                        statusLbl.Text = "Clone killed";
                        statusLbl.ForeColor = DarkTheme.TextMuted;
                        clonedPid = -1;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        Log("Kill failed: {0}", ex.Message);
                        statusLbl.Text = "Kill failed";
                        statusLbl.ForeColor = DarkTheme.Error;
                        killCloneBtn.Enabled = true;
                    });
                }
            });
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private Label MakeLabel(string text) => new Label { Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
    }
}
