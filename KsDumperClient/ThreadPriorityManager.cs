using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Thread Priority Manager - view and change thread priorities,
    /// suspend/resume individual threads, view thread state and wait reason.
    /// </summary>
    public class ThreadPriorityManager : Form
    {
        private readonly int processId;
        private readonly string processName;

        private ListView threadList;
        private ComboBox priorityCombo;
        private Button setPriorityBtn;
        private Button suspendBtn;
        private Button resumeBtn;
        private Button refreshBtn;
        private Label statsLbl;
        private RichTextBox detailsBox;

        private struct ThreadInfo
        {
            public int Id;
            public int Priority;
            public int BasePriority;
            public ThreadState State;
            public ThreadWaitReason WaitReason;
            public int WaitTime;
            public DateTime StartTime;
            public TimeSpan TotalTime;
        }

        public ThreadPriorityManager(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            RefreshThreads();
        }

        private void InitializeComponent()
        {
            Text = $"Thread Manager - {processName} (PID: {processId})";
            Size = new Size(1000, 650);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(8) };

            var row1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshThreads();
            suspendBtn = CreateButton("Suspend", 70);
            suspendBtn.Click += Suspend_Click;
            resumeBtn = CreateButton("Resume", 70);
            resumeBtn.Click += Resume_Click;
            row1.Controls.AddRange(new Control[] { refreshBtn, suspendBtn, resumeBtn });

            var row2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row2.Controls.Add(MakeLabel("Set Priority:"));
            priorityCombo = new DarkComboBox { Width = 120 };
            priorityCombo.Items.AddRange(new object[] { "Idle (-2)", "Lowest (-1)", "BelowNormal (-1)", "Normal (0)", "AboveNormal (1)", "Highest (1)", "TimeCritical (2)" });
            priorityCombo.SelectedIndex = 3;
            row2.Controls.Add(priorityCombo);
            setPriorityBtn = CreateButton("Apply", 60);
            setPriorityBtn.Click += SetPriority_Click;
            row2.Controls.Add(setPriorityBtn);
            statsLbl = new Label { Text = "", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            row2.Controls.Add(statsLbl);

            toolbar.Controls.Add(row2);
            toolbar.Controls.Add(row1);

            // Split: list + details
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 380 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            threadList = new ListView
            {
                View = View.Details, FullRowSelect = true, MultiSelect = true,
                BorderStyle = BorderStyle.None, Dock = DockStyle.Fill,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            threadList.Columns.Add("TID", 70);
            threadList.Columns.Add("Priority", 70);
            threadList.Columns.Add("Base", 60);
            threadList.Columns.Add("State", 90);
            threadList.Columns.Add("Wait Reason", 120);
            threadList.Columns.Add("Wait Time", 80);
            threadList.Columns.Add("CPU Time", 100);
            threadList.Columns.Add("Start Time", 140);
            threadList.Resize += (s, e) => { if (threadList.Columns.Count > 0) threadList.Columns[threadList.Columns.Count - 1].Width = -2; };
            threadList.SelectedIndexChanged += ThreadList_SelectedIndexChanged;

            detailsBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            split.Panel1.Controls.Add(threadList);
            split.Panel2.Controls.Add(detailsBox);

            Controls.Add(split);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshThreads()
        {
            threadList.Items.Clear();
            try
            {
                using (var proc = Process.GetProcessById(processId))
                {
                    int running = 0, waiting = 0, suspended = 0;

                    foreach (ProcessThread t in proc.Threads)
                    {
                        var lvi = new ListViewItem(t.Id.ToString());
                        lvi.SubItems.Add(t.CurrentPriority.ToString());
                        lvi.SubItems.Add(t.BasePriority.ToString());
                        lvi.SubItems.Add(t.ThreadState.ToString());
                        lvi.SubItems.Add(t.ThreadState == ThreadState.Wait ? t.WaitReason.ToString() : "-");
                        lvi.SubItems.Add("?");
                        lvi.SubItems.Add($"{t.TotalProcessorTime.TotalMilliseconds:F0}ms");
                        try { lvi.SubItems.Add(t.StartTime.ToString("HH:mm:ss.fff")); } catch { lvi.SubItems.Add("?"); }

                        switch (t.ThreadState)
                        {
                            case ThreadState.Running: lvi.ForeColor = DarkTheme.Success; running++; break;
                            case ThreadState.Wait: lvi.ForeColor = DarkTheme.TextSecondary; waiting++; break;
                            case ThreadState.Terminated: lvi.ForeColor = DarkTheme.TextMuted; break;
                            default: lvi.ForeColor = DarkTheme.TextPrimary; break;
                        }

                        lvi.Tag = t.Id;
                        threadList.Items.Add(lvi);
                    }

                    statsLbl.Text = $"Threads: {proc.Threads.Count} (Running: {running}, Waiting: {waiting}, Suspended: {suspended})";
                }
            }
            catch (Exception ex) { detailsBox.Text = $"Error: {ex.Message}"; }
        }

        private void ThreadList_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (threadList.SelectedItems.Count == 0) { detailsBox.Clear(); return; }

            try
            {
                using (var proc = Process.GetProcessById(processId))
                {
                    int tid = (int)threadList.SelectedItems[0].Tag;
                    foreach (ProcessThread t in proc.Threads)
                    {
                        if (t.Id == tid)
                        {
                            detailsBox.Clear();
                            detailsBox.SelectionColor = DarkTheme.Accent;
                            detailsBox.AppendText($"Thread {t.Id}\n");
                            detailsBox.SelectionColor = DarkTheme.TextSecondary;
                            detailsBox.AppendText(new string('═', 50) + "\n\n");

                            detailsBox.SelectionColor = DarkTheme.TextPrimary;
                            detailsBox.AppendText($"  Thread ID:       {t.Id}\n");
                            detailsBox.AppendText($"  Current Priority: {t.CurrentPriority}\n");
                            detailsBox.AppendText($"  Base Priority:    {t.BasePriority}\n");
                            detailsBox.AppendText($"  Priority Level:   {t.PriorityLevel}\n");
                            detailsBox.AppendText($"  Priority Boost:   {t.PriorityBoostEnabled}\n");
                            detailsBox.AppendText($"  State:            {t.ThreadState}\n");

                            if (t.ThreadState == ThreadState.Wait)
                                detailsBox.AppendText($"  Wait Reason:      {t.WaitReason}\n");

                            detailsBox.AppendText($"  Wait Time:        N/A\n");
                            detailsBox.AppendText($"  User Time:        {t.UserProcessorTime}\n");
                            detailsBox.AppendText($"  Kernel Time:      {t.PrivilegedProcessorTime}\n");
                            detailsBox.AppendText($"  Total CPU Time:   {t.TotalProcessorTime}\n");

                            try { detailsBox.AppendText($"  Start Time:       {t.StartTime:yyyy-MM-dd HH:mm:ss.fff}\n"); } catch { }

                            detailsBox.SelectionColor = DarkTheme.TextSecondary;
                            detailsBox.AppendText($"\n  Priority Reference:\n");
                            detailsBox.SelectionColor = DarkTheme.TextMuted;
                            detailsBox.AppendText("    -2  = Idle (lowest)\n");
                            detailsBox.SelectionColor = Color.FromArgb(210, 153, 34);
                            detailsBox.AppendText("    -1  = Below Normal\n");
                            detailsBox.SelectionColor = DarkTheme.TextPrimary;
                            detailsBox.AppendText("     0  = Normal (default)\n");
                            detailsBox.SelectionColor = Color.FromArgb(88, 166, 255);
                            detailsBox.AppendText("    +1  = Above Normal\n");
                            detailsBox.SelectionColor = DarkTheme.Warning;
                            detailsBox.AppendText("    +2  = Highest\n");
                            detailsBox.SelectionColor = DarkTheme.Error;
                            detailsBox.AppendText("    +15 = Time Critical (highest)\n");
                            break;
                        }
                    }
                }
            }
            catch (Exception ex) { detailsBox.Text = $"Error: {ex.Message}"; }
        }

        private void SetPriority_Click(object sender, EventArgs e)
        {
            if (threadList.SelectedItems.Count == 0) return;

            int[] priorityValues = { -2, -1, -1, 0, 1, 1, 2 }; // Maps combo index to priority delta
            int selectedIndex = priorityCombo.SelectedIndex;
            int delta = priorityValues[selectedIndex];

            try
            {
                using (var proc = Process.GetProcessById(processId))
                {
                    int changed = 0;
                    foreach (ListViewItem item in threadList.SelectedItems)
                    {
                        int tid = (int)item.Tag;
                        foreach (ProcessThread t in proc.Threads)
                        {
                            if (t.Id == tid)
                            {
                                try
                                {
                                    t.PriorityLevel = (ThreadPriorityLevel)(t.BasePriority + delta);
                                    changed++;
                                }
                                catch { }
                                break;
                            }
                        }
                    }
                    Log("Changed priority for {0} threads to delta {1:+0;-0;0}", changed, delta);
                    RefreshThreads();
                }
            }
            catch (Exception ex) { Log("Error: {0}", ex.Message); }
        }

        private void Suspend_Click(object sender, EventArgs e)
        {
            if (threadList.SelectedItems.Count == 0) return;
            SuspendResumeThreads(true);
        }

        private void Resume_Click(object sender, EventArgs e)
        {
            if (threadList.SelectedItems.Count == 0) return;
            SuspendResumeThreads(false);
        }

        private void SuspendResumeThreads(bool suspend)
        {
            int affected = 0;
            foreach (ListViewItem item in threadList.SelectedItems)
            {
                int tid = (int)item.Tag;
                IntPtr hThread = OpenThread(0x0002, false, (uint)tid); // THREAD_SUSPEND_RESUME
                if (hThread != IntPtr.Zero)
                {
                    if (suspend)
                        SuspendThread(hThread);
                    else
                        ResumeThread(hThread);
                    CloseHandle(hThread);
                    affected++;
                }
            }
            Log("{0} {1} thread(s)", suspend ? "Suspended" : "Resumed", affected);
            System.Threading.Thread.Sleep(100);
            RefreshThreads();
        }

        private void Log(string message, params object[] args)
        {
            try { detailsBox.Invoke(new Action(() => detailsBox.AppendText($"\n[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        // ==================== P/Invoke ====================

        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenThread(uint a, bool i, uint t);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint SuspendThread(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern uint ResumeThread(IntPtr h);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
    }
}
