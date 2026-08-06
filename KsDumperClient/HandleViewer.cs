using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class HandleViewer : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView handleList;
        private Button refreshBtn;
        private Button exportBtn;
        private Button filterBtn;
        private Label statsLbl;
        private TextBox filterBox;
        private List<ListViewItem> allHandleItems = new List<ListViewItem>();

        public HandleViewer(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"System Handles - {processName} (PID: {processId})";
            Size = new Size(1100, 650);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 6, 8, 4) };

            refreshBtn = CreateButton("Enumerate Handles", 140);
            refreshBtn.Click += Refresh_Click;
            toolbar.Controls.Add(refreshBtn);

            exportBtn = CreateButton("Export CSV", 100);
            exportBtn.Click += Export_Click;
            exportBtn.Enabled = false;
            toolbar.Controls.Add(exportBtn);

            toolbar.Controls.Add(MakeLabel("Filter:"));
            filterBox = new TextBox { Width = 120, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.None };
            filterBox.TextChanged += (s, e) => FilterList();
            toolbar.Controls.Add(filterBox);

            statsLbl = new Label { Text = "Click Enumerate to scan system handles", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.Add(statsLbl);

            handleList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont
            };
            handleList.Columns.Add("Handle", 100);
            handleList.Columns.Add("Owner PID", 80);
            handleList.Columns.Add("Target PID", 80);
            handleList.Columns.Add("Access", 100);
            handleList.Columns.Add("Attributes", 80);
            handleList.Columns.Add("Object Type", 80);
            handleList.Columns.Add("Object Name", 250);

            Controls.Add(handleList);
            Controls.Add(toolbar);

            DarkTheme.ApplyTo(this);
        }

        private async void Refresh_Click(object sender, EventArgs e)
        {
            refreshBtn.Enabled = false;
            exportBtn.Enabled = false;
            handleList.Items.Clear();
            allHandleItems.Clear();
            statsLbl.Text = "Enumerating system handles...";

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var (handleCount, handles) = driver.EnumHandles(processId);

                    this.SafeInvoke(() =>
                    {
                        if (handleCount > 0)
                        {
                            int processHandleCount = 0;
                            foreach (var h in handles)
                            {
                                var lvi = new ListViewItem($"0x{h.HandleValue:X}");
                                lvi.SubItems.Add(h.ProcessId.ToString());
                                lvi.SubItems.Add(h.TargetProcessId.ToString());
                                lvi.SubItems.Add($"0x{h.GrantedAccess:X}");
                                lvi.SubItems.Add($"0x{h.HandleAttributes:X}");
                                lvi.SubItems.Add(h.ObjectTypeIndex.ToString());
                                lvi.SubItems.Add(h.ObjectName ?? "");

                                // Color-code process handles
                                if (h.ObjectTypeIndex == 7) // Process type
                                {
                                    lvi.ForeColor = DarkTheme.Warning;
                                    processHandleCount++;
                                }
                                else
                                {
                                    lvi.ForeColor = DarkTheme.TextPrimary;
                                }

                                allHandleItems.Add(lvi);
                                handleList.Items.Add(lvi);
                            }

                            statsLbl.Text = $"Handles: {handleCount} | Process-type: {processHandleCount}";
                            exportBtn.Enabled = true;
                        }
                        else
                        {
                            statsLbl.Text = $"No handles found for PID {processId} (handleCount=0)";
                        }
                        refreshBtn.Enabled = true;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        statsLbl.Text = $"Error: {ex.Message}";
                        refreshBtn.Enabled = true;
                    });
                }
            });
        }

        private void FilterList()
        {
            string filter = filterBox.Text.Trim().ToLower();
            handleList.BeginUpdate();
            handleList.Items.Clear();

            foreach (ListViewItem lvi in allHandleItems)
            {
                if (string.IsNullOrEmpty(filter))
                {
                    handleList.Items.Add(lvi);
                }
                else
                {
                    foreach (ListViewItem.ListViewSubItem sub in lvi.SubItems)
                    {
                        if (sub.Text.ToLower().Contains(filter))
                        {
                            handleList.Items.Add(lvi);
                            break;
                        }
                    }
                }
            }
            handleList.EndUpdate();
        }

        private void Export_Click(object sender, EventArgs e)
        {
            using (var sfd = new SaveFileDialog())
            {
                sfd.Filter = "CSV Files|*.csv|All Files|*.*";
                sfd.FileName = $"{processName}_handles.csv";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        using (var w = new System.IO.StreamWriter(sfd.FileName))
                        {
                            w.WriteLine("Handle,OwnerPID,TargetPID,Access,Attributes,ObjectType,ObjectName");
                            foreach (ListViewItem lvi in handleList.Items)
                            {
                                w.WriteLine($"{lvi.SubItems[0].Text},{lvi.SubItems[1].Text},{lvi.SubItems[2].Text},{lvi.SubItems[3].Text},{lvi.SubItems[4].Text},{lvi.SubItems[5].Text},{lvi.SubItems[6].Text}");
                            }
                        }
                        MessageBox.Show("Exported successfully", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
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
