using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class KernelModuleViewer : Form
    {
        private readonly IMemoryReader driver;

        private ListView moduleList;
        private Button refreshBtn;
        private Button exportBtn;
        private Button filterBtn;
        private Label statsLbl;
        private TextBox filterBox;
        private List<ListViewItem> allModuleItems = new List<ListViewItem>();

        public KernelModuleViewer(IMemoryReader driver)
        {
            this.driver = driver;
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = "Kernel Module Viewer";
            Size = new Size(1100, 650);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 6, 8, 4) };

            refreshBtn = CreateButton("Enumerate Kernel Modules", 180);
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

            statsLbl = new Label { Text = "Click Enumerate to scan kernel modules", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.Add(statsLbl);

            moduleList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont
            };
            moduleList.Columns.Add("Base Address", 140);
            moduleList.Columns.Add("Size", 80);
            moduleList.Columns.Add("Name", 200);
            moduleList.Columns.Add("Full Path", 350);
            moduleList.Columns.Add("Flags", 80);

            Controls.Add(moduleList);
            Controls.Add(toolbar);

            DarkTheme.ApplyTo(this);
        }

        private async void Refresh_Click(object sender, EventArgs e)
        {
            refreshBtn.Enabled = false;
            exportBtn.Enabled = false;
            moduleList.Items.Clear();
            allModuleItems.Clear();
            statsLbl.Text = "Enumerating kernel modules...";

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var (moduleCount, modules) = driver.EnumKernelModules();

                    this.SafeInvoke(() =>
                    {
                        if (moduleCount > 0)
                        {
                            ulong totalSize = 0;
                            int unlinkedCount = 0;

                            foreach (var mod in modules)
                            {
                                var lvi = new ListViewItem($"0x{mod.BaseAddress:X}");
                                lvi.SubItems.Add(FormatSize(mod.ImageSize));
                                lvi.SubItems.Add(mod.BaseName ?? "");
                                lvi.SubItems.Add(mod.FullPath ?? "");
                                lvi.SubItems.Add(mod.Flags == 1 ? "UNLINKED" : "Normal");

                                totalSize += mod.ImageSize;
                                if (mod.Flags == 1)
                                {
                                    lvi.ForeColor = DarkTheme.Error;
                                    unlinkedCount++;
                                }
                                else if (mod.BaseName != null && (mod.BaseName.Contains("EasyAntiCheat") || mod.BaseName.Contains("BEDaisy") || mod.BaseName.Contains("BEKernel") || mod.BaseName.Contains("BEService")))
                                {
                                    lvi.ForeColor = DarkTheme.Warning;
                                }
                                else
                                {
                                    lvi.ForeColor = DarkTheme.TextPrimary;
                                }

                                allModuleItems.Add(lvi);
                                moduleList.Items.Add(lvi);
                            }

                            statsLbl.Text = $"Modules: {moduleCount} | Total: {FormatSize(totalSize)} | Unlinked: {unlinkedCount}";
                            exportBtn.Enabled = true;
                        }
                        else
                        {
                            statsLbl.Text = "No kernel modules found (requires kernel driver)";
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
            moduleList.BeginUpdate();
            moduleList.Items.Clear();

            foreach (ListViewItem lvi in allModuleItems)
            {
                if (string.IsNullOrEmpty(filter))
                {
                    moduleList.Items.Add(lvi);
                }
                else
                {
                    foreach (ListViewItem.ListViewSubItem sub in lvi.SubItems)
                    {
                        if (sub.Text.ToLower().Contains(filter))
                        {
                            moduleList.Items.Add(lvi);
                            break;
                        }
                    }
                }
            }
            moduleList.EndUpdate();
        }

        private void Export_Click(object sender, EventArgs e)
        {
            using (var sfd = new SaveFileDialog())
            {
                sfd.Filter = "CSV Files|*.csv|All Files|*.*";
                sfd.FileName = "kernel_modules.csv";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        using (var w = new System.IO.StreamWriter(sfd.FileName))
                        {
                            w.WriteLine("BaseAddress,Size,Name,FullPath,Flags");
                            foreach (ListViewItem lvi in moduleList.Items)
                            {
                                w.WriteLine($"{lvi.SubItems[0].Text},{lvi.SubItems[1].Text},{lvi.SubItems[2].Text},{lvi.SubItems[3].Text},{lvi.SubItems[4].Text}");
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

        private string FormatSize(ulong bytes)
        {
            if (bytes >= 1024 * 1024) return $"{bytes / (1024.0 * 1024):F1} MB";
            if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes} B";
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
