using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class DriverListView : Form
    {
        private readonly IMemoryReader driver;
        private ListView driverList;
        private RichTextBox detailBox;
        private Label countLbl;
        private TextBox filterBox;

        private List<(string basePath, string baseName, ulong baseAddress, uint imageSize, uint flags, DateTime loadTime, ulong entryPoint, uint checkSum)> allDrivers;

        public DriverListView(IMemoryReader driver)
        {
            this.driver = driver;
            InitializeComponent();
            LoadDrivers();
        }

        private void InitializeComponent()
        {
            Text = "Loaded Kernel Drivers (.sys)";
            Size = new Size(1200, 700);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(900, 500);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            Padding = Padding.Empty;
            try { Icon = AppIcon.Get(); } catch { }

            // Top toolbar
            var toolBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 42, BackColor = DarkTheme.Surface,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(8, 6, 8, 6)
            };

            var refreshBtn = new Button { Text = "Refresh", Size = new Size(80, 28), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(refreshBtn);
            refreshBtn.Click += (s, e) => LoadDrivers();
            toolBar.Controls.Add(refreshBtn);

            var dumpBtn = new Button { Text = "Dump Selected", Size = new Size(110, 28), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(dumpBtn);
            dumpBtn.Click += DumpSelected_Click;
            toolBar.Controls.Add(dumpBtn);

            var exportBtn = new Button { Text = "Export List", Size = new Size(90, 28), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(exportBtn);
            exportBtn.Click += ExportList_Click;
            toolBar.Controls.Add(exportBtn);

            toolBar.Controls.Add(new Label { Text = "Filter:", AutoSize = true, Margin = new Padding(12, 5, 4, 0), ForeColor = DarkTheme.TextSecondary });
            filterBox = new TextBox { Width = 200, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.FixedSingle };
            filterBox.TextChanged += FilterChanged;
            toolBar.Controls.Add(filterBox);

            countLbl = new Label { Text = "0 drivers", AutoSize = true, Margin = new Padding(12, 5, 0, 0), ForeColor = DarkTheme.TextSecondary };
            toolBar.Controls.Add(countLbl);

            // Main split: list top, detail bottom
            var split = new SplitContainer
            {
                Dock = DockStyle.Fill, Orientation = Orientation.Horizontal,
                BackColor = DarkTheme.Border, SplitterWidth = 3,
                Panel1MinSize = 200, Panel2MinSize = 100
            };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Surface;

            driverList = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
                MultiSelect = true, BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont
            };
            driverList.Columns.Add("#", 40);
            driverList.Columns.Add("Driver Name", 180);
            driverList.Columns.Add("Base Address", 140);
            driverList.Columns.Add("Size", 80);
            driverList.Columns.Add("Entry Point", 140);
            driverList.Columns.Add("Checksum", 90);
            driverList.Columns.Add("Load Time", 160);
            driverList.Columns.Add("Full Path", 300);
            driverList.SelectedIndexChanged += DriverSelected;

            detailBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both,
                WordWrap = false
            };

            split.Panel1.Controls.Add(driverList);
            split.Panel2.Controls.Add(detailBox);

            Controls.Add(split);
            Controls.Add(toolBar);

            DarkTheme.ApplyTo(this);

            // Auto-expand last column to fill available width
            void ExpandLastCol()
            {
                if (driverList.Columns.Count > 0)
                    driverList.Columns[driverList.Columns.Count - 1].Width = -2;
            }
            driverList.Resize += (s, e) => ExpandLastCol();

            Load += (s, e) =>
            {
                try { split.SplitterDistance = (int)(split.Height * 0.6); } catch { }
                ExpandLastCol();
            };
        }

        private void LoadDrivers()
        {
            if (!driver.IsKernelMode)
            {
                countLbl.Text = "Requires kernel driver";
                countLbl.ForeColor = DarkTheme.Error;
                return;
            }

            countLbl.Text = "Loading...";
            countLbl.ForeColor = DarkTheme.TextSecondary;

            Task.Run(() =>
            {
                try
                {
                    allDrivers = driver.EnumerateDrivers();
                    this.SafeInvoke(() => PopulateList(allDrivers));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        countLbl.Text = $"Error: {ex.Message}";
                        countLbl.ForeColor = DarkTheme.Error;
                    });
                }
            });
        }

        private void PopulateList(List<(string basePath, string baseName, ulong baseAddress, uint imageSize, uint flags, DateTime loadTime, ulong entryPoint, uint checkSum)> drivers)
        {
            driverList.BeginUpdate();
            try
            {
                driverList.Items.Clear();
                foreach (var drv in drivers)
                {
                    string name = string.IsNullOrEmpty(drv.baseName) ? "(unknown)" : drv.baseName;
                    string sizeStr = drv.imageSize > 0 ? FormatSize(drv.imageSize) : "-";
                    string loadTimeStr = drv.loadTime != DateTime.MinValue ? drv.loadTime.ToString("yyyy-MM-dd HH:mm:ss") : "-";
                    string entryStr = drv.entryPoint > 0 ? $"0x{drv.entryPoint:X}" : "-";
                    string checksumStr = drv.checkSum > 0 ? $"0x{drv.checkSum:X8}" : "-";

                    var lvi = new ListViewItem(drv.flags.ToString());
                    lvi.SubItems.Add(name);
                    lvi.SubItems.Add($"0x{drv.baseAddress:X12}");
                    lvi.SubItems.Add(sizeStr);
                    lvi.SubItems.Add(entryStr);
                    lvi.SubItems.Add(checksumStr);
                    lvi.SubItems.Add(loadTimeStr);
                    lvi.SubItems.Add(drv.basePath ?? "-");
                    lvi.Tag = drv;

                    driverList.Items.Add(lvi);
                }
            }
            finally { driverList.EndUpdate(); }

            countLbl.Text = $"{drivers.Count} drivers loaded";
            countLbl.ForeColor = DarkTheme.Success;
        }

        private void FilterChanged(object sender, EventArgs e)
        {
            if (allDrivers == null) return;
            string filter = filterBox.Text.ToLowerInvariant();

            if (string.IsNullOrEmpty(filter))
            {
                PopulateList(allDrivers);
                return;
            }

            var filtered = allDrivers.Where(d =>
                (d.baseName ?? "").ToLowerInvariant().Contains(filter) ||
                (d.basePath ?? "").ToLowerInvariant().Contains(filter)
            ).ToList();

            PopulateList(filtered);
        }

        private void DriverSelected(object sender, EventArgs e)
        {
            if (driverList.SelectedItems.Count == 0) { detailBox.Clear(); return; }

            var drv = ((dynamic)driverList.SelectedItems[0].Tag);
            var sb = new StringBuilder();

            sb.AppendLine($"Driver: {drv.baseName}");
            sb.AppendLine($"Path:   {drv.basePath}");
            sb.AppendLine();
            sb.AppendLine($"Base Address:  0x{drv.baseAddress:X16}");
            sb.AppendLine($"Image Size:    0x{drv.imageSize:X8} ({FormatSize(drv.imageSize)})");
            sb.AppendLine($"Entry Point:   0x{drv.entryPoint:X}");
            sb.AppendLine($"Checksum:      0x{drv.checkSum:X8}");
            sb.AppendLine($"Load Order:    {drv.flags}");
            sb.AppendLine($"Load Time:     {(drv.loadTime != DateTime.MinValue ? drv.loadTime.ToString("yyyy-MM-dd HH:mm:ss.fff") : "Unknown")}");
            sb.AppendLine();

            // Show flags interpretation
            uint flags = drv.flags;
            sb.AppendLine("Flags:");
            if (flags == 0) sb.AppendLine("  Normal driver");
            if ((flags & 1) != 0) sb.AppendLine("  No digital signature");
            if ((flags & 2) != 0) sb.AppendLine("  Manually mapped (not loaded by OS loader)");
            if ((flags & 4) != 0) sb.AppendLine("  PatchGuard disabled");

            detailBox.Text = sb.ToString();
        }

        private async void DumpSelected_Click(object sender, EventArgs e)
        {
            if (driverList.SelectedItems.Count == 0) return;

            string outputDir = null;
            using (var fbd = new FolderBrowserDialog())
            {
                fbd.Description = "Select output folder for driver dumps";
                if (fbd.ShowDialog() == DialogResult.OK)
                    outputDir = fbd.SelectedPath;
            }
            if (string.IsNullOrEmpty(outputDir)) return;

            countLbl.Text = "Dumping drivers...";

            await Task.Run(() =>
            {
                int dumped = 0;
                foreach (ListViewItem item in driverList.SelectedItems)
                {
                    var drv = ((dynamic)item.Tag);
                    try
                    {
                        ulong baseAddr = drv.baseAddress;
                        uint imgSize = drv.imageSize;
                        if (imgSize == 0) continue;

                        // Read the entire driver image from kernel memory
                        IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)(int)imgSize, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                        if (buf == IntPtr.Zero) continue;
                        try
                        {
                            bool ok = driver.CopyVirtualMemory(4, (IntPtr)baseAddr, buf, (int)imgSize); // PID 4 = System

                            if (ok)
                            {
                                byte[] data = new byte[imgSize];
                                System.Runtime.InteropServices.Marshal.Copy(buf, data, 0, (int)imgSize);

                                string name = string.IsNullOrEmpty(drv.baseName) ? $"driver_0x{baseAddr:X}" : drv.baseName;
                                if (!name.EndsWith(".sys", StringComparison.OrdinalIgnoreCase)) name += ".sys";
                                string outPath = Path.Combine(outputDir, name);

                                // Apply PE fix
                                var report = PE.PEFixer.FixAndSave(data, baseAddr, outPath);
                                if (report.Success) dumped++;
                            }
                        }
                        finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
                    }
                    catch { }
                }

                int d = dumped;
                this.SafeInvoke(() =>
                {
                    countLbl.Text = $"Dumped {d} drivers to {outputDir}";
                    countLbl.ForeColor = DarkTheme.Success;
                });
            });
        }

        private void ExportList_Click(object sender, EventArgs e)
        {
            if (allDrivers == null || allDrivers.Count == 0) return;

            using (var sfd = new SaveFileDialog())
            {
                sfd.FileName = "loaded_drivers.txt";
                sfd.Filter = "Text Files|*.txt|CSV Files|*.csv|All Files|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    bool csv = sfd.FileName.EndsWith(".csv", StringComparison.OrdinalIgnoreCase);
                    string sep = csv ? "," : "  ";

                    using (var w = new StreamWriter(sfd.FileName, false, Encoding.UTF8))
                    {
                        w.WriteLine(csv ? "#,Name,BaseAddress,Size,EntryPoint,Checksum,LoadTime,Path" :
                            "// KsDumper - Loaded Kernel Drivers");
                        if (!csv) w.WriteLine($"// Date: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                        if (!csv) w.WriteLine($"// Count: {allDrivers.Count}");
                        if (!csv) w.WriteLine();
                        if (!csv) w.WriteLine("#    Name                 Base Address       Size       EntryPoint       Checksum   Load Time              Path");
                        if (!csv) w.WriteLine(new string('-', 120));

                        int idx = 0;
                        foreach (var drv in allDrivers)
                        {
                            string name = string.IsNullOrEmpty(drv.baseName) ? "(unknown)" : drv.baseName;
                            string loadTimeStr = drv.loadTime != DateTime.MinValue ? drv.loadTime.ToString("yyyy-MM-dd HH:mm:ss") : "-";

                            if (csv)
                                w.WriteLine($"{idx},{name},0x{drv.baseAddress:X},{drv.imageSize},0x{drv.entryPoint:X},0x{drv.checkSum:X8},{loadTimeStr},{drv.basePath}");
                            else
                                w.WriteLine($"{idx,-4} {name,-20} 0x{drv.baseAddress:X16} 0x{drv.imageSize:X8} 0x{drv.entryPoint:X14} 0x{drv.checkSum:X8} {loadTimeStr,-20} {drv.basePath}");
                            idx++;
                        }
                    }

                    countLbl.Text = $"Exported to {sfd.FileName}";
                }
            }
        }

        private static string FormatSize(uint bytes)
        {
            if (bytes >= 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F1} MB";
            if (bytes >= 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes} B";
        }
    }
}
