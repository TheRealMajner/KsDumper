using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class HandleViewerWindow : Form
    {
        private readonly int processId;
        private readonly string processName;
        private ListView handleList;
        private ComboBox typeFilter;
        private TextBox nameFilter;
        private Label statusLbl;
        private List<HandleEnumerator.HandleInfo> allHandles;

        public HandleViewerWindow(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            allHandles = new List<HandleEnumerator.HandleInfo>();
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = $"Handles - {processName} (PID: {processId})";
            Size = new Size(950, 650);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            var refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += Refresh_Click;
            toolbar.Controls.Add(MakeLabel("Type:"));
            typeFilter = new DarkComboBox { Width = 120 };
            typeFilter.Items.AddRange(new object[] { "All", "File", "Mutant", "Event", "Section", "Key", "Thread", "Process", "Semaphore", "Token", "Desktop", "ALPC Port", "WindowStation", "Job" });
            typeFilter.SelectedIndex = 0;
            typeFilter.SelectedIndexChanged += (s, e) => ApplyFilter();
            toolbar.Controls.Add(typeFilter);
            toolbar.Controls.Add(MakeLabel("Name:"));
            nameFilter = new TextBox { Width = 200, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.FixedSingle, Font = DarkTheme.UIFont };
            nameFilter.TextChanged += (s, e) => ApplyFilter();
            toolbar.Controls.Add(nameFilter);
            var closeHandleBtn = CreateButton("Close Handle", 100);
            closeHandleBtn.Click += CloseHandle_Click;
            toolbar.Controls.Add(closeHandleBtn);
            toolbar.Controls.Add(refreshBtn);

            statusLbl = new Label { Text = "Ready", AutoSize = true, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont, Margin = new Padding(16, 6, 0, 0) };
            toolbar.Controls.Add(statusLbl);

            handleList = CreateListView();
            handleList.Columns.Add("Handle", 70);
            handleList.Columns.Add("Type", 120);
            handleList.Columns.Add("Name / Path", 500);
            handleList.Columns.Add("Access", 100);

            Controls.Add(handleList);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private async void Refresh_Click(object sender, EventArgs e)
        {
            statusLbl.Text = "Enumerating handles...";
            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    allHandles = HandleEnumerator.EnumerateHandles(processId);
                    this.SafeInvoke(() =>
                    {
                        ApplyFilter();
                        statusLbl.Text = $"{allHandles.Count} handles found";
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() => statusLbl.Text = $"Error: {ex.Message}");
                }
            });
        }

        private void ApplyFilter()
        {
            handleList.Items.Clear();
            string type = typeFilter.SelectedItem?.ToString() ?? "All";
            string name = nameFilter.Text.ToLowerInvariant();

            var typeMap = new Dictionary<string, string[]>
            {
                { "File", new[] { "File" } },
                { "Mutant", new[] { "Mutant" } },
                { "Event", new[] { "Event", "KeyedEvent" } },
                { "Section", new[] { "Section" } },
                { "Key", new[] { "Key" } },
                { "Thread", new[] { "Thread" } },
                { "Process", new[] { "Process" } },
                { "Semaphore", new[] { "Semaphore" } },
                { "Token", new[] { "Token" } },
                { "Desktop", new[] { "Desktop" } },
                { "ALPC Port", new[] { "ALPC Port" } },
                { "WindowStation", new[] { "WindowStation" } },
                { "Job", new[] { "Job" } }
            };

            foreach (var h in allHandles)
            {
                if (type != "All" && typeMap.ContainsKey(type))
                {
                    if (!typeMap[type].Any(t => h.TypeName.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0)) continue;
                }
                if (!string.IsNullOrEmpty(name) && !h.ObjectName.ToLowerInvariant().Contains(name)) continue;

                var lvi = new ListViewItem($"0x{h.Handle:X4}");
                lvi.SubItems.Add(h.TypeName);
                lvi.SubItems.Add(h.ObjectName);
                lvi.SubItems.Add($"0x{h.GrantedAccess:X8}");

                if (h.TypeName.Contains("File")) lvi.ForeColor = DarkTheme.Accent;
                else if (h.TypeName.Contains("Mutant")) lvi.ForeColor = DarkTheme.Warning;
                else if (h.TypeName.Contains("Key")) lvi.ForeColor = DarkTheme.Success;

                handleList.Items.Add(lvi);
            }
        }

        private void CloseHandle_Click(object sender, EventArgs e)
        {
            if (handleList.SelectedItems.Count == 0) return;
            var confirm = MessageBox.Show($"Close {handleList.SelectedItems.Count} handle(s)?", "Close Handle", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            foreach (ListViewItem item in handleList.SelectedItems)
            {
                try
                {
                    ushort handleVal = ushort.Parse(item.Text.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture);
                    IntPtr hProc = OpenProcess(0x0040, false, processId); // PROCESS_DUP_HANDLE
                    if (hProc != IntPtr.Zero)
                    {
                        DuplicateHandle(hProc, (IntPtr)handleVal, IntPtr.Zero, out _, 0, false, 0x00000001); // DUPLICATE_CLOSE_SOURCE
                        CloseHandle(hProc);
                    }
                }
                catch { }
            }
            Refresh_Click(sender, e);
        }

        // ==================== Helpers ====================

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(IntPtr hSourceProcess, IntPtr hSourceHandle, IntPtr hTargetProcess, out IntPtr hTarget, uint access, bool inherit, uint options);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private Label MakeLabel(string text) => new Label { Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };

        private ListView CreateListView()
        {
            var lv = new ListView { View = View.Details, FullRowSelect = true, MultiSelect = true, BorderStyle = BorderStyle.None, Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont };
            lv.Resize += (s, e) => { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; };
            lv.HandleCreated += (s, e) => { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; };
            return lv;
        }
    }
}
