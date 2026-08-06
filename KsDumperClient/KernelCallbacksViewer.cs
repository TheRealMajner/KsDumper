using System;
using System.Drawing;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class KernelCallbacksViewer : Form
    {
        private readonly IMemoryReader driver;
        private ListView callbackList;
        private Button enumBtn;
        private Button removeBtn;
        private Label statsLbl;
        private RichTextBox logBox;

        public KernelCallbacksViewer(IMemoryReader driver)
        {
            this.driver = driver;
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = "Kernel Callbacks Viewer";
            Size = new Size(900, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 42, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 6, 8, 4) };

            enumBtn = CreateButton("Enumerate Callbacks", 150);
            enumBtn.Click += Enum_Click;
            toolbar.Controls.Add(enumBtn);

            removeBtn = CreateButton("Remove AC Callbacks", 160);
            removeBtn.Click += Remove_Click;
            removeBtn.Enabled = false;
            toolbar.Controls.Add(removeBtn);

            statsLbl = new Label { Text = "Click Enumerate to scan kernel callbacks", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.Add(statsLbl);

            callbackList = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont
            };
            callbackList.Columns.Add("Type", 100);
            callbackList.Columns.Add("Callback Address", 140);
            callbackList.Columns.Add("Driver Name", 200);
            callbackList.Columns.Add("Index", 60);
            callbackList.Columns.Add("Status", 80);

            logBox = new RichTextBox
            {
                Dock = DockStyle.Bottom,
                Height = 120,
                ReadOnly = true,
                BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIMonoFont,
                ScrollBars = RichTextBoxScrollBars.Vertical
            };

            Controls.Add(callbackList);
            Controls.Add(toolbar);
            Controls.Add(logBox);

            DarkTheme.ApplyTo(this);
        }

        private async void Enum_Click(object sender, EventArgs e)
        {
            enumBtn.Enabled = false;
            removeBtn.Enabled = false;
            callbackList.Items.Clear();
            statsLbl.Text = "Enumerating kernel callbacks...";

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var (callbackCount, removedCount, callbacks) = driver.EnumKernelCallbacks(false);

                    this.SafeInvoke(() =>
                    {
                        if (callbackCount > 0)
                        {
                            string[] typeNames = { "Process", "LoadImage", "Thread", "ObRegister" };
                            foreach (var cb in callbacks)
                            {
                                string typeName = cb.CallbackType < typeNames.Length ? typeNames[cb.CallbackType] : $"Unknown({cb.CallbackType})";
                                var item = new ListViewItem(typeName);
                                item.SubItems.Add($"0x{cb.CallbackAddress:X16}");
                                item.SubItems.Add(string.IsNullOrEmpty(cb.DriverName) ? "<unknown>" : cb.DriverName);
                                item.SubItems.Add(cb.Index.ToString());
                                item.SubItems.Add(cb.Removed == 1 ? "Removed" : "Active");
                                callbackList.Items.Add(item);
                            }
                            statsLbl.Text = $"Found {callbackCount} kernel callbacks";
                            removeBtn.Enabled = true;
                            Log("Enumerated {0} kernel callbacks", callbackCount);
                        }
                        else
                        {
                            statsLbl.Text = "No kernel callbacks found";
                            Log("No kernel callbacks found.");
                        }
                        enumBtn.Enabled = true;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        Log("Error: {0}", ex.Message);
                        statsLbl.Text = "Enumeration failed";
                        enumBtn.Enabled = true;
                    });
                }
            });
        }

        private async void Remove_Click(object sender, EventArgs e)
        {
            if (MessageBox.Show("Remove all anti-cheat kernel callbacks?\n\nThis will disable anti-cheat kernel callbacks system-wide until reboot.",
                "Confirm Removal", MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;

            enumBtn.Enabled = false;
            removeBtn.Enabled = false;
            statsLbl.Text = "Removing kernel callbacks...";

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    var (callbackCount, removedCount, _) = driver.EnumKernelCallbacks(true);

                    this.SafeInvoke(() =>
                    {
                        statsLbl.Text = $"Removed {removedCount} of {callbackCount} callbacks";
                        Log("Removed {0} of {1} kernel callbacks", removedCount, callbackCount);
                        enumBtn.Enabled = true;
                        removeBtn.Enabled = false;
                    });
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() =>
                    {
                        Log("Error: {0}", ex.Message);
                        statsLbl.Text = "Removal failed";
                        enumBtn.Enabled = true;
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
    }
}
