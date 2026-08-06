using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Memory Signature Scanner - scans process memory for known malware/tool signatures
    /// using byte patterns with wildcards. Includes built-in signature database for
    /// common game hacks, anti-cheat bypasses, and injection tools.
    /// </summary>
    public class MemorySignatureScanner : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private TextBox patternBox;
        private TextBox nameBox;
        private Button scanBtn;
        private Button addSignatureBtn;
        private Button scanAllBtn;
        private Button clearBtn;
        private ListView sigList;
        private ListView resultList;
        private RichTextBox logBox;
        private Label statsLbl;

        private struct Signature
        {
            public string Name;
            public string Pattern; // "48 89 5C 24 ?? 48 89 74 24"
            public string Category;
            public string Description;
            public byte[] Bytes;
            public byte[] Mask; // 0xFF = match, 0x00 = wildcard
        }

        private struct ScanResult
        {
            public ulong Address;
            public string SignatureName;
            public string Category;
            public byte[] MatchedBytes;
        }

        private readonly List<Signature> signatures;

        // No built-in signatures — users create their own since patterns vary per game/version
        private static readonly Signature[] BuiltInSignatures = new Signature[0];

        public MemorySignatureScanner(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            signatures = new List<Signature>(BuiltInSignatures);
            InitializeComponent();
            LoadSignatureList();
        }

        private void InitializeComponent()
        {
            Text = $"Memory Signature Scanner - {processName} (PID: {processId})";
            Size = new Size(1000, 700);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Top toolbar
            var toolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(8) };

            var row1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row1.Controls.Add(MakeLabel("Pattern:"));
            patternBox = CreateTextBox(300);
            patternBox.Font = DarkTheme.UIMonoFont;
            patternBox.Text = "48 89 5C 24 ?? 48 89 74 24";
            patternBox.ForeColor = DarkTheme.TextMuted;
            row1.Controls.Add(patternBox);
            row1.Controls.Add(MakeLabel("Name:"));
            nameBox = CreateTextBox(150);
            row1.Controls.Add(nameBox);
            addSignatureBtn = CreateButton("Add Sig", 70);
            addSignatureBtn.Click += AddSignature_Click;
            row1.Controls.Add(addSignatureBtn);

            var row2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            scanBtn = CreateButton("Scan Pattern", 90);
            scanBtn.Click += ScanPattern_Click;
            scanAllBtn = CreateButton("Scan All Signatures", 140);
            scanAllBtn.Click += ScanAll_Click;
            clearBtn = CreateButton("Clear Results", 100);
            clearBtn.Click += (s, e) => { resultList.Items.Clear(); statsLbl.Text = "Results: 0"; };
            statsLbl = new Label { Text = $"Signatures: {signatures.Count} | Results: 0", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };

            row2.Controls.AddRange(new Control[] { scanBtn, scanAllBtn, clearBtn, statsLbl });

            toolbar.Controls.Add(row2);
            toolbar.Controls.Add(row1);

            // Split: signatures + results
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 350 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            // Signature list (left)
            var sigPanel = new Panel { Dock = DockStyle.Fill };
            var sigLabel = new Label { Text = "  Signature Database", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            sigList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            sigList.Columns.Add("Name", 150);
            sigList.Columns.Add("Category", 80);
            sigList.Columns.Add("Pattern", 300);
            sigList.DoubleClick += (s, e) =>
            {
                if (sigList.SelectedItems.Count > 0)
                {
                    patternBox.Text = sigList.SelectedItems[0].SubItems[2].Text;
                    nameBox.Text = sigList.SelectedItems[0].Text;
                }
            };
            sigPanel.Controls.Add(sigList);
            sigPanel.Controls.Add(sigLabel);
            split.Panel1.Controls.Add(sigPanel);

            // Results (right)
            var resPanel = new Panel { Dock = DockStyle.Fill };
            var resLabel = new Label { Text = "  Scan Results", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            resultList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            resultList.Columns.Add("Address", 130);
            resultList.Columns.Add("Signature", 150);
            resultList.Columns.Add("Category", 80);
            resultList.Columns.Add("Bytes", 250);
            resultList.Resize += (s, e) => { if (resultList.Columns.Count > 0) resultList.Columns[resultList.Columns.Count - 1].Width = -2; };
            resPanel.Controls.Add(resultList);
            resPanel.Controls.Add(resLabel);
            split.Panel2.Controls.Add(resPanel);

            // Log
            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 100, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(split);
            Controls.Add(logPanel);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void LoadSignatureList()
        {
            foreach (var sig in signatures)
            {
                var lvi = new ListViewItem(sig.Name);
                lvi.SubItems.Add(sig.Category);
                lvi.SubItems.Add(sig.Pattern);
                lvi.ForeColor = GetCategoryColor(sig.Category);
                sigList.Items.Add(lvi);
            }
        }

        private void AddSignature_Click(object sender, EventArgs e)
        {
            string pattern = patternBox.Text.Trim();
            string name = nameBox.Text.Trim();
            if (string.IsNullOrEmpty(pattern) || string.IsNullOrEmpty(name))
            {
                Log("Enter both a pattern and name");
                return;
            }

            var sig = ParseSignature(name, pattern, "Custom", "User-defined signature");
            if (sig.Bytes == null) { Log("Invalid pattern format"); return; }

            signatures.Add(sig);
            var lvi = new ListViewItem(sig.Name);
            lvi.SubItems.Add(sig.Category);
            lvi.SubItems.Add(sig.Pattern);
            lvi.ForeColor = GetCategoryColor(sig.Category);
            sigList.Items.Add(lvi);
            statsLbl.Text = $"Signatures: {signatures.Count} | Results: {resultList.Items.Count}";
            Log("Added signature: {0}", name);
        }

        private async void ScanPattern_Click(object sender, EventArgs e)
        {
            string pattern = patternBox.Text.Trim();
            if (string.IsNullOrEmpty(pattern)) { Log("Enter a pattern"); return; }

            var sig = ParseSignature(nameBox.Text.Trim().Length > 0 ? nameBox.Text.Trim() : "Custom", pattern, "Custom", "");
            if (sig.Bytes == null) { Log("Invalid pattern format"); return; }

            scanBtn.Enabled = false;
            await Task.Run(() => ScanForSignature(sig));
            scanBtn.Enabled = true;
        }

        private async void ScanAll_Click(object sender, EventArgs e)
        {
            scanAllBtn.Enabled = false;
            logBox.Clear();
            Log("Scanning all {0} signatures...", signatures.Count);

            int totalHits = 0;
            foreach (var sig in signatures)
            {
                var results = await Task.Run(() => ScanForSignatureInternal(sig));
                totalHits += results.Count;
            }

            statsLbl.Text = $"Signatures: {signatures.Count} | Results: {totalHits}";
            Log("Full scan complete: {0} hits across {1} signatures", totalHits, signatures.Count);
            scanAllBtn.Enabled = true;
        }

        private void ScanForSignature(Signature sig)
        {
            var results = ScanForSignatureInternal(sig);
            this.SafeInvoke(() =>
            {
                statsLbl.Text = $"Signatures: {signatures.Count} | Results: {resultList.Items.Count}";
                Log("Scan '{0}': {1} hits", sig.Name, results.Count);
            });
        }

        private List<ScanResult> ScanForSignatureInternal(Signature sig)
        {
            var results = new List<ScanResult>();
            try
            {
                var matches = driver.FindPattern(processId, sig.Bytes, 0xCC, 1000);
                foreach (ulong addr in matches)
                {
                    // Verify with mask
                    byte[] memBytes = new byte[sig.Bytes.Length];
                    IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)sig.Bytes.Length, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) continue;
                    try
                    {
                        if (driver.CopyVirtualMemory(processId, (IntPtr)addr, buf, sig.Bytes.Length))
                        {
                            Marshal.Copy(buf, memBytes, 0, sig.Bytes.Length);
                            bool match = true;
                            for (int i = 0; i < sig.Bytes.Length; i++)
                            {
                                if (sig.Mask[i] == 0xFF && memBytes[i] != sig.Bytes[i]) { match = false; break; }
                            }
                            if (match)
                            {
                                var result = new ScanResult { Address = addr, SignatureName = sig.Name, Category = sig.Category, MatchedBytes = memBytes };
                                results.Add(result);

                                try
                                {
                                    this.SafeInvoke(() =>
                                    {
                                        var lvi = new ListViewItem($"0x{addr:X}");
                                        lvi.SubItems.Add(sig.Name);
                                        lvi.SubItems.Add(sig.Category);
                                        lvi.SubItems.Add(BitConverter.ToString(memBytes).Replace("-", " "));
                                        lvi.ForeColor = GetCategoryColor(sig.Category);
                                        resultList.Items.Add(lvi);
                                    });
                                }
                                catch { }
                            }
                        }
                    }
                    finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
                }
            }
            catch (Exception ex)
            {
                try { Invoke(new Action(() => Log("Scan error for '{0}': {1}", sig.Name, ex.Message))); } catch { }
            }
            return results;
        }

        private Signature ParseSignature(string name, string pattern, string category, string description)
        {
            try
            {
                string[] parts = pattern.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                byte[] bytes = new byte[parts.Length];
                byte[] mask = new byte[parts.Length];

                for (int i = 0; i < parts.Length; i++)
                {
                    if (parts[i] == "??" || parts[i] == "?")
                    {
                        bytes[i] = 0xCC;
                        mask[i] = 0x00;
                    }
                    else
                    {
                        bytes[i] = Convert.ToByte(parts[i], 16);
                        mask[i] = 0xFF;
                    }
                }

                return new Signature { Name = name, Pattern = pattern, Category = category, Description = description, Bytes = bytes, Mask = mask };
            }
            catch { return new Signature { Name = name, Pattern = pattern }; }
        }

        private Color GetCategoryColor(string category)
        {
            switch (category)
            {
                case "Anti-Cheat": return Color.FromArgb(248, 81, 73);
                case "SpeedHack": return Color.FromArgb(210, 153, 34);
                case "ESP": return Color.FromArgb(180, 140, 255);
                case "Aimbot": return Color.FromArgb(255, 100, 100);
                case "Injection": return Color.FromArgb(88, 166, 255);
                case "Hook": return Color.FromArgb(63, 185, 80);
                case "Crypto": return Color.FromArgb(255, 165, 0);
                case "Process": return DarkTheme.TextPrimary;
                default: return DarkTheme.TextSecondary;
            }
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        private TextBox CreateTextBox(int w) => new TextBox { Width = w, Margin = new Padding(2, 0, 4, 0), BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.FixedSingle, Font = DarkTheme.UIFont };
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }

    // Extension for placeholder text on TextBox
    public static class TextBoxExtensions
    {
        [DllImport("user32.dll", CharSet = CharSet.Unicode)]
        private static extern IntPtr SendMessage(IntPtr hWnd, uint msg, IntPtr wParam, string lParam);

        public static void PlaceholderText(this TextBox textBox, string text)
        {
            SendMessage(textBox.Handle, 0x1501, IntPtr.Zero, text);
        }
    }
}
