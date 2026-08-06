using System.Drawing;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class UnityStatusWindow : Form
    {
        private readonly RichTextBox logBox;

        public UnityStatusWindow()
        {
            Text = "Unity Module Status";
            Size = new Size(700, 500);
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.SizableToolWindow;
            ShowInTaskbar = false;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            Padding = Padding.Empty;
            try { this.Icon = Utility.AppIcon.Get(); } catch { }

            logBox = new RichTextBox
            {
                Dock = DockStyle.Fill,
                ReadOnly = true,
                BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIMonoFont,
                WordWrap = false
            };
            Controls.Add(logBox);

            DarkTheme.ApplyTo(this);
        }

        public void AppendSection(string moduleName, string filePath, UnityReference uref)
        {
            if (InvokeRequired) { this.SafeInvoke(new System.Action(() => AppendSection(moduleName, filePath, uref))); return; }

            AppendLine($"=== {moduleName} ===", Color.FromArgb(63, 185, 80));
            AppendLine($"  Path: {filePath}", DarkTheme.TextMuted);
            AppendLine($"  ImageSize: 0x{uref.ImageSize:X}  EntryPoint: 0x{uref.EntryPointRva:X}", DarkTheme.TextMuted);
            AppendLine("", DarkTheme.TextMuted);

            AppendLine("  Sections:", Color.FromArgb(180, 180, 255));
            foreach (var sec in uref.Sections)
            {
                string chars = "";
                if ((sec.Characteristics & 0x20000000) != 0) chars += "E";
                if ((sec.Characteristics & 0x40000000) != 0) chars += "R";
                if ((sec.Characteristics & 0x80000000u) != 0) chars += "W";
                AppendLine($"    {sec.Name,-10} RVA: 0x{sec.VirtualAddress:X8}  VSize: 0x{sec.VirtualSize:X8}  RawSize: 0x{sec.RawSize:X8}  [{chars}]", Color.FromArgb(200, 200, 200));
            }
            AppendLine("", DarkTheme.TextMuted);

            if (uref.Exports.Length > 0)
            {
                AppendLine($"  Exports: ({uref.Exports.Length})", Color.FromArgb(180, 180, 255));
                int shown = 0;
                foreach (var exp in uref.Exports)
                {
                    if (shown < 30)
                    {
                        AppendLine($"    0x{exp.Rva:X8}  {exp.Name}", Color.FromArgb(180, 180, 180));
                        shown++;
                    }
                }
                if (uref.Exports.Length > 30)
                    AppendLine($"    ... and {uref.Exports.Length - 30} more", DarkTheme.TextMuted);
                AppendLine("", DarkTheme.TextMuted);
            }
        }

        public void AppendComparison(UnityReference.SectionComparison cmp)
        {
            if (InvokeRequired) { this.SafeInvoke(new System.Action(() => AppendComparison(cmp))); return; }

            Color statusColor = cmp.IsDecrypted
                ? Color.FromArgb(255, 180, 50)
                : Color.FromArgb(63, 185, 80);
            string status = cmp.IsDecrypted
                ? $"DECRYPTED ({cmp.DifferentBytes} bytes differ, {cmp.DiffPercent:F1}%)"
                : "IDENTICAL";

            AppendLine($"  [{cmp.Name}] {status}", statusColor);
        }

        public void AppendComparisonHeader(string moduleName)
        {
            if (InvokeRequired) { this.SafeInvoke(new System.Action(() => AppendComparisonHeader(moduleName))); return; }

            AppendLine($"--- {moduleName} Section Comparison ---", Color.FromArgb(255, 220, 100));
        }

        public void AppendLine(string text, Color color)
        {
            if (InvokeRequired) { this.SafeInvoke(new System.Action(() => AppendLine(text, color))); return; }

            logBox.SelectionStart = logBox.TextLength;
            logBox.SelectionColor = color;
            logBox.AppendText(text + "\n");
            logBox.ScrollToCaret();
        }

        public void AppendExportMap(string moduleName, System.Collections.Generic.List<(string name, ulong address)> exports)
        {
            if (InvokeRequired) { this.SafeInvoke(new System.Action(() => AppendExportMap(moduleName, exports))); return; }

            AppendLine($"--- {moduleName} Export Address Map ---", Color.FromArgb(255, 220, 100));
            foreach (var (name, address) in exports)
            {
                AppendLine($"  0x{address:X16}  {name}", Color.FromArgb(200, 200, 200));
            }
            AppendLine("", DarkTheme.TextMuted);
        }
    }
}
