using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace KsDumperClient.Utility
{
    public static class DarkTheme
    {
        // GitHub Dark inspired palette
        public static readonly Color Background = Color.FromArgb(13, 17, 23);
        public static readonly Color Surface = Color.FromArgb(22, 27, 34);
        public static readonly Color SurfaceElevated = Color.FromArgb(28, 33, 40);
        public static readonly Color SurfaceHover = Color.FromArgb(48, 54, 61);
        public static readonly Color Border = Color.FromArgb(48, 54, 61);
        public static readonly Color BorderSubtle = Color.FromArgb(33, 38, 45);
        public static readonly Color TextPrimary = Color.FromArgb(230, 237, 243);
        public static readonly Color TextSecondary = Color.FromArgb(139, 148, 158);
        public static readonly Color TextMuted = Color.FromArgb(110, 118, 129);
        public static readonly Color Accent = Color.FromArgb(88, 166, 255);
        public static readonly Color AccentHover = Color.FromArgb(121, 192, 255);
        public static readonly Color AccentSubtle = Color.FromArgb(31, 111, 235);
        public static readonly Color Selection = Color.FromArgb(56, 139, 253, 40);
        public static readonly Color SelectionBorder = Color.FromArgb(56, 139, 253);
        public static readonly Color Success = Color.FromArgb(63, 185, 80);
        public static readonly Color Warning = Color.FromArgb(210, 153, 34);
        public static readonly Color Error = Color.FromArgb(248, 81, 73);
        public static readonly Color HiddenModule = Color.FromArgb(248, 81, 73);
        public static readonly Color PackedModule = Color.FromArgb(210, 153, 34);
        public static readonly Color NoPathModule = Color.FromArgb(210, 153, 34);

        // Luxury palette - gradients, glows, pressed states
        public static readonly Color GradientTop = Color.FromArgb(34, 39, 46);
        public static readonly Color GradientBottom = Color.FromArgb(22, 27, 34);
        public static readonly Color GlowAccent = Color.FromArgb(40, 88, 166, 255);
        public static readonly Color SurfacePressed = Color.FromArgb(16, 20, 26);
        public static readonly Color SurfaceActive = Color.FromArgb(38, 43, 50);

        public static readonly Font UIFont = new Font("Segoe UI", 9F, FontStyle.Regular);
        public static readonly Font UIFontBold = new Font("Segoe UI", 9F, FontStyle.Bold);
        public static readonly Font UIFontSmall = new Font("Segoe UI", 8.25F, FontStyle.Regular);
        public static readonly Font UIMonoFont = new Font("Consolas", 9F, FontStyle.Regular);

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        private static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string pszSubIdList);

        public static void ApplyTo(Form form)
        {
            form.BackColor = Background;
            form.ForeColor = TextPrimary;
            form.Font = UIFont;

            ApplyDarkTitleBar(form);
            ApplyBorderFix(form);
            ApplyToControls(form.Controls);
        }

        private static void ApplyDarkTitleBar(Form form)
        {
            try
            {
                var hwnd = form.Handle;

                // Enable dark mode title bar (Windows 10 1809+)
                int darkMode = 1;
                WinApi.DwmSetWindowAttribute(hwnd, WinApi.DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1, ref darkMode, sizeof(int));
                WinApi.DwmSetWindowAttribute(hwnd, WinApi.DWMWA_USE_IMMERSIVE_DARK_MODE, ref darkMode, sizeof(int));

                // Windows 11: Set title bar colors and rounded corners
                // DWMWA_CAPTION_COLOR, DWMWA_TEXT_COLOR, DWMWA_BORDER_COLOR are available on Win11 22000+
                int captionColor = ColorToBGR(SurfaceElevated);
                int textColor = ColorToBGR(TextPrimary);
                int borderColor = ColorToBGR(Border);

                WinApi.DwmSetWindowAttribute(hwnd, WinApi.DWMWA_CAPTION_COLOR, ref captionColor, sizeof(int));
                WinApi.DwmSetWindowAttribute(hwnd, WinApi.DWMWA_TEXT_COLOR, ref textColor, sizeof(int));
                WinApi.DwmSetWindowAttribute(hwnd, WinApi.DWMWA_BORDER_COLOR, ref borderColor, sizeof(int));

                // Rounded corners (Windows 11)
                int cornerPreference = WinApi.DWMWCP_ROUNDSMALL;
                WinApi.DwmSetWindowAttribute(hwnd, WinApi.DWMWA_WINDOW_CORNER_PREFERENCE, ref cornerPreference, sizeof(int));

                // Force frame redraw to apply changes
                WinApi.SetWindowPos(hwnd, IntPtr.Zero, 0, 0, 0, 0,
                    WinApi.SWP_FRAMECHANGED | WinApi.SWP_NOMOVE | WinApi.SWP_NOSIZE | WinApi.SWP_NOZORDER);
            }
            catch
            {
                // Silently fail on older Windows versions that don't support DWM dark mode
            }
        }

        private static int ColorToBGR(Color c)
        {
            return (c.B << 16) | (c.G << 8) | c.R;
        }

        // Holds references to border fixers so they aren't garbage collected
        private static readonly Dictionary<IntPtr, DarkBorderFixer> borderFixers = new Dictionary<IntPtr, DarkBorderFixer>();
        private static readonly Dictionary<IntPtr, DarkTabControlFixer> tabControlFixers = new Dictionary<IntPtr, DarkTabControlFixer>();
        private static readonly Dictionary<IntPtr, DarkComboBoxFixer> comboBoxFaceFixers = new Dictionary<IntPtr, DarkComboBoxFixer>();
        private static readonly List<ComboBoxDropdownFixer> comboBoxFixers = new List<ComboBoxDropdownFixer>();

        private static void ApplyBorderFix(Form form)
        {
            // Border fixer disabled — the WM_NCCALCSIZE subclass causes heap corruption on some systems
        }

        private static void ApplyToControls(Control.ControlCollection controls)
        {
            foreach (Control control in controls)
            {
                if (control.ContextMenuStrip != null)
                {
                    control.ContextMenuStrip.Renderer = new DarkToolStripRenderer();
                    control.ContextMenuStrip.BackColor = Surface;
                    control.ContextMenuStrip.ForeColor = TextPrimary;
                    foreach (ToolStripItem item in control.ContextMenuStrip.Items)
                        item.ForeColor = TextPrimary;
                }

                // Apply dark scrollbar theme to any scrollable control
                if (control is ListView || control is RichTextBox || control is TextBox
                    || control is ListBox || control is TreeView || control is DataGridView
                    || control is ComboBox || control is Panel || control is TabPage)
                {
                    try { SetWindowTheme(control.Handle, "DarkMode_Explorer", null); } catch { }
                }

                if (control is ListView lv)
                {
                    ApplyToListView(lv);
                }
                else if (control is RichTextBox rtb)
                {
                    ApplyToRichTextBox(rtb);
                }
                else if (control is TabControl tc)
                {
                    ApplyToTabControl(tc);
                }
                else if (control is ComboBox cb)
                {
                    ApplyToComboBox(cb);
                }
                else if (control is TrackBar tb)
                {
                    ApplyToTrackBar(tb);
                }
                else if (control is CheckBox chk)
                {
                    ApplyToCheckBox(chk);
                }
                else if (control is RadioButton rb)
                {
                    ApplyToRadioButton(rb);
                }
                else if (control is TextBox txt && !(txt is RichTextBox))
                {
                    ApplyToTextBox(txt);
                }
                else if (control is ListBox lb)
                {
                    ApplyToListBox(lb);
                }
                else if (control is TreeView tv)
                {
                    ApplyToTreeView(tv);
                }
                else if (control is DataGridView dgv)
                {
                    ApplyToDataGridView(dgv);
                }
                else if (control is LinkLabel ll)
                {
                    ApplyToLinkLabel(ll);
                }
                else if (control is GroupBox gb)
                {
                    ApplyToGroupBox(gb);
                    ApplyToControls(gb.Controls);
                }
                else if (control is Button btn)
                {
                    ApplyToButton(btn);
                }
                else if (control is Panel pnl)
                {
                    bool hasFlowChildren = false;
                    foreach (Control c in pnl.Controls)
                        if (c is FlowLayoutPanel) { hasFlowChildren = true; break; }
                    pnl.BackColor = hasFlowChildren ? Surface : Background;
                    pnl.ForeColor = TextPrimary;
                    ApplyToControls(pnl.Controls);
                }
                else if (control is SplitContainer sc)
                {
                    sc.BackColor = Border;
                    sc.SplitterWidth = Math.Max(sc.SplitterWidth, 3);
                    sc.Panel1.BackColor = Background;
                    sc.Panel2.BackColor = Background;
                    ApplyToControls(sc.Panel1.Controls);
                    ApplyToControls(sc.Panel2.Controls);
                }
                else if (control is TableLayoutPanel tlp)
                {
                    tlp.BackColor = Background;
                    ApplyToControls(tlp.Controls);
                }
                else if (control is FlowLayoutPanel flp)
                {
                    flp.BackColor = Surface;
                    flp.Margin = Padding.Empty;
                    ApplyToControls(flp.Controls);
                }
                else if (control is Label lbl)
                {
                    lbl.ForeColor = TextPrimary;
                    lbl.BackColor = Color.Transparent;
                }
                else if (control is NumericUpDown nud)
                {
                    // DarkNumericUpDown handles its own painting
                    if (!(control is DarkNumericUpDown))
                        DarkControlsHelper.StyleNumericUpDown(nud);
                }
                else if (control is DomainUpDown dud)
                {
                    dud.BackColor = SurfaceElevated;
                    dud.ForeColor = TextPrimary;
                    dud.Font = UIFont;
                }
                else if (control is DateTimePicker dtp)
                {
                    dtp.CalendarMonthBackground = Surface;
                    dtp.CalendarTitleBackColor = SurfaceElevated;
                    dtp.CalendarTitleForeColor = TextPrimary;
                    dtp.CalendarTrailingForeColor = TextMuted;
                    dtp.ForeColor = TextPrimary;
                }
                else if (control is ProgressBar pb)
                {
                    pb.BackColor = Surface;
                    pb.ForeColor = Accent;
                }
                else if (control is ToolStrip ts)
                {
                    ApplyToToolStrip(ts);
                }
                else if (control is ContextMenuStrip cms)
                {
                    cms.Renderer = new DarkToolStripRenderer();
                    cms.BackColor = Surface;
                    cms.ForeColor = TextPrimary;
                }
                else if (control.HasChildren)
                {
                    ApplyToControls(control.Controls);
                }
            }
        }

        // --- ListView ---
        private static void ApplyToListView(ListView lv)
        {
            lv.BackColor = Surface;
            lv.ForeColor = TextPrimary;
            lv.Font = UIFont;
            lv.OwnerDraw = true;
            lv.FullRowSelect = true;

            lv.DrawColumnHeader -= ListViewDrawColumnHeader;
            lv.DrawItem -= ListViewDrawItem;
            lv.DrawSubItem -= ListViewDrawSubItem;

            lv.DrawColumnHeader += ListViewDrawColumnHeader;
            lv.DrawItem += ListViewDrawItem;
            lv.DrawSubItem += ListViewDrawSubItem;

            // Fill empty area with dark background when no items
            lv.Paint -= ListViewPaintEmpty;
            lv.Paint += ListViewPaintEmpty;

            new ListViewHeaderFixer(lv);
        }

        private static void ListViewPaintEmpty(object sender, PaintEventArgs e)
        {
            var lv = (ListView)sender;
            if (lv.Items.Count == 0 && lv.View == View.Details)
            {
                using (var brush = new SolidBrush(Surface))
                    e.Graphics.FillRectangle(brush, lv.ClientRectangle);
            }
        }

        private static void ListViewDrawColumnHeader(object sender, DrawListViewColumnHeaderEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            // Gradient fill for header
            using (var brush = new LinearGradientBrush(e.Bounds, SurfaceElevated, Surface, LinearGradientMode.Vertical))
                g.FillRectangle(brush, e.Bounds);

            // Bottom border line
            using (var pen = new Pen(Border, 1f))
                g.DrawLine(pen, e.Bounds.Left, e.Bounds.Bottom - 1, e.Bounds.Right, e.Bounds.Bottom - 1);

            // Right separator (subtle vertical line)
            using (var pen = new Pen(Color.FromArgb(20, 255, 255, 255), 1f))
                g.DrawLine(pen, e.Bounds.Right - 1, e.Bounds.Top + 4, e.Bounds.Right - 1, e.Bounds.Bottom - 4);

            // Header text with refined rendering
            var textBounds = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 16, e.Bounds.Height);
            TextRenderer.DrawText(g, e.Header.Text, UIFontBold, textBounds, TextSecondary,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }

        private static void ListViewDrawItem(object sender, DrawListViewItemEventArgs e)
        {
            e.DrawDefault = false;
        }

        private static void ListViewDrawSubItem(object sender, DrawListViewSubItemEventArgs e)
        {
            Color bgColor;
            Color fgColor = e.Item.ForeColor;

            if (e.Item.Selected)
            {
                bgColor = Color.FromArgb(30, 56, 139, 253);
                fgColor = TextPrimary;
            }
            else if (e.ItemIndex % 2 == 1)
            {
                bgColor = Color.FromArgb(17, 21, 27);
            }
            else
            {
                bgColor = Surface;
            }

            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            using (var bgBrush = new SolidBrush(bgColor))
                g.FillRectangle(bgBrush, e.Bounds);

            // Fill empty space to the right of the last column with the same row color
            var lv = (ListView)sender;
            if (e.ColumnIndex == lv.Columns.Count - 1)
            {
                int totalColWidth = 0;
                foreach (ColumnHeader col in lv.Columns)
                    totalColWidth += col.Width;

                if (totalColWidth < lv.ClientSize.Width)
                {
                    var fillRect = new Rectangle(totalColWidth, e.Bounds.Top,
                        lv.ClientSize.Width - totalColWidth, e.Bounds.Height);
                    using (var bgBrush = new SolidBrush(bgColor))
                        g.FillRectangle(bgBrush, fillRect);
                }
            }

            // Accent left bar on selected rows (rounded, with glow)
            if (e.Item.Selected && e.ColumnIndex == 0)
            {
                var barRect = new Rectangle(e.Bounds.Left + 1, e.Bounds.Top + 2, 3, e.Bounds.Height - 4);
                using (var brush = new SolidBrush(Accent))
                    g.FillRectangle(brush, barRect);

                // Subtle glow around the bar
                using (var brush = new SolidBrush(Color.FromArgb(25, Accent)))
                    g.FillRectangle(brush, barRect.X - 1, barRect.Y - 1, barRect.Width + 2, barRect.Height + 2);
            }

            // Subtle bottom separator line
            using (var pen = new Pen(Color.FromArgb(15, 255, 255, 255), 1f))
                g.DrawLine(pen, e.Bounds.Left + 4, e.Bounds.Bottom - 1, e.Bounds.Right - 4, e.Bounds.Bottom - 1);

            var textBounds = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height);
            TextRenderer.DrawText(g, e.SubItem?.Text ?? "", UIFont, textBounds, fgColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
        }

        // --- RichTextBox ---
        private static void ApplyToRichTextBox(RichTextBox rtb)
        {
            rtb.BackColor = Surface;
            rtb.ForeColor = TextPrimary;
            rtb.Font = UIMonoFont;
        }

        // --- TextBox ---
        private static void ApplyToTextBox(TextBox txt)
        {
            txt.BackColor = SurfaceElevated;
            txt.ForeColor = TextPrimary;
            txt.BorderStyle = BorderStyle.FixedSingle;
            txt.Font = UIFont;

            // Luxury: rounded border with focus glow
            txt.Paint -= TextBoxFocusPaint;
            txt.Paint += TextBoxFocusPaint;

            // Track focus state for border color change
            txt.GotFocus -= TextBoxFocusChanged;
            txt.LostFocus -= TextBoxFocusChanged;
            txt.GotFocus += TextBoxFocusChanged;
            txt.LostFocus += TextBoxFocusChanged;
        }

        private static void TextBoxFocusChanged(object sender, EventArgs e)
        {
            var txt = (TextBox)sender;
            txt.Invalidate();
            // Also repaint parent to show border glow
            txt.Parent?.Invalidate(new Rectangle(txt.Left - 2, txt.Top - 2, txt.Width + 4, txt.Height + 4), true);
        }

        private static void TextBoxFocusPaint(object sender, PaintEventArgs e)
        {
            // Paint handled on parent panel below
        }

        // --- ComboBox ---
        private static void ApplyToComboBox(ComboBox cb)
        {
            // DarkComboBox handles its own painting
            if (cb is DarkComboBox) return;

            cb.BackColor = SurfaceElevated;
            cb.ForeColor = TextPrimary;
            cb.Font = UIFont;
            cb.FlatStyle = FlatStyle.Flat;

            if (cb.DropDownStyle == ComboBoxStyle.DropDownList)
            {
                cb.DrawMode = DrawMode.OwnerDrawFixed;
                cb.DrawItem -= ComboBoxDrawItem;
                cb.DrawItem += ComboBoxDrawItem;
            }

            // Luxury combo paint (custom arrow, rounded border)
            DarkControlsHelper.StyleComboBox(cb);

            // Fix white dropdown popup background
            comboBoxFixers.Add(new ComboBoxDropdownFixer(cb));

            // Fix white background on the DropDownList face itself
            if (!comboBoxFaceFixers.ContainsKey(cb.Handle))
            {
                var fixer = new DarkComboBoxFixer(cb);
                comboBoxFaceFixers[cb.Handle] = fixer;
                var parentForm = cb.FindForm();
                if (parentForm != null)
                {
                    parentForm.FormClosed += (s, e) =>
                    {
                        comboBoxFaceFixers.Remove(cb.Handle);
                        fixer.ReleaseHandle();
                    };
                }
            }
        }

        private static void ComboBoxDrawItem(object sender, DrawItemEventArgs e)
        {
            var cb = (ComboBox)sender;
            if (e.Index < 0) return;

            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            bool isSelected = (e.State & DrawItemState.Selected) != 0;
            Color bgColor = isSelected ? Color.FromArgb(30, 56, 139, 253) : Surface;
            Color fgColor = isSelected ? TextPrimary : TextSecondary;

            using (var bgBrush = new SolidBrush(bgColor))
                g.FillRectangle(bgBrush, e.Bounds);

            // Accent left bar on selected item
            if (isSelected)
            {
                var barRect = new Rectangle(e.Bounds.Left + 2, e.Bounds.Top + 3, 3, e.Bounds.Height - 6);
                using (var brush = new SolidBrush(Accent))
                    g.FillRectangle(brush, barRect);
            }

            string text = cb.Items[e.Index]?.ToString() ?? "";
            var textBounds = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height);
            TextRenderer.DrawText(g, text, UIFont, textBounds, fgColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }

        // --- TrackBar (Slider) ---
        private static void ApplyToTrackBar(TrackBar tb)
        {
            tb.BackColor = Background;

            // Hook Paint for custom rendering
            tb.Paint -= TrackBarPaint;
            tb.Paint += TrackBarPaint;
        }

        private static void TrackBarPaint(object sender, PaintEventArgs e)
        {
            var tb = (TrackBar)sender;
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            int trackY = tb.Height / 2;
            int trackHeight = 4;
            int thumbRadius = 8;

            // Calculate track bounds
            int leftMargin = thumbRadius + 2;
            int rightMargin = thumbRadius + 2;
            int trackLeft = leftMargin;
            int trackRight = tb.Width - rightMargin;
            int trackWidth = trackRight - trackLeft;

            // Background track
            var trackRect = new Rectangle(trackLeft, trackY - trackHeight / 2, trackWidth, trackHeight);
            using (var brush = new SolidBrush(SurfaceHover))
                g.FillRectangle(brush, trackRect);

            // Filled portion
            float ratio = (float)(tb.Value - tb.Minimum) / (tb.Maximum - tb.Minimum);
            int fillWidth = (int)(trackWidth * ratio);
            var fillRect = new Rectangle(trackLeft, trackY - trackHeight / 2, fillWidth, trackHeight);
            using (var brush = new SolidBrush(Accent))
                g.FillRectangle(brush, fillRect);

            // Thumb
            int thumbX = trackLeft + fillWidth;
            var thumbRect = new Rectangle(thumbX - thumbRadius, trackY - thumbRadius, thumbRadius * 2, thumbRadius * 2);
            using (var brush = new SolidBrush(Accent))
                g.FillEllipse(brush, thumbRect);
            using (var pen = new Pen(AccentHover, 1.5f))
                g.DrawEllipse(pen, thumbRect);
        }

        // --- CheckBox ---
        private static void ApplyToCheckBox(CheckBox chk)
        {
            chk.ForeColor = TextPrimary;
            chk.BackColor = Color.Transparent;
            chk.Font = UIFont;
            chk.FlatStyle = FlatStyle.Standard;

            // Luxury: custom paint handler for premium checkbox appearance
            chk.Paint -= LuxuryCheckBoxPaint;
            chk.Paint += LuxuryCheckBoxPaint;
        }

        private static void LuxuryCheckBoxPaint(object sender, PaintEventArgs e)
        {
            var chk = (CheckBox)sender;
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            // Clear default rendering
            g.Clear(chk.BackColor == Color.Transparent ? (chk.Parent?.BackColor ?? Background) : chk.BackColor);

            int boxSize = 16;
            int boxY = (chk.Height - boxSize) / 2;
            var boxRect = new Rectangle(0, boxY, boxSize, boxSize);

            // Draw checkbox box with rounded corners
            using (var path = DarkControlsHelper.CreateRoundedRect(boxRect, 3))
            {
                Color fillColor = chk.Checked ? AccentSubtle : SurfaceElevated;
                using (var brush = new SolidBrush(fillColor))
                    g.FillPath(brush, path);

                Color borderColor = chk.Checked ? Accent : Border;
                using (var pen = new Pen(borderColor, 1.2f))
                    g.DrawPath(pen, path);
            }

            // Draw checkmark
            if (chk.Checked)
            {
                using (var pen = new Pen(TextPrimary, 2f))
                {
                    pen.StartCap = LineCap.Round;
                    pen.EndCap = LineCap.Round;
                    g.DrawLine(pen, boxRect.X + 3, boxRect.Y + 8, boxRect.X + 7, boxRect.Y + 12);
                    g.DrawLine(pen, boxRect.X + 7, boxRect.Y + 12, boxRect.X + 13, boxRect.Y + 4);
                }
            }

            // Draw text
            var textRect = new Rectangle(boxSize + 6, 0, chk.Width - boxSize - 6, chk.Height);
            TextRenderer.DrawText(g, chk.Text, chk.Font, textRect, chk.ForeColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }

        // --- RadioButton ---
        private static void ApplyToRadioButton(RadioButton rb)
        {
            rb.ForeColor = TextPrimary;
            rb.BackColor = Color.Transparent;
            rb.Font = UIFont;
            rb.FlatStyle = FlatStyle.Standard;

            // Luxury: custom paint handler for premium radio button appearance
            rb.Paint -= LuxuryRadioPaint;
            rb.Paint += LuxuryRadioPaint;
        }

        private static void LuxuryRadioPaint(object sender, PaintEventArgs e)
        {
            var rb = (RadioButton)sender;
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            g.Clear(rb.BackColor == Color.Transparent ? (rb.Parent?.BackColor ?? Background) : rb.BackColor);

            int radioSize = 16;
            int radioY = (rb.Height - radioSize) / 2;
            var radioRect = new Rectangle(0, radioY, radioSize, radioSize);

            // Draw outer circle
            Color fillColor = rb.Checked ? AccentSubtle : SurfaceElevated;
            using (var brush = new SolidBrush(fillColor))
                g.FillEllipse(brush, radioRect);

            Color borderColor = rb.Checked ? Accent : Border;
            using (var pen = new Pen(borderColor, 1.2f))
                g.DrawEllipse(pen, radioRect);

            // Draw inner dot when checked
            if (rb.Checked)
            {
                var dotRect = new Rectangle(radioRect.X + 4, radioRect.Y + 4, radioRect.Width - 8, radioRect.Height - 8);
                using (var brush = new SolidBrush(TextPrimary))
                    g.FillEllipse(brush, dotRect);
            }

            // Draw text
            var textRect = new Rectangle(radioSize + 6, 0, rb.Width - radioSize - 6, rb.Height);
            TextRenderer.DrawText(g, rb.Text, rb.Font, textRect, rb.ForeColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }

        // --- ListBox ---
        private static void ApplyToListBox(ListBox lb)
        {
            lb.BackColor = Surface;
            lb.ForeColor = TextPrimary;
            lb.Font = UIFont;
            lb.BorderStyle = BorderStyle.None;

            lb.DrawMode = DrawMode.OwnerDrawFixed;
            lb.DrawItem -= ListBoxDrawItem;
            lb.DrawItem += ListBoxDrawItem;
        }

        private static void ListBoxDrawItem(object sender, DrawItemEventArgs e)
        {
            var lb = (ListBox)sender;
            if (e.Index < 0) return;

            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            bool selected = (e.State & DrawItemState.Selected) != 0;
            Color bgColor = selected ? Color.FromArgb(30, 56, 139, 253) : (e.Index % 2 == 1 ? Color.FromArgb(17, 21, 27) : Surface);

            using (var brush = new SolidBrush(bgColor))
                g.FillRectangle(brush, e.Bounds);

            string text = lb.Items[e.Index]?.ToString() ?? "";
            var textBounds = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height);
            TextRenderer.DrawText(g, text, UIFont, textBounds, TextPrimary,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);

            if (selected)
            {
                // Accent left bar
                var barRect = new Rectangle(e.Bounds.Left + 1, e.Bounds.Top + 2, 3, e.Bounds.Height - 4);
                using (var brush = new SolidBrush(Accent))
                    g.FillRectangle(brush, barRect);
                // Glow
                using (var brush = new SolidBrush(Color.FromArgb(25, Accent)))
                    g.FillRectangle(brush, barRect.X - 1, barRect.Y - 1, barRect.Width + 2, barRect.Height + 2);
            }

            // Subtle row separator
            using (var pen = new Pen(Color.FromArgb(15, 255, 255, 255), 1f))
                g.DrawLine(pen, e.Bounds.Left + 4, e.Bounds.Bottom - 1, e.Bounds.Right - 4, e.Bounds.Bottom - 1);
        }

        // --- TreeView ---
        private static void ApplyToTreeView(TreeView tv)
        {
            tv.BackColor = Surface;
            tv.ForeColor = TextPrimary;
            tv.Font = UIFont;
            tv.BorderStyle = BorderStyle.None;
            tv.LineColor = Border;
            tv.FullRowSelect = true;
            tv.ShowLines = true;

            tv.DrawMode = TreeViewDrawMode.OwnerDrawText;
            tv.DrawNode -= TreeViewDrawNode;
            tv.DrawNode += TreeViewDrawNode;
        }

        private static void TreeViewDrawNode(object sender, DrawTreeNodeEventArgs e)
        {
            var tv = (TreeView)sender;
            bool selected = (e.State & TreeNodeStates.Selected) != 0;

            // Fill full row background
            var rowBounds = new Rectangle(0, e.Bounds.Top, tv.Width, e.Bounds.Height);
            Color bgColor = selected ? Color.FromArgb(40, 56, 139, 253) : Surface;
            using (var brush = new SolidBrush(bgColor))
                e.Graphics.FillRectangle(brush, rowBounds);

            // Draw text
            var textBounds = new Rectangle(e.Bounds.X + 2, e.Bounds.Y, e.Bounds.Width, e.Bounds.Height);
            using (var brush = new SolidBrush(selected ? TextPrimary : TextSecondary))
                e.Graphics.DrawString(e.Node.Text, UIFont, brush, textBounds);

            // Selection indicator
            if (selected)
            {
                using (var pen = new Pen(Accent, 2))
                    e.Graphics.DrawLine(pen, 0, e.Bounds.Top, 0, e.Bounds.Bottom);
            }
        }

        // --- DataGridView ---
        private static void ApplyToDataGridView(DataGridView dgv)
        {
            dgv.BackgroundColor = Surface;
            dgv.GridColor = BorderSubtle;
            dgv.BorderStyle = BorderStyle.None;
            dgv.CellBorderStyle = DataGridViewCellBorderStyle.SingleHorizontal;
            dgv.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            dgv.RowHeadersVisible = false;
            dgv.EnableHeadersVisualStyles = false;
            dgv.AllowUserToResizeRows = false;

            dgv.DefaultCellStyle.BackColor = Surface;
            dgv.DefaultCellStyle.ForeColor = TextPrimary;
            dgv.DefaultCellStyle.SelectionBackColor = Color.FromArgb(40, 56, 139, 253);
            dgv.DefaultCellStyle.SelectionForeColor = TextPrimary;
            dgv.DefaultCellStyle.Font = UIFont;
            dgv.DefaultCellStyle.Padding = new Padding(4, 2, 4, 2);

            dgv.ColumnHeadersDefaultCellStyle.BackColor = SurfaceElevated;
            dgv.ColumnHeadersDefaultCellStyle.ForeColor = TextSecondary;
            dgv.ColumnHeadersDefaultCellStyle.Font = UIFontBold;
            dgv.ColumnHeadersDefaultCellStyle.Padding = new Padding(4, 2, 4, 2);
            dgv.ColumnHeadersHeight = 32;
            dgv.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;

            dgv.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(18, 22, 28);
        }

        // --- LinkLabel ---
        private static void ApplyToLinkLabel(LinkLabel ll)
        {
            ll.LinkColor = Accent;
            ll.VisitedLinkColor = AccentHover;
            ll.ActiveLinkColor = AccentSubtle;
            ll.Font = UIFont;
        }

        // --- TabControl ---
        private static void ApplyToTabControl(TabControl tc)
        {
            tc.BackColor = Background;
            tc.Font = UIFont;
            tc.Padding = new Point(12, 6);

            tc.DrawMode = TabDrawMode.OwnerDrawFixed;
            tc.DrawItem -= TabControlDrawItem;
            tc.DrawItem += TabControlDrawItem;

            // Fill entire tab strip header with dark background.
            // Must be in Paint event (not DrawItem) because DrawItem's Graphics
            // is clipped to individual tab bounds and can't paint full width.
            tc.Paint -= TabControlPaintStrip;
            tc.Paint += TabControlPaintStrip;

            // Fix white border frame around tab page area
            if (!tabControlFixers.ContainsKey(tc.Handle))
            {
                var fixer = new DarkTabControlFixer(tc);
                tabControlFixers[tc.Handle] = fixer;
                var parentForm = tc.FindForm();
                if (parentForm != null)
                {
                    parentForm.FormClosed += (s, e) =>
                    {
                        tabControlFixers.Remove(tc.Handle);
                        fixer.ReleaseHandle();
                    };
                }
            }

            // Style each tab page
            foreach (TabPage page in tc.TabPages)
            {
                page.BackColor = Background;
                page.ForeColor = TextPrimary;
                ApplyToControls(page.Controls);
            }
        }

        private static void TabControlDrawItem(object sender, DrawItemEventArgs e)
        {
            var tc = (TabControl)sender;
            var page = tc.TabPages[e.Index];
            bool selected = (e.Index == tc.SelectedIndex);
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            var tabRect = e.Bounds;
            Color fgColor = selected ? TextPrimary : TextSecondary;

            if (selected)
            {
                // Selected tab: rounded top corners, gradient fill
                var roundedRect = new Rectangle(tabRect.X + 1, tabRect.Y, tabRect.Width - 2, tabRect.Height - 1);
                using (var path = DarkControlsHelper.CreateRoundedRect(roundedRect, 6))
                {
                    // Only round top corners - clip bottom
                    using (var clipRegion = new Region(new Rectangle(tabRect.X, tabRect.Y, tabRect.Width, tabRect.Height + 10)))
                    {
                        g.SetClip(clipRegion, CombineMode.Intersect);
                        using (var brush = new LinearGradientBrush(roundedRect, GradientTop, Surface, LinearGradientMode.Vertical))
                            g.FillPath(brush, path);
                        g.ResetClip();
                    }
                }

                // Accent underline (wider, with rounded ends)
                var accentRect = new Rectangle(tabRect.Left + 8, tabRect.Bottom - 3, tabRect.Width - 16, 2);
                using (var brush = new SolidBrush(Accent))
                    g.FillRectangle(brush, accentRect);
            }
            else
            {
                // Unselected: flat background
                using (var brush = new SolidBrush(Background))
                    g.FillRectangle(brush, tabRect);
            }

            // Tab text
            var textBounds = new Rectangle(tabRect.X, tabRect.Y, tabRect.Width, tabRect.Height - 3);
            TextRenderer.DrawText(g, page.Text, UIFont, textBounds, fgColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }

        private static void TabControlPaintStrip(object sender, PaintEventArgs e)
        {
            var tc = (TabControl)sender;
            if (tc.TabCount == 0) return;

            // Fill the entire tab strip header area with dark background.
            // Paint event Graphics covers the full control (not clipped to tabs).
            var firstTab = tc.GetTabRect(0);
            var stripRect = new Rectangle(0, 0, tc.ClientSize.Width, firstTab.Bottom);
            using (var brush = new SolidBrush(Background))
                e.Graphics.FillRectangle(brush, stripRect);
        }

        // --- GroupBox ---
        private static void ApplyToGroupBox(GroupBox gb)
        {
            gb.ForeColor = TextSecondary;
            gb.BackColor = Background;
            gb.Font = UIFontBold;
        }

        // --- Button ---
        private static void ApplyToButton(Button btn)
        {
            DarkControlsHelper.StyleButton(btn);
        }

        // --- ToolStrip ---
        private static void ApplyToToolStrip(ToolStrip ts)
        {
            ts.Renderer = new DarkToolStripRenderer();
            ts.BackColor = Surface;
            ts.ForeColor = TextPrimary;

            foreach (ToolStripItem item in ts.Items)
            {
                item.ForeColor = TextPrimary;
                item.BackColor = Surface;

                if (item is ToolStripTextBox tsTxt)
                {
                    tsTxt.TextBox.BackColor = SurfaceElevated;
                    tsTxt.TextBox.ForeColor = TextPrimary;
                    tsTxt.TextBox.BorderStyle = BorderStyle.FixedSingle;
                    tsTxt.TextBox.Font = UIFont;
                }
                else if (item is ToolStripButton tsBtn)
                {
                    tsBtn.Font = UIFont;
                }
            }
        }

        // --- ToolTip helper (call from form code) ---
        public static void StyleToolTip(ToolTip tt)
        {
            tt.BackColor = SurfaceElevated;
            tt.ForeColor = TextPrimary;
            tt.OwnerDraw = true;
            tt.Draw -= ToolTipDraw;
            tt.Draw += ToolTipDraw;
            tt.Popup -= ToolTipPopup;
            tt.Popup += ToolTipPopup;
        }

        private static void ToolTipPopup(object sender, PopupEventArgs e)
        {
            // Add padding
            var tt = (ToolTip)sender;
            e.ToolTipSize = new Size(e.ToolTipSize.Width + 12, e.ToolTipSize.Height + 8);
        }

        private static void ToolTipDraw(object sender, DrawToolTipEventArgs e)
        {
            using (var bgBrush = new SolidBrush(SurfaceElevated))
                e.Graphics.FillRectangle(bgBrush, e.Bounds);

            using (var pen = new Pen(Border))
                e.Graphics.DrawRectangle(pen, e.Bounds.X, e.Bounds.Y, e.Bounds.Width - 1, e.Bounds.Height - 1);

            var textBounds = new Rectangle(e.Bounds.X + 6, e.Bounds.Y + 4, e.Bounds.Width - 12, e.Bounds.Height - 8);
            using (var brush = new SolidBrush(TextPrimary))
                e.Graphics.DrawString(e.ToolTipText, UIFontSmall, brush, textBounds);
        }
    }

    internal class DarkColorTable : ProfessionalColorTable
    {
        public override Color ToolStripDropDownBackground => DarkTheme.Surface;
        public override Color ImageMarginGradientBegin => DarkTheme.Surface;
        public override Color ImageMarginGradientMiddle => DarkTheme.Surface;
        public override Color ImageMarginGradientEnd => DarkTheme.Surface;
        public override Color SeparatorDark => DarkTheme.Border;
        public override Color SeparatorLight => DarkTheme.Border;
        public override Color MenuStripGradientBegin => DarkTheme.Background;
        public override Color MenuStripGradientEnd => DarkTheme.Background;
        public override Color MenuItemSelected => DarkTheme.SurfaceHover;
        public override Color MenuItemSelectedGradientBegin => DarkTheme.SurfaceHover;
        public override Color MenuItemSelectedGradientEnd => DarkTheme.SurfaceHover;
        public override Color MenuItemBorder => Color.Transparent;
        public override Color MenuBorder => DarkTheme.Border;
        public override Color ImageMarginRevealedGradientBegin => DarkTheme.Surface;
        public override Color ImageMarginRevealedGradientMiddle => DarkTheme.Surface;
        public override Color ImageMarginRevealedGradientEnd => DarkTheme.Surface;
        public override Color CheckBackground => DarkTheme.SurfaceHover;
        public override Color CheckPressedBackground => DarkTheme.Accent;
        public override Color CheckSelectedBackground => DarkTheme.Accent;
        public override Color ButtonSelectedHighlight => DarkTheme.SurfaceHover;
        public override Color ButtonSelectedBorder => DarkTheme.Border;
        public override Color ButtonCheckedHighlight => DarkTheme.AccentSubtle;
        public override Color ButtonCheckedGradientBegin => DarkTheme.AccentSubtle;
        public override Color ButtonCheckedGradientEnd => DarkTheme.AccentSubtle;
        public override Color ButtonPressedBorder => DarkTheme.Accent;
        public override Color ButtonSelectedGradientBegin => DarkTheme.SurfaceHover;
        public override Color ButtonSelectedGradientEnd => DarkTheme.SurfaceHover;
        public override Color ButtonPressedGradientBegin => DarkTheme.AccentSubtle;
        public override Color ButtonPressedGradientEnd => DarkTheme.AccentSubtle;
        public override Color ToolStripBorder => DarkTheme.Border;
        public override Color ToolStripGradientBegin => DarkTheme.Surface;
        public override Color ToolStripGradientMiddle => DarkTheme.Surface;
        public override Color ToolStripGradientEnd => DarkTheme.Surface;
        public override Color ToolStripContentPanelGradientBegin => DarkTheme.Background;
        public override Color ToolStripContentPanelGradientEnd => DarkTheme.Background;
        public override Color ToolStripPanelGradientBegin => DarkTheme.Background;
        public override Color ToolStripPanelGradientEnd => DarkTheme.Background;
        public override Color GripDark => DarkTheme.Border;
        public override Color GripLight => DarkTheme.Border;
        public override Color OverflowButtonGradientBegin => DarkTheme.Surface;
        public override Color OverflowButtonGradientMiddle => DarkTheme.Surface;
        public override Color OverflowButtonGradientEnd => DarkTheme.Surface;
    }

    internal class DarkToolStripRenderer : ToolStripProfessionalRenderer
    {
        public DarkToolStripRenderer() : base(new DarkColorTable()) { }

        protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e)
        {
            e.TextColor = DarkTheme.TextPrimary;
            base.OnRenderItemText(e);
        }

        protected override void OnRenderToolStripBackground(ToolStripRenderEventArgs e)
        {
            using (var brush = new SolidBrush(DarkTheme.Surface))
                e.Graphics.FillRectangle(brush, e.AffectedBounds);
        }

        protected override void OnRenderToolStripBorder(ToolStripRenderEventArgs e)
        {
            using (var pen = new Pen(DarkTheme.Border))
            {
                var rect = e.AffectedBounds;
                e.Graphics.DrawLine(pen, rect.Left, rect.Bottom - 1, rect.Right, rect.Bottom - 1);
            }
        }

        protected override void OnRenderButtonBackground(ToolStripItemRenderEventArgs e)
        {
            var item = e.Item;
            var g = e.Graphics;
            var rect = new Rectangle(0, 0, item.Width - 1, item.Height - 1);

            Color bgColor = item.Pressed
                ? DarkTheme.AccentSubtle
                : item.Selected
                    ? DarkTheme.SurfaceHover
                    : (item.BackColor.IsEmpty || item.BackColor == SystemColors.Control)
                        ? DarkTheme.Surface
                        : item.BackColor;

            using (var brush = new SolidBrush(bgColor))
                g.FillRectangle(brush, rect);

            if (item.Selected || item.Pressed)
            {
                using (var pen = new Pen(DarkTheme.Border))
                    g.DrawRectangle(pen, rect);
            }
        }

        protected override void OnRenderDropDownButtonBackground(ToolStripItemRenderEventArgs e)
        {
            OnRenderButtonBackground(e);
        }

        protected override void OnRenderOverflowButtonBackground(ToolStripItemRenderEventArgs e)
        {
            OnRenderButtonBackground(e);
        }

        protected override void OnRenderMenuItemBackground(ToolStripItemRenderEventArgs e)
        {
            var item = e.Item;
            var g = e.Graphics;
            var rect = new Rectangle(0, 0, item.Width, item.Height);

            Color bgColor = item.Selected
                ? DarkTheme.SurfaceHover
                : DarkTheme.Surface;

            using (var brush = new SolidBrush(bgColor))
                g.FillRectangle(brush, rect);
        }

        protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e)
        {
            using (var pen = new Pen(DarkTheme.Border))
            {
                if (e.Vertical)
                    e.Graphics.DrawLine(pen, e.Item.Width / 2, 2, e.Item.Width / 2, e.Item.Height - 2);
                else
                    e.Graphics.DrawLine(pen, 2, e.Item.Height / 2, e.Item.Width - 2, e.Item.Height / 2);
            }
        }
    }

    /// <summary>
    /// Subclasses a form's window procedure to eliminate the default white
    /// non-client border while preserving the DWM title bar.
    /// Handles all relevant messages to maintain the dark border in every state.
    /// </summary>
    internal class DarkBorderFixer : NativeWindow
    {
        private const int WM_NCCALCSIZE = 0x0083;
        private const int WM_NCPAINT = 0x0085;
        private const int WM_NCACTIVATE = 0x0086;
        private const int WM_ERASEBKGND = 0x0014;
        private const int WM_SIZE = 0x0005;
        private const int SM_CXFRAME = 32;
        private const int SM_CYFRAME = 33;

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll")]
        private static extern bool IsZoomed(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern IntPtr GetWindowDC(IntPtr hWnd);

        [DllImport("user32.dll")]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("gdi32.dll")]
        private static extern IntPtr CreateSolidBrush(int crColor);

        [DllImport("gdi32.dll")]
        private static extern int FillRect(IntPtr hDC, ref RECT lprc, IntPtr hbr);

        [DllImport("gdi32.dll")]
        private static extern bool DeleteObject(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left, Top, Right, Bottom;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct NCCALCSIZE_PARAMS
        {
            public RECT rgrc0;
            public RECT rgrc1;
            public RECT rgrc2;
            public IntPtr lppos;
        }

        private readonly Form form;

        public DarkBorderFixer(Form form)
        {
            this.form = form;
            AssignHandle(form.Handle);
        }

        private void PaintDarkBorder(IntPtr hwnd)
        {
            if (IsZoomed(hwnd)) return;

            IntPtr hdc = GetWindowDC(hwnd);
            if (hdc == IntPtr.Zero) return;
            try
            {
                GetWindowRect(hwnd, out RECT rc);
                int w = rc.Right - rc.Left;
                int h = rc.Bottom - rc.Top;

                int color = (DarkTheme.Border.B << 16)
                          | (DarkTheme.Border.G << 8)
                          | DarkTheme.Border.R;
                IntPtr brush = CreateSolidBrush(color);

                // Paint 8px on left, right, bottom + 1px top strip
                var left = new RECT { Left = 0, Top = 0, Right = 8, Bottom = h };
                FillRect(hdc, ref left, brush);

                var right = new RECT { Left = w - 8, Top = 0, Right = w, Bottom = h };
                FillRect(hdc, ref right, brush);

                var bottom = new RECT { Left = 0, Top = h - 8, Right = w, Bottom = h };
                FillRect(hdc, ref bottom, brush);

                var top = new RECT { Left = 0, Top = 0, Right = w, Bottom = 1 };
                FillRect(hdc, ref top, brush);

                DeleteObject(brush);
            }
            finally
            {
                ReleaseDC(hwnd, hdc);
            }
        }

        protected override void WndProc(ref Message m)
        {
            // Handle WM_NCCALCSIZE to remove borders
            if (m.Msg == WM_NCCALCSIZE && m.WParam != IntPtr.Zero)
            {
                base.WndProc(ref m);

                if (!IsZoomed(m.HWnd))
                {
                    int cxFrame = GetSystemMetrics(SM_CXFRAME) + 4;
                    int cyFrame = GetSystemMetrics(SM_CYFRAME) + 4;

                    // Read only rgrc0 (first RECT at lParam offset 0) and write it back directly.
                    // Using Marshal on the full NCCALCSIZE_PARAMS can corrupt adjacent heap memory.
                    var rgrc0 = System.Runtime.InteropServices.Marshal.PtrToStructure<RECT>(m.LParam);

                    rgrc0.Left -= cxFrame;
                    rgrc0.Right += cxFrame;
                    rgrc0.Bottom += cyFrame;

                    System.Runtime.InteropServices.Marshal.StructureToPtr(rgrc0, m.LParam, false);
                }

                m.Result = IntPtr.Zero;
                return;
            }

            base.WndProc(ref m);

            // Fill entire window with dark on every background erase
            if (m.Msg == WM_ERASEBKGND && !IsZoomed(m.HWnd))
            {
                PaintDarkBorder(m.HWnd);
            }

            // Paint dark border over any remaining non-client area
            if (m.Msg == WM_NCPAINT || m.Msg == WM_NCACTIVATE)
            {
                PaintDarkBorder(m.HWnd);
            }

            // Repaint borders after resize/restore from maximized
            if (m.Msg == WM_SIZE)
            {
                PaintDarkBorder(m.HWnd);
            }
        }
    }

    /// <summary>
    /// Subclasses a ListView's window procedure to paint the empty space to the
    /// right of the last column header with the dark theme color. Needed for
    /// regular (non-ProcessListView) ListViews whose columns don't span the
    /// full control width.
    /// </summary>
    internal class ListViewHeaderFixer : NativeWindow
    {
        private const int WM_PAINT = 0x000F;
        private const int LVM_GETHEADER = 0x101F;
        private readonly ListView listView;

        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern bool GetClientRect(IntPtr hWnd, out RECT lpRect);

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left, Top, Right, Bottom;
        }

        public ListViewHeaderFixer(ListView lv)
        {
            listView = lv;
            AssignHandle(lv.Handle);
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);

            if (m.Msg == WM_PAINT && listView.View == View.Details && listView.Columns.Count > 0)
            {
                int totalColWidth = 0;
                foreach (ColumnHeader col in listView.Columns)
                    totalColWidth += col.Width;

                int clientWidth = listView.ClientSize.Width;
                if (totalColWidth < clientWidth)
                {
                    IntPtr headerHwnd = SendMessage(m.HWnd, LVM_GETHEADER, IntPtr.Zero, IntPtr.Zero);
                    if (headerHwnd != IntPtr.Zero)
                    {
                        GetWindowRect(headerHwnd, out RECT headerRect);
                        int headerHeight = headerRect.Bottom - headerRect.Top;

                        // Convert header screen coords to ListView client coords
                        int x = totalColWidth;
                        int w = clientWidth - x;

                        using (var g = Graphics.FromHwnd(headerHwnd))
                        {
                            // Fill header empty space
                            using (var brush = new SolidBrush(DarkTheme.SurfaceElevated))
                                g.FillRectangle(brush, x, 0, w, headerHeight);

                            // Draw bottom border line matching column header style
                            using (var pen = new Pen(DarkTheme.Border))
                                g.DrawLine(pen, x, headerHeight - 1, x + w, headerHeight - 1);
                        }
                    }
                }
            }
        }
    }

    /// <summary>
    /// Subclasses a TabControl to draw a dark 1px border over the default
    /// white border frame that WinForms draws around the tab page area.
    /// </summary>
    internal class DarkTabControlFixer : NativeWindow
    {
        private const int WM_PAINT = 0x000F;

        public DarkTabControlFixer(TabControl tc)
        {
            AssignHandle(tc.Handle);
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);

            if (m.Msg == WM_PAINT)
            {
                using (var g = Graphics.FromHwnd(m.HWnd))
                {
                    var tc = Control.FromHandle(m.HWnd) as TabControl;
                    if (tc == null || tc.TabCount == 0) return;

                    int w = tc.ClientSize.Width;
                    int h = tc.ClientSize.Height;

                    // Calculate tab strip height
                    int tabStripHeight = tc.GetTabRect(0).Bottom;

                    // Fill the ENTIRE tab strip header area with dark background.
                    // This MUST happen here (after base.WndProc) because the native
                    // TabControl paints its default white strip AFTER the Paint event
                    // fires during base.WndProc, covering any earlier dark fill.
                    var stripRect = new Rectangle(0, 0, w, tabStripHeight);
                    using (var brush = new SolidBrush(DarkTheme.Background))
                        g.FillRectangle(brush, stripRect);

                    // Re-draw individual tab headers since the strip fill covers them.
                    // DrawItem events fired during base.WndProc and are now hidden.
                    for (int i = 0; i < tc.TabCount; i++)
                    {
                        var tabRect = tc.GetTabRect(i);
                        bool selected = (i == tc.SelectedIndex);

                        Color bgColor = selected ? DarkTheme.Surface : DarkTheme.Background;
                        Color fgColor = selected ? DarkTheme.TextPrimary : DarkTheme.TextSecondary;

                        using (var brush = new SolidBrush(bgColor))
                            g.FillRectangle(brush, tabRect);

                        // Accent underline on selected tab
                        if (selected)
                        {
                            var accentRect = new Rectangle(tabRect.Left + 4, tabRect.Bottom - 3, tabRect.Width - 8, 2);
                            using (var brush = new SolidBrush(DarkTheme.Accent))
                                g.FillRectangle(brush, accentRect);
                        }

                        // Tab text
                        var textBounds = new Rectangle(tabRect.X, tabRect.Y, tabRect.Width, tabRect.Height - 3);
                        var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
                        using (var brush = new SolidBrush(fgColor))
                            g.DrawString(tc.TabPages[i].Text, DarkTheme.UIFont, brush, textBounds, format);
                    }

                    // Fill only the page area (below the tab strip) to cover
                    // the native white frame that WinForms draws around tab pages
                    using (var brush = new SolidBrush(DarkTheme.Background))
                        g.FillRectangle(brush, 0, tabStripHeight, w, h - tabStripHeight);

                    // Draw dark border around the page area only
                    using (var pen = new Pen(DarkTheme.Border, 1))
                    {
                        g.DrawLine(pen, 0, tabStripHeight, w - 1, tabStripHeight);
                        g.DrawLine(pen, 0, h - 1, w - 1, h - 1);
                        g.DrawLine(pen, 0, tabStripHeight, 0, h - 1);
                        g.DrawLine(pen, w - 1, tabStripHeight, w - 1, h - 1);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Subclasses a DropDownList ComboBox to paint its face with the dark theme
    /// background. Windows draws a white background on the combo face that
    /// BackColor/FlatStyle can't reliably override on modern Windows versions.
    /// </summary>
    internal class DarkComboBoxFixer : NativeWindow
    {
        private const int WM_PAINT = 0x000F;

        public DarkComboBoxFixer(ComboBox cb)
        {
            AssignHandle(cb.Handle);
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);

            if (m.Msg == WM_PAINT)
            {
                var cb = Control.FromHandle(m.HWnd) as ComboBox;
                if (cb == null || cb.DropDownStyle != ComboBoxStyle.DropDownList) return;

                using (var g = Graphics.FromHwnd(m.HWnd))
                {
                    int w = cb.ClientSize.Width;
                    int h = cb.ClientSize.Height;

                    // Leave the dropdown arrow area alone (rightmost scrollbar width)
                    int arrowWidth = SystemInformation.VerticalScrollBarWidth + 2;
                    int faceWidth = w - arrowWidth;

                    // Fill the combo face with dark background
                    using (var brush = new SolidBrush(DarkTheme.SurfaceElevated))
                        g.FillRectangle(brush, 0, 0, faceWidth, h);

                    // Draw border
                    using (var pen = new Pen(DarkTheme.Border))
                    {
                        g.DrawLine(pen, 0, 0, w - 1, 0);
                        g.DrawLine(pen, 0, h - 1, w - 1, h - 1);
                        g.DrawLine(pen, 0, 0, 0, h - 1);
                        g.DrawLine(pen, w - 1, 0, w - 1, h - 1);
                    }

                    // Re-draw the selected text
                    if (cb.SelectedIndex >= 0)
                    {
                        string text = cb.GetItemText(cb.SelectedItem);
                        var textRect = new Rectangle(6, 0, faceWidth - 12, h);
                        var format = new StringFormat { Alignment = StringAlignment.Near, LineAlignment = StringAlignment.Center };
                        using (var brush = new SolidBrush(DarkTheme.TextPrimary))
                            g.DrawString(text, cb.Font, brush, textRect, format);
                    }
                }
            }
        }
    }

    /// <summary>
    /// Subclasses a ComboBox's window procedure to apply dark theme to the
    /// dropdown listbox popup, which is a separate child HWND that doesn't
    /// inherit the parent's theme.
    /// </summary>
    internal class ComboBoxDropdownFixer : NativeWindow
    {
        private const int WM_CTLCOLORLISTBOX = 0x0134;
        private readonly ComboBox comboBox;
        private readonly HashSet<IntPtr> themedHandles = new HashSet<IntPtr>();

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        private static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string pszSubIdList);

        [DllImport("gdi32.dll")]
        private static extern int SetTextColor(IntPtr hdc, int crColor);

        [DllImport("gdi32.dll")]
        private static extern int SetBkColor(IntPtr hdc, int crColor);

        [DllImport("gdi32.dll")]
        private static extern int SetBkMode(IntPtr hdc, int iBkMode);

        [DllImport("gdi32.dll")]
        private static extern IntPtr CreateSolidBrush(int crColor);

        private static readonly IntPtr TRANSPARENT = new IntPtr(1);

        public ComboBoxDropdownFixer(ComboBox cb)
        {
            comboBox = cb;
            AssignHandle(cb.Handle);
        }

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == WM_CTLCOLORLISTBOX)
            {
                IntPtr listHwnd = m.LParam;

                // Apply dark theme to the dropdown listbox once
                if (!themedHandles.Contains(listHwnd))
                {
                    SetWindowTheme(listHwnd, "DarkMode_Explorer", null);
                    themedHandles.Add(listHwnd);
                }

                // Set text and background colors for the dropdown
                int textColor = (DarkTheme.TextPrimary.B << 16)
                              | (DarkTheme.TextPrimary.G << 8)
                              | DarkTheme.TextPrimary.R;
                int bgColor = (DarkTheme.Surface.B << 16)
                            | (DarkTheme.Surface.G << 8)
                            | DarkTheme.Surface.R;

                SetTextColor(m.WParam, textColor);
                SetBkColor(m.WParam, bgColor);
                SetBkMode(m.WParam, 1); // TRANSPARENT

                // Return a brush for the background
                m.Result = CreateSolidBrush(bgColor);
                return;
            }

            base.WndProc(ref m);
        }
    }
}
