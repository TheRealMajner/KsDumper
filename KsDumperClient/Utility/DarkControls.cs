using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace KsDumperClient.Utility
{
    /// <summary>
    /// Luxury dark-themed button with rounded corners, gradient fill, and glow effects.
    /// </summary>
    public class DarkButton : Button
    {
        private bool isHovered;
        private bool isPressed;
        private const int CornerRadius = 6;

        public DarkButton()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            FlatStyle = FlatStyle.Flat;
            FlatAppearance.BorderSize = 0;
            BackColor = Color.Transparent;
            ForeColor = DarkTheme.TextPrimary;
            Font = DarkTheme.UIFont;
            Cursor = Cursors.Hand;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = DarkControlsHelper.CreateRoundedRect(rect, CornerRadius))
            {
                // Fill gradient
                Color topColor = isPressed ? DarkTheme.SurfacePressed :
                                 isHovered ? DarkTheme.GradientTop : DarkTheme.SurfaceElevated;
                Color bottomColor = isPressed ? DarkTheme.Background :
                                    isHovered ? DarkTheme.Surface : DarkTheme.Surface;

                using (var brush = new LinearGradientBrush(rect, topColor, bottomColor, LinearGradientMode.Vertical))
                    g.FillPath(brush, path);

                // Border
                Color borderColor = isHovered ? DarkTheme.Accent : DarkTheme.Border;
                using (var pen = new Pen(borderColor, isHovered ? 1.5f : 1f))
                    g.DrawPath(pen, path);

                // Hover glow effect
                if (isHovered)
                {
                    using (var glowPath = DarkControlsHelper.CreateRoundedRect(new Rectangle(1, 1, Width - 3, Height - 3), CornerRadius - 1))
                    using (var pen = new Pen(Color.FromArgb(30, DarkTheme.Accent), 1f))
                        g.DrawPath(pen, glowPath);
                }
            }

            // Text
            var textRect = new Rectangle(0, 0, Width, Height);
            TextRenderer.DrawText(g, Text, Font, textRect, ForeColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }

        protected override void OnMouseEnter(EventArgs e) { isHovered = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { isHovered = false; isPressed = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnMouseDown(MouseEventArgs e) { isPressed = true; Invalidate(); base.OnMouseDown(e); }
        protected override void OnMouseUp(MouseEventArgs e) { isPressed = false; Invalidate(); base.OnMouseUp(e); }
    }

    /// <summary>
    /// Luxury dark-themed checkbox with custom painted check mark and accent glow.
    /// </summary>
    public class DarkCheckBox : CheckBox
    {
        private bool isHovered;
        private const int BoxSize = 16;
        private const int CornerRadius = 3;

        public DarkCheckBox()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            ForeColor = DarkTheme.TextPrimary;
            Font = DarkTheme.UIFont;
        }

        protected override void OnPaintBackground(PaintEventArgs e)
        {
            // Suppress native background — we paint it ourselves in OnPaint
        }

        private struct PAINTSTRUCT
        {
            public IntPtr hdc;
            public int fErase;
            public int rcPaint_left;
            public int rcPaint_top;
            public int rcPaint_right;
            public int rcPaint_bottom;
            public int fIncUpdate;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 32)]
            public byte[] rgbReserved;
        }

        [DllImport("user32.dll")]
        private static extern IntPtr BeginPaint(IntPtr hwnd, out PAINTSTRUCT lpPaint);

        [DllImport("user32.dll")]
        private static extern int EndPaint(IntPtr hwnd, ref PAINTSTRUCT lpPaint);

        protected override void WndProc(ref Message m)
        {
            if (m.Msg == 0x000F) // WM_PAINT
            {
                IntPtr hdc = BeginPaint(Handle, out PAINTSTRUCT ps);
                using (var g = Graphics.FromHdc(hdc))
                {
                    OnPaint(new PaintEventArgs(g, Rectangle.FromLTRB(ps.rcPaint_left, ps.rcPaint_top, ps.rcPaint_right, ps.rcPaint_bottom)));
                }
                EndPaint(Handle, ref ps);
                return;
            }
            base.WndProc(ref m);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            // Clear background
            using (var bgBrush = new SolidBrush(BackColor))
                g.FillRectangle(bgBrush, ClientRectangle);

            int padLeft = 2;
            int boxY = (Height - BoxSize) / 2;
            var boxRect = new Rectangle(padLeft, boxY, BoxSize, BoxSize);

            // Draw checkbox box
            using (var path = DarkControlsHelper.CreateRoundedRect(boxRect, CornerRadius))
            {
                Color fillColor = Checked ? DarkTheme.AccentSubtle : DarkTheme.SurfaceElevated;
                using (var brush = new SolidBrush(fillColor))
                    g.FillPath(brush, path);

                Color borderColor = isHovered || Checked ? DarkTheme.Accent : DarkTheme.Border;
                using (var pen = new Pen(borderColor, 1.2f))
                    g.DrawPath(pen, path);
            }

            // Draw checkmark
            if (Checked)
            {
                using (var pen = new Pen(DarkTheme.TextPrimary, 2f))
                {
                    pen.StartCap = LineCap.Round;
                    pen.EndCap = LineCap.Round;
                    g.DrawLine(pen, boxRect.X + 3, boxRect.Y + 8, boxRect.X + 7, boxRect.Y + 12);
                    g.DrawLine(pen, boxRect.X + 7, boxRect.Y + 12, boxRect.X + 13, boxRect.Y + 4);
                }
            }

            // Draw text
            int textX = padLeft + BoxSize + 6;
            var textRect = new Rectangle(textX, 0, Width - textX - 2, Height);
            TextRenderer.DrawText(g, Text, Font, textRect, ForeColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }

        protected override void OnMouseEnter(EventArgs e) { isHovered = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { isHovered = false; Invalidate(); base.OnMouseLeave(e); }
    }

    /// <summary>
    /// Luxury dark-themed panel with optional rounded corners and subtle border.
    /// </summary>
    public class DarkPanel : Panel
    {
        public int CornerRadius { get; set; } = 4;
        public bool DrawBorder { get; set; } = true;

        public DarkPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = DarkTheme.Surface;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            var rect = new Rectangle(0, 0, Width - 1, Height - 1);

            if (CornerRadius > 0)
            {
                using (var path = DarkControlsHelper.CreateRoundedRect(rect, CornerRadius))
                {
                    using (var brush = new SolidBrush(BackColor))
                        g.FillPath(brush, path);

                    if (DrawBorder)
                    {
                        using (var pen = new Pen(DarkTheme.BorderSubtle, 1f))
                            g.DrawPath(pen, path);
                    }

                    // Clip children to rounded area
                    Region = new Region(path);
                }
            }
            else
            {
                base.OnPaint(e);
                if (DrawBorder)
                {
                    using (var pen = new Pen(DarkTheme.BorderSubtle, 1f))
                        g.DrawRectangle(pen, rect);
                }
            }
        }
    }

    /// <summary>
    /// Luxury dark ComboBox with custom-painted dropdown arrow, rounded border, and focus glow.
    /// Completely replaces the native dropdown button rendering.
    /// </summary>
    public class DarkComboBox : ComboBox
    {
        private bool isHovered;
        private bool isFocused;
        private const int ArrowWidth = 24;
        private const int CornerRadius = 4;

        public DarkComboBox()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            DrawMode = DrawMode.OwnerDrawFixed;
            DropDownStyle = ComboBoxStyle.DropDownList;
            BackColor = DarkTheme.SurfaceElevated;
            ForeColor = DarkTheme.TextPrimary;
            Font = DarkTheme.UIFont;
            FlatStyle = FlatStyle.Flat;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = DarkControlsHelper.CreateRoundedRect(rect, CornerRadius))
            {
                // Fill background with subtle gradient
                using (var brush = new LinearGradientBrush(rect, DarkTheme.GradientTop, DarkTheme.SurfaceElevated, LinearGradientMode.Vertical))
                    g.FillPath(brush, path);

                // Border with focus glow
                Color borderColor = isFocused ? DarkTheme.Accent : (isHovered ? DarkTheme.Border : DarkTheme.BorderSubtle);
                using (var pen = new Pen(borderColor, isFocused ? 1.5f : 1f))
                    g.DrawPath(pen, path);

                // Focus glow
                if (isFocused)
                {
                    using (var glowPath = DarkControlsHelper.CreateRoundedRect(new Rectangle(-1, -1, Width + 1, Height + 1), CornerRadius + 1))
                    using (var pen = new Pen(Color.FromArgb(35, DarkTheme.Accent), 1f))
                        g.DrawPath(pen, glowPath);
                }
            }

            // Separator line before arrow area
            int arrowX = Width - ArrowWidth;
            using (var pen = new Pen(DarkTheme.BorderSubtle, 1f))
                g.DrawLine(pen, arrowX, 3, arrowX, Height - 4);

            // Hover highlight on arrow area
            if (isHovered)
            {
                var hoverRect = new Rectangle(arrowX + 1, 1, ArrowWidth - 2, Height - 3);
                using (var brush = new SolidBrush(Color.FromArgb(15, DarkTheme.Accent)))
                    g.FillRectangle(brush, hoverRect);
            }

            // Draw dropdown chevron (pointing down)
            int chevronX = arrowX + ArrowWidth / 2;
            int chevronY = Height / 2;
            Color chevronColor = isHovered ? DarkTheme.Accent : DarkTheme.TextSecondary;
            using (var pen = new Pen(chevronColor, 2f))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                g.DrawLine(pen, chevronX - 5, chevronY - 3, chevronX, chevronY + 2);
                g.DrawLine(pen, chevronX, chevronY + 2, chevronX + 5, chevronY - 3);
            }

            // Draw selected item text
            if (SelectedIndex >= 0)
            {
                string text = GetItemText(SelectedItem);
                var textRect = new Rectangle(8, 0, Width - ArrowWidth - 16, Height);
                TextRenderer.DrawText(g, text, Font, textRect, ForeColor,
                    TextFormatFlags.Left | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
            }
        }

        protected override void OnDrawItem(DrawItemEventArgs e)
        {
            if (e.Index < 0) return;

            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            bool isSelected = (e.State & DrawItemState.Selected) != 0;
            Color bgColor = isSelected ? Color.FromArgb(30, 56, 139, 253) : DarkTheme.Surface;
            Color fgColor = isSelected ? DarkTheme.TextPrimary : DarkTheme.TextSecondary;

            using (var brush = new SolidBrush(bgColor))
                g.FillRectangle(brush, e.Bounds);

            // Accent left bar on selected item
            if (isSelected)
            {
                var barRect = new Rectangle(e.Bounds.Left + 2, e.Bounds.Top + 3, 3, e.Bounds.Height - 6);
                using (var brush = new SolidBrush(DarkTheme.Accent))
                    g.FillRectangle(brush, barRect);
            }

            string text = GetItemText(Items[e.Index]);
            var textBounds = new Rectangle(e.Bounds.X + 8, e.Bounds.Y, e.Bounds.Width - 12, e.Bounds.Height);
            TextRenderer.DrawText(g, text, Font, textBounds, fgColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }

        protected override void OnMouseEnter(EventArgs e) { isHovered = true; Invalidate(); base.OnMouseEnter(e); }
        protected override void OnMouseLeave(EventArgs e) { isHovered = false; Invalidate(); base.OnMouseLeave(e); }
        protected override void OnGotFocus(EventArgs e) { isFocused = true; Invalidate(); base.OnGotFocus(e); }
        protected override void OnLostFocus(EventArgs e) { isFocused = false; Invalidate(); base.OnLostFocus(e); }
        protected override void OnSelectedIndexChanged(EventArgs e) { Invalidate(); base.OnSelectedIndexChanged(e); }
    }

    /// <summary>
    /// Luxury dark NumericUpDown with custom-painted arrows, rounded border, and focus glow.
    /// Completely replaces the native up/down button rendering.
    /// </summary>
    public class DarkNumericUpDown : NumericUpDown
    {
        private bool isHovered;
        private bool upHovered;
        private bool downHovered;
        private bool isFocused;
        private const int ArrowWidth = 20;
        private const int CornerRadius = 4;

        public DarkNumericUpDown()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            BackColor = DarkTheme.SurfaceElevated;
            ForeColor = DarkTheme.TextPrimary;
            Font = DarkTheme.UIFont;
            BorderStyle = BorderStyle.None;

            // Hide the native up/down buttons by making them invisible
            Controls[0].Visible = false;
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            var rect = new Rectangle(0, 0, Width - 1, Height - 1);
            using (var path = DarkControlsHelper.CreateRoundedRect(rect, CornerRadius))
            {
                // Fill background
                using (var brush = new SolidBrush(DarkTheme.SurfaceElevated))
                    g.FillPath(brush, path);

                // Border with focus glow
                Color borderColor = isFocused ? DarkTheme.Accent : (isHovered ? DarkTheme.Border : DarkTheme.BorderSubtle);
                using (var pen = new Pen(borderColor, isFocused ? 1.5f : 1f))
                    g.DrawPath(pen, path);

                // Focus glow
                if (isFocused)
                {
                    using (var glowPath = DarkControlsHelper.CreateRoundedRect(new Rectangle(-1, -1, Width + 1, Height + 1), CornerRadius + 1))
                    using (var pen = new Pen(Color.FromArgb(35, DarkTheme.Accent), 1f))
                        g.DrawPath(pen, glowPath);
                }
            }

            // Separator line before arrow area
            int arrowX = Width - ArrowWidth;
            using (var pen = new Pen(DarkTheme.BorderSubtle, 1f))
                g.DrawLine(pen, arrowX, 3, arrowX, Height - 4);

            // Draw UP arrow (chevron pointing up)
            int upCenterX = arrowX + ArrowWidth / 2;
            int upY = Height / 4;
            Color upColor = upHovered ? DarkTheme.Accent : DarkTheme.TextSecondary;
            using (var pen = new Pen(upColor, 1.8f))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                g.DrawLine(pen, upCenterX - 4, upY + 3, upCenterX, upY - 1);
                g.DrawLine(pen, upCenterX, upY - 1, upCenterX + 4, upY + 3);
            }

            // UP arrow hover background
            if (upHovered)
            {
                var upRect = new Rectangle(arrowX + 1, 1, ArrowWidth - 2, Height / 2 - 1);
                using (var brush = new SolidBrush(Color.FromArgb(20, DarkTheme.Accent)))
                    g.FillRectangle(brush, upRect);
            }

            // Draw DOWN arrow (chevron pointing down)
            int downY = Height * 3 / 4;
            Color downColor = downHovered ? DarkTheme.Accent : DarkTheme.TextSecondary;
            using (var pen = new Pen(downColor, 1.8f))
            {
                pen.StartCap = LineCap.Round;
                pen.EndCap = LineCap.Round;
                g.DrawLine(pen, downCenterX() - 4, downY - 3, downCenterX(), downY + 1);
                g.DrawLine(pen, downCenterX(), downY + 1, downCenterX() + 4, downY - 3);
            }

            // DOWN arrow hover background
            if (downHovered)
            {
                var downRect = new Rectangle(arrowX + 1, Height / 2, ArrowWidth - 2, Height / 2 - 1);
                using (var brush = new SolidBrush(Color.FromArgb(20, DarkTheme.Accent)))
                    g.FillRectangle(brush, downRect);
            }

            // Draw the value text
            string displayText = GetDisplayText();
            var textRect = new Rectangle(6, 0, Width - ArrowWidth - 12, Height);
            TextRenderer.DrawText(g, displayText, Font, textRect, ForeColor,
                TextFormatFlags.Left | TextFormatFlags.VerticalCenter);
        }

        private int downCenterX() => Width - ArrowWidth / 2;

        private string GetDisplayText()
        {
            if (Hexadecimal)
                return "0x" + ((long)Value).ToString("X");
            return Value.ToString();
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            int arrowX = Width - ArrowWidth;
            bool wasUp = upHovered;
            bool wasDown = downHovered;

            if (e.X >= arrowX)
            {
                upHovered = e.Y < Height / 2;
                downHovered = e.Y >= Height / 2;
            }
            else
            {
                upHovered = false;
                downHovered = false;
            }

            isHovered = true;
            if (wasUp != upHovered || wasDown != downHovered)
                Invalidate();
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            isHovered = false;
            upHovered = false;
            downHovered = false;
            Invalidate();
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            base.OnMouseDown(e);
            int arrowX = Width - ArrowWidth;
            if (e.X >= arrowX)
            {
                if (e.Y < Height / 2)
                {
                    // Up arrow clicked
                    if (Value + Increment <= Maximum)
                        Value += Increment;
                }
                else
                {
                    // Down arrow clicked
                    if (Value - Increment >= Minimum)
                        Value -= Increment;
                }
                Invalidate();
            }
            else
            {
                // Click on text area - focus for editing
                Focus();
                Select(0, Text.Length);
            }
        }

        protected override void OnMouseWheel(MouseEventArgs e)
        {
            if (e.Delta > 0 && Value + Increment <= Maximum)
                Value += Increment;
            else if (e.Delta < 0 && Value - Increment >= Minimum)
                Value -= Increment;
            Invalidate();
        }

        protected override void OnGotFocus(EventArgs e)
        {
            base.OnGotFocus(e);
            isFocused = true;
            Invalidate();
        }

        protected override void OnLostFocus(EventArgs e)
        {
            base.OnLostFocus(e);
            isFocused = false;
            Invalidate();
        }

        protected override void OnValueChanged(EventArgs e)
        {
            base.OnValueChanged(e);
            Invalidate();
        }

        // Override to prevent native button painting
        protected override void OnTextBoxTextChanged(object source, EventArgs e)
        {
            // Suppress - we draw our own text
        }
    }

    /// <summary>
    /// Shared helpers for luxury dark controls.
    /// </summary>
    public static class DarkControlsHelper
    {
        /// <summary>
        /// Safely invokes a delegate on the UI thread, checking for disposed controls.
        /// Prevents ObjectDisposedException when background tasks outlive their forms.
        /// </summary>
        public static void SafeInvoke(this Control control, Action action)
        {
            try
            {
                if (control != null && !control.IsDisposed && control.IsHandleCreated)
                    control.Invoke(action);
            }
            catch (ObjectDisposedException) { }
            catch (InvalidOperationException) { }
        }
        /// <summary>
        /// Creates a rounded rectangle GraphicsPath.
        /// </summary>
        public static GraphicsPath CreateRoundedRect(Rectangle rect, int radius)
        {
            var path = new GraphicsPath();
            if (radius <= 0)
            {
                path.AddRectangle(rect);
                return path;
            }

            int d = radius * 2;
            path.AddArc(rect.X, rect.Y, d, d, 180, 90);
            path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
            path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
            path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
            path.CloseFigure();
            return path;
        }

        /// <summary>
        /// Styles an existing Button with the luxury dark paint handler.
        /// Can be called on buttons created by factory methods.
        /// </summary>
        public static void StyleButton(Button btn)
        {
            btn.FlatStyle = FlatStyle.Flat;
            btn.FlatAppearance.BorderSize = 0;
            btn.BackColor = DarkTheme.SurfaceElevated;
            btn.ForeColor = DarkTheme.TextPrimary;
            btn.Font = DarkTheme.UIFont;
            btn.Cursor = Cursors.Hand;

            btn.Paint -= LuxuryButtonPaint;
            btn.Paint += LuxuryButtonPaint;
        }

        private static void LuxuryButtonPaint(object sender, PaintEventArgs e)
        {
            var btn = (Button)sender;
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            var rect = new Rectangle(0, 0, btn.Width - 1, btn.Height - 1);
            bool hovered = btn.ClientRectangle.Contains(btn.PointToClient(Control.MousePosition));
            bool pressed = Control.MouseButtons.HasFlag(MouseButtons.Left) && hovered;

            using (var path = CreateRoundedRect(rect, 5))
            {
                Color topColor = pressed ? DarkTheme.SurfacePressed :
                                 hovered ? DarkTheme.GradientTop : DarkTheme.SurfaceElevated;
                Color bottomColor = pressed ? DarkTheme.Background :
                                    hovered ? DarkTheme.Surface : DarkTheme.Surface;

                using (var brush = new LinearGradientBrush(rect, topColor, bottomColor, LinearGradientMode.Vertical))
                    g.FillPath(brush, path);

                Color borderColor = hovered ? DarkTheme.Accent : DarkTheme.Border;
                using (var pen = new Pen(borderColor, hovered ? 1.3f : 1f))
                    g.DrawPath(pen, path);
            }

            var textRect = new Rectangle(0, 0, btn.Width, btn.Height);
            TextRenderer.DrawText(g, btn.Text, btn.Font, textRect, btn.ForeColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }

        /// <summary>
        /// Styles an existing ComboBox with custom dropdown arrow painting.
        /// </summary>
        public static void StyleComboBox(ComboBox cb)
        {
            cb.Paint -= LuxuryComboPaint;
            cb.Paint += LuxuryComboPaint;
        }

        private static void LuxuryComboPaint(object sender, PaintEventArgs e)
        {
            var cb = (ComboBox)sender;
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            var rect = new Rectangle(0, 0, cb.Width - 1, cb.Height - 1);
            using (var path = CreateRoundedRect(rect, 4))
            {
                using (var brush = new SolidBrush(DarkTheme.SurfaceElevated))
                    g.FillPath(brush, path);

                using (var pen = new Pen(DarkTheme.Border, 1f))
                    g.DrawPath(pen, path);
            }

            // Custom dropdown arrow (chevron)
            if (cb.DropDownStyle == ComboBoxStyle.DropDownList)
            {
                int arrowX = cb.Width - 18;
                int arrowY = cb.Height / 2 - 2;
                using (var pen = new Pen(DarkTheme.TextSecondary, 1.5f))
                {
                    pen.StartCap = LineCap.Round;
                    pen.EndCap = LineCap.Round;
                    g.DrawLine(pen, arrowX, arrowY, arrowX + 4, arrowY + 4);
                    g.DrawLine(pen, arrowX + 4, arrowY + 4, arrowX + 8, arrowY);
                }
            }
        }
        /// <summary>
        /// Styles a NumericUpDown with luxury rounded border and focus glow.
        /// </summary>
        public static void StyleNumericUpDown(NumericUpDown nud)
        {
            nud.BackColor = DarkTheme.SurfaceElevated;
            nud.ForeColor = DarkTheme.TextPrimary;
            nud.Font = DarkTheme.UIFont;
            nud.BorderStyle = BorderStyle.None;

            // Paint rounded border on parent with focus glow
            nud.Paint -= LuxuryNumericPaint;
            nud.Paint += LuxuryNumericPaint;

            nud.GotFocus -= NumericFocusChanged;
            nud.LostFocus -= NumericFocusChanged;
            nud.GotFocus += NumericFocusChanged;
            nud.LostFocus += NumericFocusChanged;
        }

        private static void NumericFocusChanged(object sender, EventArgs e)
        {
            var nud = (NumericUpDown)sender;
            nud.Invalidate();
        }

        private static void LuxuryNumericPaint(object sender, PaintEventArgs e)
        {
            var nud = (NumericUpDown)sender;
            var g = e.Graphics;
            g.SmoothingMode = SmoothingMode.AntiAlias;

            var rect = new Rectangle(0, 0, nud.Width - 1, nud.Height - 1);
            using (var path = CreateRoundedRect(rect, 4))
            {
                using (var brush = new SolidBrush(DarkTheme.SurfaceElevated))
                    g.FillPath(brush, path);

                Color borderColor = nud.Focused ? DarkTheme.Accent : DarkTheme.Border;
                using (var pen = new Pen(borderColor, nud.Focused ? 1.5f : 1f))
                    g.DrawPath(pen, path);

                // Focus glow
                if (nud.Focused)
                {
                    using (var glowPath = CreateRoundedRect(new Rectangle(-1, -1, nud.Width + 1, nud.Height + 1), 5))
                    using (var pen = new Pen(Color.FromArgb(40, DarkTheme.Accent), 1f))
                        g.DrawPath(pen, glowPath);
                }
            }
        }
    }
}
