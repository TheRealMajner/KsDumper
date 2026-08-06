using System;
using System.Collections.Generic;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.ReClass;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    public class ReClassWindow : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private TextBox addressBox;
        private Button goBtn;
        private Button saveBtn;
        private Button loadBtn;
        private NumericUpDown refreshInterval;
        private CheckBox autoRefreshChk;
        private Label statusLbl;

        private DoubleBufferedPanel viewPanel;
        private VScrollBar scrollBar;
        private NodeRenderer renderer;
        private ClassNode rootNode;
        private MemoryNode selectedNode;
        private ulong baseAddress;
        private int scrollOffset;

        private System.Windows.Forms.Timer refreshTimer;
        private TextBox editBox;

        public ReClassWindow(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            renderer = new NodeRenderer();
            rootNode = new ClassNode("Root");
            InitializeComponent();
            RefreshView();
        }

        private void InitializeComponent()
        {
            Text = $"ReClass Memory View - {processName} (PID: {processId})";
            Size = new Size(1050, 700);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };

            toolbar.Controls.Add(MakeLabel("Address:"));
            addressBox = new TextBox { Width = 160, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.None };
            addressBox.Text = "0x0";
            addressBox.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) GoToAddress(); };
            toolbar.Controls.Add(addressBox);

            goBtn = MakeButton("Go", 40);
            goBtn.Click += (s, e) => GoToAddress();
            toolbar.Controls.Add(goBtn);

            toolbar.Controls.Add(MakeSpacer(16));

            refreshInterval = new NumericUpDown { Width = 60, Minimum = 50, Maximum = 10000, Value = 500, Increment = 50, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.None, Font = DarkTheme.UIFont };
            toolbar.Controls.Add(refreshInterval);
            toolbar.Controls.Add(MakeLabel("ms"));

            autoRefreshChk = new CheckBox { Text = "Auto", ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont, Checked = true, AutoSize = true };
            autoRefreshChk.CheckedChanged += (s, e) => UpdateTimer();
            toolbar.Controls.Add(autoRefreshChk);

            toolbar.Controls.Add(MakeSpacer(16));

            saveBtn = MakeButton("Save", 50);
            saveBtn.Click += Save_Click;
            toolbar.Controls.Add(saveBtn);

            loadBtn = MakeButton("Load", 50);
            loadBtn.Click += Load_Click;
            toolbar.Controls.Add(loadBtn);

            toolbar.Controls.Add(MakeSpacer(16));

            var addBtn = MakeButton("+ Add Node", 80);
            addBtn.Click += (s, e) => ShowAddNodeMenu(addBtn);
            toolbar.Controls.Add(addBtn);

            statusLbl = new Label { Text = $"PID: {processId}", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.Add(statusLbl);

            Controls.Add(toolbar);

            // Main view area with scrollbar
            var viewContainer = new Panel { Dock = DockStyle.Fill, BackColor = DarkTheme.Background };

            scrollBar = new VScrollBar { Dock = DockStyle.Right, Width = 16 };
            scrollBar.Scroll += (s, e) => { scrollOffset = scrollBar.Value; viewPanel.Invalidate(); };
            viewContainer.Controls.Add(scrollBar);

            viewPanel = new DoubleBufferedPanel();
            viewPanel.Dock = DockStyle.Fill;
            viewPanel.BackColor = DarkTheme.Background;
            viewPanel.Paint += ViewPanel_Paint;
            viewPanel.MouseDown += ViewPanel_MouseDown;
            viewPanel.MouseDoubleClick += ViewPanel_MouseDoubleClick;
            viewPanel.MouseWheel += ViewPanel_MouseWheel;
            viewContainer.Controls.Add(viewPanel);

            Controls.Add(viewContainer);

            // Context menu
            var ctx = new ContextMenuStrip();
            ctx.Renderer = new ToolStripProfessionalRenderer();
            ctx.BackColor = DarkTheme.Surface;
            ctx.ForeColor = DarkTheme.TextPrimary;

            var changeTypeMenu = new ToolStripMenuItem("Change Type");
            foreach (var typeName in StructureDefinition.AllTypes)
            {
                var item = new ToolStripMenuItem(typeName);
                item.Click += (s, e) => ChangeSelectedNodeType(typeName);
                changeTypeMenu.DropDownItems.Add(item);
            }
            ctx.Items.Add(changeTypeMenu);
            ctx.Items.Add(new ToolStripSeparator());

            var insertItem = new ToolStripMenuItem("Insert Node Below");
            foreach (var typeName in StructureDefinition.AllTypes)
            {
                var item = new ToolStripMenuItem(typeName);
                var tn = typeName;
                item.Click += (s, e) => InsertNodeBelow(tn);
                insertItem.DropDownItems.Add(item);
            }
            ctx.Items.Add(insertItem);

            ctx.Items.Add("Delete Node", null, (s, e) => DeleteSelectedNode());
            ctx.Items.Add("Rename", null, (s, e) => RenameSelectedNode());
            ctx.Items.Add(new ToolStripSeparator());
            ctx.Items.Add("Copy Address", null, (s, e) =>
            {
                if (selectedNode != null) Clipboard.SetText("0x" + selectedNode.ResolvedAddress.ToString("X"));
            });
            ctx.Items.Add("Copy Value", null, (s, e) =>
            {
                if (selectedNode != null) Clipboard.SetText(selectedNode.FormatValue());
            });

            viewPanel.ContextMenuStrip = ctx;

            // Edit textbox (hidden by default, shown on double-click of value column)
            editBox = new TextBox { Visible = false, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.Accent, BorderStyle = BorderStyle.FixedSingle };
            editBox.KeyDown += EditBox_KeyDown;
            editBox.LostFocus += (s, e) => CommitEdit();
            viewPanel.Controls.Add(editBox);

            // Refresh timer
            refreshTimer = new System.Windows.Forms.Timer();
            refreshTimer.Tick += (s, e) => RefreshView();
            UpdateTimer();

            DarkTheme.ApplyTo(this);
            FormClosing += (s, e) => { refreshTimer?.Stop(); };
        }

        private void GoToAddress()
        {
            string text = addressBox.Text.Trim().Replace("0x", "").Replace("0X", "");
            if (ulong.TryParse(text, System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
            {
                baseAddress = addr;
                RefreshView();
            }
        }

        private void RefreshView()
        {
            if (rootNode.Children != null && rootNode.Children.Count > 0)
            {
                ReadAllNodes(rootNode);
            }
            UpdateScrollBar();
            viewPanel.Invalidate();
        }

        private void ReadAllNodes(MemoryNode node)
        {
            if (node is ClassNode cn)
            {
                cn.ReadMemory(driver, processId, baseAddress);
            }
            else
            {
                node.ReadMemory(driver, processId, baseAddress);
            }
        }

        private void UpdateScrollBar()
        {
            int totalHeight = renderer.GetTotalHeight(rootNode);
            int viewHeight = viewPanel.Height;

            if (totalHeight > viewHeight)
            {
                scrollBar.Visible = true;
                scrollBar.Minimum = 0;
                scrollBar.Maximum = totalHeight;
                scrollBar.LargeChange = Math.Max(1, viewHeight);
                scrollBar.SmallChange = NodeRenderer.RowHeight;
                if (scrollOffset > scrollBar.Maximum - scrollBar.LargeChange)
                    scrollOffset = Math.Max(0, scrollBar.Maximum - scrollBar.LargeChange);
                scrollBar.Value = scrollOffset;
            }
            else
            {
                scrollBar.Visible = false;
                scrollOffset = 0;
            }
        }

        private void ViewPanel_Paint(object sender, PaintEventArgs e)
        {
            var g = e.Graphics;
            g.TextRenderingHint = System.Drawing.Text.TextRenderingHint.ClearTypeGridFit;

            int width = viewPanel.Width - (scrollBar.Visible ? scrollBar.Width : 0);
            renderer.DrawHeader(g, width);
            renderer.Render(g, rootNode, viewPanel.ClientRectangle, scrollOffset, width, selectedNode);
        }

        private void ViewPanel_MouseDown(object sender, MouseEventArgs e)
        {
            var hit = renderer.HitTest(rootNode, e.Location, scrollOffset);

            if (hit.Area == HitArea.Toggle && hit.Node != null)
            {
                hit.Node.IsExpanded = !hit.Node.IsExpanded;
                viewPanel.Invalidate();
                return;
            }

            if (hit.Node != null)
            {
                selectedNode = hit.Node;
                viewPanel.Invalidate();

                if (e.Button == MouseButtons.Right)
                {
                    viewPanel.ContextMenuStrip?.Show(viewPanel, e.Location);
                }
            }
        }

        private void ViewPanel_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            var hit = renderer.HitTest(rootNode, e.Location, scrollOffset);

            if (hit.Node != null && hit.Area == HitArea.Value)
            {
                selectedNode = hit.Node;
                ShowEditBox(hit);
            }
        }

        private void ShowEditBox(HitTestResult hit)
        {
            if (selectedNode == null) return;

            int valueColumnX = 4 + NodeRenderer.OffsetColumnWidth + NodeRenderer.AddressColumnWidth + NodeRenderer.HexColumnWidth;
            editBox.Location = new Point(valueColumnX, hit.RowY - scrollOffset);
            editBox.Width = NodeRenderer.ValueColumnWidth;
            editBox.Height = NodeRenderer.RowHeight;
            editBox.Text = selectedNode.FormatValue().Replace("\"", "");
            editBox.Visible = true;
            editBox.Focus();
            editBox.SelectAll();
        }

        private void EditBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.KeyCode == Keys.Enter)
            {
                CommitEdit();
                e.Handled = true;
                e.SuppressKeyPress = true;
            }
            else if (e.KeyCode == Keys.Escape)
            {
                editBox.Visible = false;
                e.Handled = true;
                e.SuppressKeyPress = true;
            }
        }

        private void CommitEdit()
        {
            if (selectedNode == null || !editBox.Visible) return;
            editBox.Visible = false;

            byte[] data = selectedNode.ParseInput(editBox.Text);
            if (data != null)
            {
                selectedNode.WriteMemory(driver, processId, baseAddress, data);
                RefreshView();
            }
        }

        private void ViewPanel_MouseWheel(object sender, MouseEventArgs e)
        {
            scrollOffset -= e.Delta / 3;
            if (scrollOffset < 0) scrollOffset = 0;
            int maxScroll = Math.Max(0, renderer.GetTotalHeight(rootNode) - viewPanel.Height);
            if (scrollOffset > maxScroll) scrollOffset = maxScroll;
            if (scrollBar.Visible) scrollBar.Value = scrollOffset;
            viewPanel.Invalidate();
        }

        private void ChangeSelectedNodeType(string typeName)
        {
            if (selectedNode == null || selectedNode.Parent == null) return;

            var newNode = StructureDefinition.CreateNodeFromType(typeName);
            if (selectedNode.Parent is ClassNode cn)
            {
                cn.ReplaceNode(selectedNode, newNode);
            }
            selectedNode = newNode;
            RefreshView();
        }

        private void InsertNodeBelow(string typeName)
        {
            if (selectedNode == null || selectedNode.Parent == null) return;

            var newNode = StructureDefinition.CreateNodeFromType(typeName);
            newNode.Name = "field";

            if (selectedNode.Parent is ClassNode cn)
            {
                int idx = cn.Children.IndexOf(selectedNode);
                cn.InsertNode(idx + 1, newNode);
            }
            else if (selectedNode.Parent is PointerNode pn)
            {
                pn.AddChild(newNode);
            }
            selectedNode = newNode;
            RefreshView();
        }

        private void DeleteSelectedNode()
        {
            if (selectedNode == null || selectedNode.Parent == null) return;

            if (selectedNode.Parent is ClassNode cn)
                cn.RemoveNode(selectedNode);
            else if (selectedNode.Parent is PointerNode pn)
                pn.RemoveChild(selectedNode);

            selectedNode = null;
            RefreshView();
        }

        private void RenameSelectedNode()
        {
            if (selectedNode == null) return;
            string newName = ShowInputDialog("Rename Node", "New name:", selectedNode.Name);
            if (newName != null)
            {
                selectedNode.Name = newName;
                viewPanel.Invalidate();
            }
        }

        private void ShowAddNodeMenu(Control anchor)
        {
            var menu = new ContextMenuStrip();
            menu.Renderer = new ToolStripProfessionalRenderer();
            menu.BackColor = DarkTheme.Surface;
            menu.ForeColor = DarkTheme.TextPrimary;

            foreach (var typeName in StructureDefinition.AllTypes)
            {
                var item = new ToolStripMenuItem(typeName);
                var tn = typeName;
                item.Click += (s, e) =>
                {
                    var newNode = StructureDefinition.CreateNodeFromType(tn);
                    newNode.Name = "field";
                    rootNode.AddNode(newNode);
                    selectedNode = newNode;
                    RefreshView();
                };
                menu.Items.Add(item);
            }

            menu.Show(anchor, new Point(0, anchor.Height));
        }

        private void Save_Click(object sender, EventArgs e)
        {
            using (var sfd = new SaveFileDialog())
            {
                sfd.Filter = "ReClass XML|*.xml|All Files|*.*";
                sfd.FileName = "structure.xml";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        StructureDefinition.Save(rootNode, sfd.FileName);
                        statusLbl.Text = $"Saved: {System.IO.Path.GetFileName(sfd.FileName)}";
                    }
                    catch (Exception ex)
                    {
                        statusLbl.Text = $"Save error: {ex.Message}";
                    }
                }
            }
        }

        private void Load_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog())
            {
                ofd.Filter = "ReClass XML|*.xml|All Files|*.*";
                if (ofd.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        var loaded = StructureDefinition.Load(ofd.FileName);
                        if (loaded is ClassNode cn)
                        {
                            rootNode = cn;
                            selectedNode = null;
                            RefreshView();
                            statusLbl.Text = $"Loaded: {System.IO.Path.GetFileName(ofd.FileName)}";
                        }
                    }
                    catch (Exception ex)
                    {
                        statusLbl.Text = $"Load error: {ex.Message}";
                    }
                }
            }
        }

        private void UpdateTimer()
        {
            refreshTimer.Interval = (int)refreshInterval.Value;
            refreshTimer.Enabled = autoRefreshChk.Checked;
        }

        private string ShowInputDialog(string title, string prompt, string defaultValue)
        {
            var form = new Form { Text = title, Width = 350, Height = 150, StartPosition = FormStartPosition.CenterParent, BackColor = DarkTheme.Background, FormBorderStyle = FormBorderStyle.FixedDialog, MaximizeBox = false, MinimizeBox = false };
            var lbl = new Label { Text = prompt, Left = 12, Top = 12, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont, AutoSize = true };
            var txt = new TextBox { Text = defaultValue, Left = 12, Top = 36, Width = 310, Font = DarkTheme.UIFont, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.None };
            var ok = new Button { Text = "OK", Left = 160, Top = 72, Width = 70, BackColor = DarkTheme.AccentSubtle, ForeColor = Color.White, FlatStyle = FlatStyle.Flat };
            var cancel = new Button { Text = "Cancel", Left = 240, Top = 72, Width = 70, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, FlatStyle = FlatStyle.Flat };
            ok.Click += (s, e) => { form.DialogResult = DialogResult.OK; form.Close(); };
            cancel.Click += (s, e) => { form.DialogResult = DialogResult.Cancel; form.Close(); };
            form.Controls.AddRange(new Control[] { lbl, txt, ok, cancel });
            form.AcceptButton = ok;
            form.CancelButton = cancel;
            return form.ShowDialog() == DialogResult.OK ? txt.Text : null;
        }

        private Button MakeButton(string text, int width)
        {
            var b = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0), FlatStyle = FlatStyle.Flat, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont };
            b.FlatAppearance.BorderSize = 0;
            return b;
        }

        private Label MakeLabel(string text) => new Label { Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
        private Control MakeSpacer(int width) => new Control { Width = width, Height = 1 };
    }

    /// <summary>
    /// Double-buffered panel to eliminate flicker during custom rendering.
    /// </summary>
    public class DoubleBufferedPanel : Panel
    {
        public DoubleBufferedPanel()
        {
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint |
                     ControlStyles.OptimizedDoubleBuffer | ControlStyles.ResizeRedraw, true);
            UpdateStyles();
        }
    }
}
