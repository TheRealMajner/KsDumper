namespace KsDumperClient
{
    partial class Dumper
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.toolStrip1 = new System.Windows.Forms.ToolStrip();
            this.refreshMenuBtn = new System.Windows.Forms.ToolStripButton();
            this.connectBtn = new System.Windows.Forms.ToolStripButton();
            this.searchTextBox = new System.Windows.Forms.ToolStripTextBox();
            this.hideSystemProcessMenuBtn = new System.Windows.Forms.ToolStripButton();
            this.logPanel = new System.Windows.Forms.Panel();
            this.logsTextBox = new System.Windows.Forms.RichTextBox();
            this.logHeaderLabel = new System.Windows.Forms.Label();
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.dumpMainModuleToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.dumpModulesToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.openInExplorerToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.processList = new KsDumperClient.Utility.ProcessListView();
            this.PIDHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.NameHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.PathHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.BaseAddressHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.EntryPointHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ImageSizeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ImageTypeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.StatusHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.IntegrityHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.toolStrip1.SuspendLayout();
            this.logPanel.SuspendLayout();
            this.contextMenuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // toolStrip1
            // 
            this.toolStrip1.AllowMerge = false;
            this.toolStrip1.AutoSize = false;
            this.toolStrip1.GripStyle = System.Windows.Forms.ToolStripGripStyle.Hidden;
            this.toolStrip1.ImageScalingSize = new System.Drawing.Size(20, 20);
            var searchLabel = new System.Windows.Forms.ToolStripLabel("Search");
            searchLabel.Alignment = System.Windows.Forms.ToolStripItemAlignment.Right;
            searchLabel.ForeColor = System.Drawing.Color.FromArgb(139, 148, 158);
            var listDriversBtn = new System.Windows.Forms.ToolStripButton("  List Drivers  ");
            listDriversBtn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            listDriversBtn.Margin = new System.Windows.Forms.Padding(0, 1, 4, 2);
            listDriversBtn.Click += new System.EventHandler(this.listDriversBtn_Click);

            var autoDumpBtn = new System.Windows.Forms.ToolStripButton("  Auto Dump  ");
            autoDumpBtn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            autoDumpBtn.Margin = new System.Windows.Forms.Padding(0, 1, 4, 2);
            autoDumpBtn.Click += new System.EventHandler(this.autoDumpBtn_Click);

            var servicesBtn = new System.Windows.Forms.ToolStripButton("  Services  ");
            servicesBtn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            servicesBtn.Margin = new System.Windows.Forms.Padding(0, 1, 4, 2);
            servicesBtn.Click += new System.EventHandler(this.servicesBtn_Click);

            var peViewerBtn = new System.Windows.Forms.ToolStripButton("  PE Viewer  ");
            peViewerBtn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            peViewerBtn.Margin = new System.Windows.Forms.Padding(0, 1, 4, 2);
            peViewerBtn.Click += (s, ev) => new PEViewerWindow().Show();

            var processTreeBtn = new System.Windows.Forms.ToolStripButton("  Process Tree  ");
            processTreeBtn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            processTreeBtn.Margin = new System.Windows.Forms.Padding(0, 1, 4, 2);
            processTreeBtn.Click += (s, ev) => new ProcessTreeView(driver).Show();

            this.toolStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.refreshMenuBtn,
            this.connectBtn,
            new System.Windows.Forms.ToolStripSeparator(),
            this.hideSystemProcessMenuBtn,
            new System.Windows.Forms.ToolStripSeparator(),
            listDriversBtn,
            autoDumpBtn,
            servicesBtn,
            peViewerBtn,
            processTreeBtn,
            searchLabel,
            this.searchTextBox});
            this.toolStrip1.Location = new System.Drawing.Point(0, 0);
            this.toolStrip1.Name = "toolStrip1";
            this.toolStrip1.Padding = new System.Windows.Forms.Padding(8, 4, 8, 4);
            this.toolStrip1.ShowItemToolTips = false;
            this.toolStrip1.Size = new System.Drawing.Size(1068, 36);
            this.toolStrip1.TabIndex = 4;
            this.toolStrip1.Text = "toolStrip1";
            // 
            // refreshMenuBtn
            // 
            this.refreshMenuBtn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.refreshMenuBtn.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.refreshMenuBtn.Margin = new System.Windows.Forms.Padding(0, 1, 4, 2);
            this.refreshMenuBtn.Name = "refreshMenuBtn";
            this.refreshMenuBtn.Size = new System.Drawing.Size(58, 28);
            this.refreshMenuBtn.Text = "  Refresh  ";
            this.refreshMenuBtn.Click += new System.EventHandler(this.refreshMenuBtn_Click);
            // 
            // connectBtn
            // 
            this.connectBtn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.connectBtn.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.connectBtn.Margin = new System.Windows.Forms.Padding(0, 1, 4, 2);
            this.connectBtn.Name = "connectBtn";
            this.connectBtn.Size = new System.Drawing.Size(62, 28);
            this.connectBtn.Text = "  Connect  ";
            this.connectBtn.Click += new System.EventHandler(this.connectBtn_Click);
            // 
            // searchTextBox
            // 
            this.searchTextBox.Alignment = System.Windows.Forms.ToolStripItemAlignment.Right;
            this.searchTextBox.AutoSize = false;
            this.searchTextBox.Name = "searchTextBox";
            this.searchTextBox.Size = new System.Drawing.Size(200, 26);
            this.searchTextBox.TextBoxTextAlign = System.Windows.Forms.HorizontalAlignment.Left;
            this.searchTextBox.TextChanged += new System.EventHandler(this.searchTextBox_TextChanged);
            // 
            // hideSystemProcessMenuBtn
            // 
            this.hideSystemProcessMenuBtn.Alignment = System.Windows.Forms.ToolStripItemAlignment.Right;
            this.hideSystemProcessMenuBtn.DisplayStyle = System.Windows.Forms.ToolStripItemDisplayStyle.Text;
            this.hideSystemProcessMenuBtn.ImageTransparentColor = System.Drawing.Color.Magenta;
            this.hideSystemProcessMenuBtn.Margin = new System.Windows.Forms.Padding(0, 1, 8, 2);
            this.hideSystemProcessMenuBtn.Name = "hideSystemProcessMenuBtn";
            this.hideSystemProcessMenuBtn.Size = new System.Drawing.Size(142, 28);
            this.hideSystemProcessMenuBtn.Text = "  Show System Processes  ";
            this.hideSystemProcessMenuBtn.Click += new System.EventHandler(this.hideSystemProcessMenuBtn_Click);
            // 
            // logPanel
            // 
            this.logPanel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom |
            System.Windows.Forms.AnchorStyles.Left) | System.Windows.Forms.AnchorStyles.Right)));
            this.logPanel.Controls.Add(this.logsTextBox);
            this.logPanel.Controls.Add(this.logHeaderLabel);
            this.logPanel.Location = new System.Drawing.Point(8, 556);
            this.logPanel.Name = "logPanel";
            this.logPanel.Padding = new System.Windows.Forms.Padding(0);
            this.logPanel.Size = new System.Drawing.Size(1052, 192);
            this.logPanel.TabIndex = 5;
            // 
            // logHeaderLabel
            // 
            this.logHeaderLabel.Dock = System.Windows.Forms.DockStyle.Top;
            this.logHeaderLabel.Location = new System.Drawing.Point(0, 0);
            this.logHeaderLabel.Name = "logHeaderLabel";
            this.logHeaderLabel.Size = new System.Drawing.Size(1052, 28);
            this.logHeaderLabel.TabIndex = 1;
            this.logHeaderLabel.Text = "   Output Log";
            this.logHeaderLabel.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // logsTextBox
            // 
            this.logsTextBox.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.logsTextBox.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.logsTextBox.Location = new System.Drawing.Point(0, 28);
            this.logsTextBox.Name = "logsTextBox";
            this.logsTextBox.ReadOnly = true;
            this.logsTextBox.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.Vertical;
            this.logsTextBox.Size = new System.Drawing.Size(1052, 164);
            this.logsTextBox.TabIndex = 0;
            this.logsTextBox.Text = "";
            this.logsTextBox.TextChanged += new System.EventHandler(this.logsTextBox_TextChanged);
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.dumpMainModuleToolStripMenuItem,
            this.dumpModulesToolStripMenuItem,
            this.toolStripSeparator1,
            this.openInExplorerToolStripMenuItem});
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(196, 82);
            this.contextMenuStrip1.Opening += new System.ComponentModel.CancelEventHandler(this.contextMenuStrip1_Opening);
            // 
            // dumpMainModuleToolStripMenuItem
            // 
            this.dumpMainModuleToolStripMenuItem.Name = "dumpMainModuleToolStripMenuItem";
            this.dumpMainModuleToolStripMenuItem.Size = new System.Drawing.Size(195, 24);
            this.dumpMainModuleToolStripMenuItem.Text = "Dump Main Module";
            this.dumpMainModuleToolStripMenuItem.Click += new System.EventHandler(this.dumpMainModuleToolStripMenuItem_Click);
            // 
            // dumpModulesToolStripMenuItem
            // 
            this.dumpModulesToolStripMenuItem.Name = "dumpModulesToolStripMenuItem";
            this.dumpModulesToolStripMenuItem.Size = new System.Drawing.Size(195, 24);
            this.dumpModulesToolStripMenuItem.Text = "Dump Modules...";
            this.dumpModulesToolStripMenuItem.Click += new System.EventHandler(this.dumpModulesToolStripMenuItem_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(192, 6);
            // 
            // openInExplorerToolStripMenuItem
            // 
            this.openInExplorerToolStripMenuItem.Name = "openInExplorerToolStripMenuItem";
            this.openInExplorerToolStripMenuItem.Size = new System.Drawing.Size(195, 24);
            this.openInExplorerToolStripMenuItem.Text = "Open In Explorer";
            this.openInExplorerToolStripMenuItem.Click += new System.EventHandler(this.openInExplorerToolStripMenuItem_Click);
            // 
            // processList
            // 
            this.processList.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top |
            System.Windows.Forms.AnchorStyles.Bottom) | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.processList.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.processList.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.PIDHeader,
            this.NameHeader,
            this.PathHeader,
            this.BaseAddressHeader,
            this.EntryPointHeader,
            this.ImageSizeHeader,
            this.ImageTypeHeader,
            this.StatusHeader,
            this.IntegrityHeader});
            this.processList.ContextMenuStrip = this.contextMenuStrip1;
            this.processList.FullRowSelect = true;
            this.processList.Location = new System.Drawing.Point(8, 42);
            this.processList.MultiSelect = false;
            this.processList.Name = "processList";
            this.processList.Size = new System.Drawing.Size(1052, 506);
            this.processList.TabIndex = 2;
            this.processList.UseCompatibleStateImageBehavior = false;
            this.processList.View = System.Windows.Forms.View.Details;
            // 
            // PIDHeader
            // 
            this.PIDHeader.Text = "PID";
            this.PIDHeader.Width = 72;
            // 
            // NameHeader
            // 
            this.NameHeader.Text = "Process Name";
            this.NameHeader.Width = 160;
            // 
            // PathHeader
            // 
            this.PathHeader.Text = "Path";
            this.PathHeader.Width = 380;
            // 
            // BaseAddressHeader
            // 
            this.BaseAddressHeader.Text = "Base Address";
            this.BaseAddressHeader.Width = 108;
            // 
            // EntryPointHeader
            // 
            this.EntryPointHeader.Text = "Entry Point";
            this.EntryPointHeader.Width = 108;
            // 
            // ImageSizeHeader
            // 
            this.ImageSizeHeader.Text = "Image Size";
            this.ImageSizeHeader.Width = 92;
            // 
            // ImageTypeHeader
            // 
            this.ImageTypeHeader.Text = "Arch";
            this.ImageTypeHeader.Width = 64;
            //
            // StatusHeader
            //
            this.StatusHeader.Text = "Status";
            this.StatusHeader.Width = 160;
            //
            // IntegrityHeader
            //
            this.IntegrityHeader.Text = "Integrity";
            this.IntegrityHeader.Width = 80;
            // 
            // Dumper
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = Utility.DarkTheme.Background;
            this.ForeColor = Utility.DarkTheme.TextPrimary;
            this.Padding = System.Windows.Forms.Padding.Empty;
            this.ClientSize = new System.Drawing.Size(1068, 756);
            this.Controls.Add(this.logPanel);
            this.Controls.Add(this.toolStrip1);
            this.Controls.Add(this.processList);
            this.MinimumSize = new System.Drawing.Size(800, 600);
            try { this.Icon = Utility.AppIcon.Get(); } catch { }
            this.Name = "Dumper";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "KsDumper";
            this.Load += new System.EventHandler(this.Dumper_Load);
            this.toolStrip1.ResumeLayout(false);
            this.toolStrip1.PerformLayout();
            this.logPanel.ResumeLayout(false);
            this.contextMenuStrip1.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        #endregion
        private KsDumperClient.Utility.ProcessListView processList;
        private System.Windows.Forms.ColumnHeader PIDHeader;
        private System.Windows.Forms.ColumnHeader NameHeader;
        private System.Windows.Forms.ColumnHeader PathHeader;
        private System.Windows.Forms.ColumnHeader BaseAddressHeader;
        private System.Windows.Forms.ColumnHeader EntryPointHeader;
        private System.Windows.Forms.ColumnHeader ImageSizeHeader;
        private System.Windows.Forms.ColumnHeader ImageTypeHeader;
        private System.Windows.Forms.ColumnHeader StatusHeader;
        private System.Windows.Forms.ColumnHeader IntegrityHeader;
        private System.Windows.Forms.ToolStrip toolStrip1;
        private System.Windows.Forms.ToolStripButton refreshMenuBtn;
        private System.Windows.Forms.ToolStripButton connectBtn;
        private System.Windows.Forms.ToolStripButton hideSystemProcessMenuBtn;
        private System.Windows.Forms.ToolStripTextBox searchTextBox;
        private System.Windows.Forms.Panel logPanel;
        private System.Windows.Forms.RichTextBox logsTextBox;
        private System.Windows.Forms.Label logHeaderLabel;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem dumpMainModuleToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem dumpModulesToolStripMenuItem;
        private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
        private System.Windows.Forms.ToolStripMenuItem openInExplorerToolStripMenuItem;
    }
}
