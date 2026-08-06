using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;
using static KsDumperClient.Utility.WinApi;

namespace KsDumperClient
{
    public class ProcessAttachWindow : Form
    {
        public enum AttachMethod
        {
            Standard,
            Minimal,
            Debug,
            SuspendFirst,
            Kernel
        }

        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;
        private readonly AttachMethod attachMethod;
        private IntPtr processHandle = IntPtr.Zero;

        private TabControl tabControl;
        private ListView threadList;
        private RichTextBox memoryView;
        private TextBox addressBox;
        private TextBox sizeBox;
        private Button readMemBtn;
        private Button writeMemBtn;
        private TextBox writeValueBox;
        private Label statusLbl;
        private Label infoLbl;
        private RichTextBox logBox;
        private ListView memoryMapList;
        private TextBox injectPathBox;
        private Button injectBtn;
        private Button browseInjectBtn;

        // Debugger controls
        private CheckBox debuggerCheck;
        private ComboBox debugModeCombo;
        private Button debugAttachBtn;
        private DebugAttachEngine debugEngine;

        public ProcessAttachWindow(IMemoryReader driver, int processId, string processName, AttachMethod method = AttachMethod.Standard)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            this.attachMethod = method;
            InitializeComponent();
            AttachToProcess();
        }

        private void InitializeComponent()
        {
            Text = $"Attach [{attachMethod}] - {processName} (PID: {processId})";
            Size = new Size(1100, 750);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(900, 600);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            Padding = Padding.Empty;
            try { Icon = AppIcon.Get(); } catch { }

            // ===================== TOP BAR =====================
            var topPanel = new Panel { Dock = DockStyle.Top, Height = 50, BackColor = DarkTheme.Surface, Padding = new Padding(12, 0, 12, 0) };
            infoLbl = new Label
            {
                Location = new Point(12, 8), AutoSize = true,
                ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFontBold
            };
            statusLbl = new Label
            {
                Location = new Point(12, 28), AutoSize = true,
                ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontSmall
            };
            topPanel.Controls.AddRange(new Control[] { infoLbl, statusLbl });

            // Debugger controls (right side of top bar)
            debuggerCheck = new CheckBox
            {
                Text = "Debugger:", Location = new Point(580, 6), AutoSize = true,
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont
            };

            debugModeCombo = new DarkComboBox { Location = new Point(660, 4), Width = 150 };
            debugModeCombo.Items.AddRange(new object[] { "Standard", "Stealth", "VEH", "Hardware BP", "Kernel (Driver)" });
            debugModeCombo.SelectedIndex = 0;

            debugAttachBtn = new Button { Text = "Attach", Location = new Point(820, 3), Size = new Size(70, 26) };
            DarkControlsHelper.StyleButton(debugAttachBtn);

            debuggerCheck.CheckedChanged += DebuggerCheck_Changed;
            debugAttachBtn.Click += DebugAttach_Click;

            topPanel.Controls.AddRange(new Control[] { debuggerCheck, debugModeCombo, debugAttachBtn });

            // ===================== BOTTOM LOG =====================
            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 130, BackColor = DarkTheme.Surface };
            var logLabel = new Label
            {
                Text = "   Output", Dock = DockStyle.Top, Height = 24,
                TextAlign = ContentAlignment.MiddleLeft,
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold,
                BackColor = DarkTheme.SurfaceElevated
            };
            logBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            // ===================== TAB CONTROL =====================
            tabControl = new TabControl { Dock = DockStyle.Fill, Font = DarkTheme.UIFont, Padding = new Point(10, 5), BackColor = DarkTheme.Background };

            // ===================== THREADS TAB =====================
            var threadsPage = new TabPage("Threads") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            threadList = CreateListView();
            threadList.Sorting = SortOrder.None;
            threadList.Columns.Add("TID", 80);
            threadList.Columns.Add("Priority", 65);
            threadList.Columns.Add("Start Address", 140);
            threadList.Columns.Add("State", 100);
            threadList.Columns.Add("Wait Reason", 120);

            var threadToolBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 40, BackColor = DarkTheme.Surface,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(8, 6, 8, 6), Margin = Padding.Empty
            };
            var refreshThreadsBtn = CreateButton("Refresh", 75);
            var suspendThreadBtn = CreateButton("Suspend", 75);
            var resumeThreadBtn = CreateButton("Resume", 75);
            var killThreadBtn = CreateButton("Kill Thread", 85);
            refreshThreadsBtn.Click += (s, ev) => LoadThreads();
            suspendThreadBtn.Click += SuspendThread_Click;
            resumeThreadBtn.Click += ResumeThread_Click;
            killThreadBtn.Click += KillThread_Click;
            threadToolBar.Controls.AddRange(new Control[] { refreshThreadsBtn, suspendThreadBtn, resumeThreadBtn, killThreadBtn });

            threadsPage.Controls.Add(threadList);
            threadsPage.Controls.Add(threadToolBar);

            // ===================== MEMORY TAB =====================
            var memoryPage = new TabPage("Memory R/W") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };

            // Watch List (created early so toolbar can reference it)
            var watchList = CreateListView();
            watchList.Dock = DockStyle.Fill;
            watchList.Columns.Add("Address", 120);
            watchList.Columns.Add("Value", 140);
            watchList.Columns.Add("Previous", 140);
            watchList.Columns.Add("Type", 60);

            // Add to Watch handler
            EventHandler addToWatch = (s, ev) =>
            {
                string addr = addressBox.Text.Trim();
                if (string.IsNullOrEmpty(addr)) return;
                foreach (ListViewItem existing in watchList.Items)
                    if (existing.Text == addr) return;
                var lvi = new ListViewItem(addr);
                lvi.SubItems.Add("");
                lvi.SubItems.Add("");
                lvi.SubItems.Add("Int32");
                watchList.Items.Add(lvi);
                Log("Added {0} to watch list", addr);
            };

            // Toolbar: 3 rows
            var memToolBar = new Panel { Dock = DockStyle.Top, Height = 100, BackColor = DarkTheme.Surface, Padding = new Padding(0) };

            // Row 1: Address + Read + Write
            var row1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 2), Margin = Padding.Empty };
            row1.Controls.Add(MakeLabel("Address:"));
            addressBox = CreateTextBox(160);
            addressBox.Font = DarkTheme.UIMonoFont;
            row1.Controls.Add(addressBox);
            row1.Controls.Add(MakeLabel("Size:"));
            sizeBox = CreateTextBox(70);
            sizeBox.Text = "256";
            sizeBox.Font = DarkTheme.UIMonoFont;
            row1.Controls.Add(sizeBox);
            readMemBtn = CreateButton("Read", 60);
            readMemBtn.Click += ReadMemory_Click;
            row1.Controls.Add(readMemBtn);
            row1.Controls.Add(MakeSpacer(12));
            row1.Controls.Add(MakeLabel("Interpret:"));
            var typeCombo = new DarkComboBox { Width = 120 };
            typeCombo.Items.AddRange(new object[] { "Hex Dump", "Int32", "UInt32", "Int64", "Float", "Double", "ASCII String", "Unicode String", "Pointer Chain" });
            typeCombo.SelectedIndex = 0;
            row1.Controls.Add(typeCombo);

            // Row 2: Write value + Write button
            var row2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 2, 8, 2), Margin = Padding.Empty };
            row2.Controls.Add(MakeLabel("Write hex:"));
            writeValueBox = CreateTextBox(360);
            writeValueBox.Font = DarkTheme.UIMonoFont;
            row2.Controls.Add(writeValueBox);
            writeMemBtn = CreateButton("Write", 60);
            writeMemBtn.Click += WriteMemory_Click;
            row2.Controls.Add(writeMemBtn);

            // Row 3: Search
            var row3 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 2, 8, 2), Margin = Padding.Empty };
            row3.Controls.Add(MakeLabel("Search:"));
            var searchBox = CreateTextBox(220);
            row3.Controls.Add(searchBox);
            var searchTypeCombo = new DarkComboBox { Width = 100 };
            searchTypeCombo.Items.AddRange(new object[] { "Hex Bytes", "ASCII", "Unicode", "Int32", "Float", "Pattern (??)" });
            searchTypeCombo.SelectedIndex = 0;
            row3.Controls.Add(searchTypeCombo);
            var searchBtn = CreateButton("Search", 65);
            row3.Controls.Add(searchBtn);
            var navPrevBtn = CreateButton("< Prev", 55);
            row3.Controls.Add(navPrevBtn);
            var navNextBtn = CreateButton("Next >", 55);
            row3.Controls.Add(navNextBtn);
            var bookmarkBtn = CreateButton("Bookmark", 80);
            row3.Controls.Add(bookmarkBtn);
            var watchBtn = CreateButton("Watch", 60);
            watchBtn.Click += addToWatch;
            row3.Controls.Add(watchBtn);

            memToolBar.Controls.Add(row3);
            memToolBar.Controls.Add(row2);
            memToolBar.Controls.Add(row1);

            // Split: hex view left, search/bookmarks right
            var memSplit = new SplitContainer
            {
                Dock = DockStyle.Fill, Orientation = Orientation.Vertical,
                BackColor = DarkTheme.Background,
                SplitterWidth = 3, FixedPanel = FixedPanel.None,
                Panel1MinSize = 100, Panel2MinSize = 100
            };
            memSplit.Panel1.BackColor = DarkTheme.Background;
            memSplit.Panel2.BackColor = DarkTheme.Surface;

            memoryView = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Background,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both,
                WordWrap = false
            };
            memSplit.Panel1.Controls.Add(memoryView);
            memSplit.Panel1.Controls.Add(memToolBar);

            // Right panel: search results + bookmarks
            var rightSplit = new SplitContainer
            {
                Dock = DockStyle.Fill, Orientation = Orientation.Horizontal,
                BackColor = DarkTheme.Surface,
                SplitterWidth = 3, FixedPanel = FixedPanel.None,
                Panel1MinSize = 50, Panel2MinSize = 50
            };
            rightSplit.Panel1.BackColor = DarkTheme.Surface;
            rightSplit.Panel2.BackColor = DarkTheme.Surface;

            var searchResultsLabel = new Label
            {
                Text = "  Search Results", Dock = DockStyle.Top, Height = 24,
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold,
                TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated
            };
            var searchResultsList = CreateListView();
            searchResultsList.Dock = DockStyle.Fill;
            searchResultsList.Columns.Add("Address", 140);
            searchResultsList.Columns.Add("Value", 200);
            searchResultsList.DoubleClick += (s, ev) =>
            {
                if (searchResultsList.SelectedItems.Count > 0)
                {
                    addressBox.Text = searchResultsList.SelectedItems[0].Text;
                    readMemBtn.PerformClick();
                }
            };

            var bookmarksLabel = new Label
            {
                Text = "  Bookmarks", Dock = DockStyle.Top, Height = 24,
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold,
                TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated
            };
            var bookmarkList = CreateListView();
            bookmarkList.Dock = DockStyle.Fill;
            bookmarkList.Columns.Add("Address", 140);
            bookmarkList.Columns.Add("Label", 180);
            bookmarkList.DoubleClick += (s, ev) =>
            {
                if (bookmarkList.SelectedItems.Count > 0)
                {
                    addressBox.Text = bookmarkList.SelectedItems[0].Text;
                    readMemBtn.PerformClick();
                }
            };

            rightSplit.Panel1.Controls.Add(searchResultsList);
            rightSplit.Panel1.Controls.Add(searchResultsLabel);
            rightSplit.Panel2.Controls.Add(bookmarkList);
            rightSplit.Panel2.Controls.Add(bookmarksLabel);

            // Watch List - auto-refreshing address monitor
            var watchLabel = new Label
            {
                Text = "  Watch List", Dock = DockStyle.Top, Height = 24,
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold,
                TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated
            };
            watchList.DoubleClick += (s, ev) =>
            {
                if (watchList.SelectedItems.Count > 0)
                {
                    addressBox.Text = watchList.SelectedItems[0].Text;
                    readMemBtn.PerformClick();
                }
            };

            // Wrap rightSplit + watch in a vertical split
            var outerRightSplit = new SplitContainer
            {
                Dock = DockStyle.Fill, Orientation = Orientation.Horizontal,
                BackColor = DarkTheme.Surface, SplitterWidth = 3,
                Panel1MinSize = 80, Panel2MinSize = 80
            };
            outerRightSplit.Panel1.BackColor = DarkTheme.Surface;
            outerRightSplit.Panel2.BackColor = DarkTheme.Surface;
            outerRightSplit.Panel1.Controls.Add(rightSplit);
            outerRightSplit.Panel2.Controls.Add(watchList);
            outerRightSplit.Panel2.Controls.Add(watchLabel);

            memSplit.Panel2.Controls.Add(outerRightSplit);

            memoryPage.Controls.Add(memSplit);

            // Watch list auto-refresh timer
            var watchTimer = new System.Windows.Forms.Timer { Interval = 500 };
            watchTimer.Tick += (s, ev) =>
            {
                if (tabControl.SelectedTab != memoryPage) return;
                foreach (ListViewItem item in watchList.Items)
                {
                    try
                    {
                        ulong addr;
                        string hex = item.Text.Replace("0x", "").Replace("0X", "");
                        if (!ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out addr)) continue;

                        int readSize = 8;
                        IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)readSize,
                            WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                        if (buf == IntPtr.Zero) continue;
                        try
                        {
                            if (driver.CopyVirtualMemory(processId, (IntPtr)addr, buf, readSize))
                            {
                                byte[] data = new byte[readSize];
                                System.Runtime.InteropServices.Marshal.Copy(buf, data, 0, readSize);

                                string currentVal = $"{BitConverter.ToInt32(data, 0)} / 0x{BitConverter.ToUInt32(data, 0):X8}";
                                string prevVal = item.SubItems[1].Text;

                                item.SubItems[2].Text = prevVal; // Move current to previous
                                item.SubItems[1].Text = currentVal; // Set new current

                                // Highlight if value changed
                                if (prevVal != "" && prevVal != currentVal)
                                    item.ForeColor = DarkTheme.Warning;
                                else
                                    item.ForeColor = DarkTheme.TextPrimary;
                            }
                        }
                        finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
                    }
                    catch { }
                }
            };
            watchTimer.Start();

            // ===================== MEMORY MAP TAB =====================
            var memMapPage = new TabPage("Memory Map") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            memoryMapList = CreateListView();
            memoryMapList.Columns.Add("Base Address", 150);
            memoryMapList.Columns.Add("Size", 100);
            memoryMapList.Columns.Add("Protect", 130);
            memoryMapList.Columns.Add("State", 100);
            memoryMapList.Columns.Add("Type", 110);

            var memMapToolBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 40, BackColor = DarkTheme.Surface,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(8, 6, 8, 6), Margin = Padding.Empty
            };
            var refreshMapBtn = CreateButton("Refresh Map", 100);
            refreshMapBtn.Click += (s, ev) => LoadMemoryMap();
            memMapToolBar.Controls.Add(refreshMapBtn);

            memMapPage.Controls.Add(memoryMapList);
            memMapPage.Controls.Add(memMapToolBar);

            // ===================== INJECT TAB =====================
            var injectPage = new TabPage("Inject DLL") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            var injectPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(12), BackColor = DarkTheme.Background };

            var injectLabel = new Label
            {
                Text = "Select a DLL to inject into the target process:",
                Dock = DockStyle.Top, Height = 28,
                ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };

            var injectPathPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 36,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(0, 4, 0, 4), Margin = Padding.Empty
            };
            injectPathBox = CreateTextBox(550);
            browseInjectBtn = CreateButton("Browse...", 85);
            browseInjectBtn.Click += BrowseInject_Click;
            injectPathPanel.Controls.Add(injectPathBox);
            injectPathPanel.Controls.Add(browseInjectBtn);

            injectBtn = CreateButton("Inject DLL", 120);
            injectBtn.BackColor = DarkTheme.AccentSubtle;
            injectBtn.Click += InjectDll_Click;
            var injectBtnPanel = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 36,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(0, 4, 0, 8), Margin = Padding.Empty
            };
            injectBtnPanel.Controls.Add(injectBtn);

            var injectMethodsLabel = new Label
            {
                Text = "Injection Methods (reference):",
                Dock = DockStyle.Top, Height = 28,
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold
            };

            var methodList = CreateListView();
            methodList.Dock = DockStyle.Fill;
            methodList.Columns.Add("Method", 220);
            methodList.Columns.Add("Requires Driver", 120);
            methodList.Columns.Add("Description", 380);

            methodList.Items.Add(new ListViewItem(new[] { "LoadLibrary (CreateRemoteThread)", "No", "Classic injection via CreateRemoteThread + LoadLibraryA" }));
            methodList.Items.Add(new ListViewItem(new[] { "NtCreateThreadEx", "No", "Undocumented thread creation, bypasses some hooks" }));
            methodList.Items.Add(new ListViewItem(new[] { "APC Injection", "No", "QueueUserAPC to alertable thread, stealthy" }));
            methodList.Items.Add(new ListViewItem(new[] { "Manual Map (Reflective)", "Yes", "Maps DLL manually without LoadLibrary, no disk traces" }));
            methodList.Items.Add(new ListViewItem(new[] { "Kernel Inject", "Yes", "Inject via kernel driver MmCopyVirtualMemory" }));
            methodList.Items.Add(new ListViewItem(new[] { "SetWindowsHookEx", "No", "Hook-based injection, targets GUI threads" }));

            // Add in reverse order for dock stacking
            injectPanel.Controls.Add(methodList);
            injectPanel.Controls.Add(injectMethodsLabel);
            injectPanel.Controls.Add(injectBtnPanel);
            injectPanel.Controls.Add(injectPathPanel);
            injectPanel.Controls.Add(injectLabel);
            injectPage.Controls.Add(injectPanel);

            // ===================== IMPORTS TAB =====================
            var importsPage = new TabPage("Import Table") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };

            var importToolBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 40, BackColor = DarkTheme.Surface,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(8, 6, 8, 6), Margin = Padding.Empty
            };
            var refreshImportsBtn = CreateButton("Refresh Imports", 120);
            var expandAllBtn = CreateButton("Expand All", 85);
            var collapseAllBtn = CreateButton("Collapse All", 90);
            var searchImportBox = CreateTextBox(200);
            searchImportBox.Font = DarkTheme.UIFont;
            var importCountLbl = new Label { Text = "0 imports", AutoSize = true, Margin = new Padding(8, 5, 0, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
            importToolBar.Controls.AddRange(new Control[] { refreshImportsBtn, expandAllBtn, collapseAllBtn, searchImportBox, importCountLbl });

            var importTree = new TreeView
            {
                Dock = DockStyle.Fill, BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIMonoFont, ShowLines = true,
                HideSelection = false, FullRowSelect = true
            };

            importsPage.Controls.Add(importTree);
            importsPage.Controls.Add(importToolBar);

            // ===================== PE HEADERS TAB =====================
            var headersPage = new TabPage("PE Headers") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };

            var headersToolBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 40, BackColor = DarkTheme.Surface,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(8, 6, 8, 6), Margin = Padding.Empty
            };
            var refreshHeadersBtn = CreateButton("Refresh Headers", 120);
            var headersCountLbl = new Label { Text = "", AutoSize = true, Margin = new Padding(8, 5, 0, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
            headersToolBar.Controls.AddRange(new Control[] { refreshHeadersBtn, headersCountLbl });

            var headersView = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Background,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both,
                WordWrap = false
            };

            headersPage.Controls.Add(headersView);
            headersPage.Controls.Add(headersToolBar);

            // ===================== INFO TAB =====================
            var infoPage = new TabPage("Process Info") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            var infoText = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary
            };
            infoPage.Controls.Add(infoText);

            // ===================== DISASSEMBLER TAB =====================
            var disasmPage = new TabPage("Disassembler") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            var disasmToolBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 40, BackColor = DarkTheme.Surface,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(8, 6, 8, 6), Margin = Padding.Empty
            };
            disasmToolBar.Controls.Add(MakeLabel("Address:"));
            var disasmAddrBox = CreateTextBox(140);
            disasmAddrBox.Font = DarkTheme.UIMonoFont;
            disasmToolBar.Controls.Add(disasmAddrBox);
            var disasmGoBtn = CreateButton("Disassemble", 90);
            disasmToolBar.Controls.Add(disasmGoBtn);
            var disasmCountBox = new DarkNumericUpDown { Width = 60, Minimum = 10, Maximum = 1000, Value = 50 };
            disasmToolBar.Controls.Add(MakeLabel("Count:"));
            disasmToolBar.Controls.Add(disasmCountBox);

            var disasmList = CreateListView();
            disasmList.Columns.Add("Address", 130);
            disasmList.Columns.Add("Bytes", 160);
            disasmList.Columns.Add("Instruction", 300);
            disasmList.Columns.Add("Category", 80);

            disasmGoBtn.Click += (s, ev) =>
            {
                ulong addr;
                string hex = disasmAddrBox.Text.Replace("0x", "").Replace("0X", "");
                if (!ulong.TryParse(hex, System.Globalization.NumberStyles.HexNumber, null, out addr)) { Log("Invalid address"); return; }

                int count = (int)disasmCountBox.Value;
                int readSize = count * 15; // Max x86 instruction is 15 bytes
                IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)readSize,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (buf == IntPtr.Zero) { Log("Failed to allocate buffer"); return; }
                try
                {
                    if (!driver.CopyVirtualMemory(processId, (IntPtr)addr, buf, readSize))
                    { Log("Failed to read memory at 0x{0:X}", addr); return; }
                    byte[] code = new byte[readSize];
                    System.Runtime.InteropServices.Marshal.Copy(buf, code, 0, readSize);

                    var instructions = Utility.SimpleDisassembler.Disassemble(code, addr, count);
                    disasmList.Items.Clear();
                    foreach (var instr in instructions)
                    {
                        var lvi = new ListViewItem($"0x{instr.Address:X}");
                        lvi.SubItems.Add(BitConverter.ToString(instr.Bytes).Replace("-", " "));
                        lvi.SubItems.Add($"{instr.Mnemonic} {instr.Operands}");
                        lvi.SubItems.Add(instr.Category);

                        if (instr.Category == "CALL") lvi.ForeColor = DarkTheme.Accent;
                        else if (instr.Category == "JMP") lvi.ForeColor = DarkTheme.Success;
                        else if (instr.Category == "RET") lvi.ForeColor = DarkTheme.Error;
                        else if (instr.Category == "INT") lvi.ForeColor = DarkTheme.Warning;
                        else lvi.ForeColor = DarkTheme.TextPrimary;

                        disasmList.Items.Add(lvi);
                    }
                    Log("Disassembled {0} instructions at 0x{1:X}", instructions.Count, addr);
                }
                finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
            };

            disasmPage.Controls.Add(disasmList);
            disasmPage.Controls.Add(disasmToolBar);

            // ===================== CALL STACK TAB =====================
            var callStackPage = new TabPage("Call Stack") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            var csToolBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Top, Height = 40, BackColor = DarkTheme.Surface,
                FlowDirection = FlowDirection.LeftToRight, WrapContents = false,
                Padding = new Padding(8, 6, 8, 6), Margin = Padding.Empty
            };
            csToolBar.Controls.Add(MakeLabel("Thread:"));
            var csThreadCombo = new DarkComboBox { Width = 160 };
            csToolBar.Controls.Add(csThreadCombo);
            var csRefreshBtn = CreateButton("Refresh Stack", 100);
            csToolBar.Controls.Add(csRefreshBtn);
            var csDepthBox = new DarkNumericUpDown { Width = 60, Minimum = 5, Maximum = 100, Value = 30 };
            csToolBar.Controls.Add(MakeLabel("Depth:"));
            csToolBar.Controls.Add(csDepthBox);

            var csList = CreateListView();
            csList.Columns.Add("#", 40);
            csList.Columns.Add("Return Address", 140);
            csList.Columns.Add("Module", 200);
            csList.Columns.Add("Function", 250);
            csList.Columns.Add("Offset", 80);

            csRefreshBtn.Click += (s, ev) =>
            {
                csList.Items.Clear();
                if (csThreadCombo.SelectedItem == null) return;

                string tidStr = csThreadCombo.SelectedItem.ToString();
                if (!uint.TryParse(tidStr, out uint tid)) return;

                int maxDepth = (int)csDepthBox.Value;
                Log("Walking call stack for thread {0} (depth: {1})...", tid, maxDepth);

                try
                {
                    // Get thread context to find RSP
                    byte[] ctx = null;
                    if (driver.IsKernelMode)
                        ctx = driver.GetThreadContext(processId, (int)tid, 0x0010003F); // CONTEXT_FULL
                    if (ctx == null)
                    {
                        // Fallback to user-mode
                        IntPtr hThread = OpenThread(0x0008 | 0x0010 | 0x0040, false, tid);
                        if (hThread != IntPtr.Zero)
                        {
                            try
                            {
                                IntPtr ctxPtr = System.Runtime.InteropServices.Marshal.AllocHGlobal(2048);
                                for (int i = 0; i < 2048; i++) System.Runtime.InteropServices.Marshal.WriteByte(ctxPtr, i, 0);
                                System.Runtime.InteropServices.Marshal.WriteInt32(ctxPtr, 48, 0x0010003F);
                                if (GetThreadContext(hThread, ctxPtr))
                                {
                                    ctx = new byte[2048];
                                    System.Runtime.InteropServices.Marshal.Copy(ctxPtr, ctx, 0, 2048);
                                }
                                System.Runtime.InteropServices.Marshal.FreeHGlobal(ctxPtr);
                            }
                            finally { CloseHandle(hThread); }
                        }
                    }

                    if (ctx == null || ctx.Length < 2048) { Log("Failed to get thread context"); return; }

                    // x64 CONTEXT: RSP at offset 152, RBP at offset 160
                    ulong rsp = BitConverter.ToUInt64(ctx, 152);
                    ulong rbp = BitConverter.ToUInt64(ctx, 160);

                    // Get export map for symbol resolution
                    var exportMap = driver.GetExportMap(processId);

                    // Get module list for module name resolution
                    driver.GetModuleSummaryList(processId, out var modules);

                    // Walk the stack by following return addresses on the stack
                    for (int frame = 0; frame < maxDepth; frame++)
                    {
                        // Read 8 bytes at RSP (return address)
                        byte[] retAddrBytes = new byte[8];
                        IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)8,
                            WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                        if (buf == IntPtr.Zero) break;
                        if (!driver.CopyVirtualMemory(processId, (IntPtr)rsp, buf, 8))
                        {
                            WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                            break;
                        }
                        System.Runtime.InteropServices.Marshal.Copy(buf, retAddrBytes, 0, 8);
                        WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);

                        ulong retAddr = BitConverter.ToUInt64(retAddrBytes, 0);
                        if (retAddr == 0 || retAddr > 0x00007FFFFFFEFFFF) break;

                        // Resolve to module + function
                        string moduleName = "???";
                        string funcName = "";
                        string offsetStr = "";

                        // Find which module this address belongs to
                        if (modules != null)
                        {
                            foreach (var mod in modules)
                            {
                                if (retAddr >= mod.BaseAddress && retAddr < mod.BaseAddress + mod.ImageSize)
                                {
                                    moduleName = mod.ModuleName;
                                    ulong rva = retAddr - mod.BaseAddress;
                                    offsetStr = $"+0x{rva:X}";

                                    // Try to find the nearest exported function
                                    ulong nearestAddr = 0;
                                    string nearestFunc = "";
                                    foreach (var kvp in exportMap)
                                    {
                                        if (kvp.Key >= mod.BaseAddress && kvp.Key < mod.BaseAddress + mod.ImageSize && kvp.Key <= retAddr)
                                        {
                                            if (kvp.Key > nearestAddr)
                                            {
                                                nearestAddr = kvp.Key;
                                                nearestFunc = kvp.Value.funcName;
                                            }
                                        }
                                    }
                                    if (nearestAddr > 0)
                                    {
                                        funcName = nearestFunc;
                                        ulong funcOffset = retAddr - nearestAddr;
                                        if (funcOffset > 0)
                                            offsetStr = $"{nearestFunc}+0x{funcOffset:X}";
                                    }
                                    break;
                                }
                            }
                        }

                        var lvi = new ListViewItem(frame.ToString());
                        lvi.SubItems.Add($"0x{retAddr:X}");
                        lvi.SubItems.Add(moduleName);
                        lvi.SubItems.Add(funcName);
                        lvi.SubItems.Add(offsetStr);

                        if (funcName != "") lvi.ForeColor = DarkTheme.Accent;
                        else if (moduleName != "???") lvi.ForeColor = DarkTheme.TextPrimary;
                        else lvi.ForeColor = DarkTheme.TextMuted;

                        csList.Items.Add(lvi);

                        // Advance RSP by 8 (pop the return address)
                        rsp += 8;

                        // Also try to follow RBP chain for frame-based unwinding
                        if (rbp > rsp && rbp < 0x00007FFFFFFEFFFF)
                        {
                            // Read saved RBP at [RBP] and return address at [RBP+8]
                            byte[] frameData = new byte[16];
                            buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)16,
                                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                            if (buf != IntPtr.Zero)
                            {
                                if (driver.CopyVirtualMemory(processId, (IntPtr)rbp, buf, 16))
                                {
                                    System.Runtime.InteropServices.Marshal.Copy(buf, frameData, 0, 16);
                                    ulong savedRbp = BitConverter.ToUInt64(frameData, 0);
                                    ulong frameRetAddr = BitConverter.ToUInt64(frameData, 8);

                                    if (frameRetAddr > retAddr && frameRetAddr < 0x00007FFFFFFEFFFF)
                                    {
                                        // Use frame-based return address instead
                                        rsp = rbp + 16; // Skip saved RBP + return address
                                        rbp = savedRbp;
                                    }
                                }
                                WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                            }
                        }
                    }

                    Log("Stack walk complete: {0} frames", csList.Items.Count);
                }
                catch (Exception ex) { Log("Stack walk error: {0}", ex.Message); }
            };

            // Populate thread combo when tab is selected
            tabControl.Selected += (s, ev) =>
            {
                if (tabControl.SelectedTab == callStackPage && csThreadCombo.Items.Count == 0)
                {
                    foreach (ListViewItem item in threadList.Items)
                        csThreadCombo.Items.Add(item.Text);
                    if (csThreadCombo.Items.Count > 0)
                        csThreadCombo.SelectedIndex = 0;
                }
            };

            callStackPage.Controls.Add(csList);
            callStackPage.Controls.Add(csToolBar);

            tabControl.TabPages.AddRange(new[] { threadsPage, memoryPage, memMapPage, injectPage, importsPage, headersPage, infoPage, disasmPage, callStackPage });

            // Dark separator panels to fill visual gaps between docked sections
            var topSep = new Panel { Dock = DockStyle.Top, Height = 1, BackColor = DarkTheme.Border };
            var bottomSep = new Panel { Dock = DockStyle.Bottom, Height = 1, BackColor = DarkTheme.Border };

            // Assembly order matters for dock stacking (last added docks first)
            Controls.Add(tabControl);
            Controls.Add(bottomSep);
            Controls.Add(logPanel);
            Controls.Add(topSep);
            Controls.Add(topPanel);

            DarkTheme.ApplyTo(this);

            // Apply luxury styling to all buttons
            void RestyleButtons(Control.ControlCollection ctrls)
            {
                foreach (Control c in ctrls)
                {
                    if (c is Button btn)
                        DarkControlsHelper.StyleButton(btn);
                    else if (c.HasChildren)
                        RestyleButtons(c.Controls);
                }
            }
            RestyleButtons(Controls);

            // Auto-expand last column on remaining ListViews
            void AutoExpandLastCol(ListView lv)
            {
                void DoExpand() { if (lv.Columns.Count > 0) lv.Columns[lv.Columns.Count - 1].Width = -2; }
                lv.Resize += (s, ev) => DoExpand();
                Load += (s, ev) => DoExpand();
            }
            AutoExpandLastCol(threadList);
            AutoExpandLastCol(memoryMapList);
            AutoExpandLastCol(searchResultsList);
            AutoExpandLastCol(bookmarkList);
            AutoExpandLastCol(methodList);
            AutoExpandLastCol(disasmList);

            // Set splitter distances after layout
            Load += (s, ev) =>
            {
                try { if (memSplit.Width > 300) memSplit.SplitterDistance = (int)(memSplit.Width * 0.65); } catch { }
                try { if (rightSplit.Height > 200) rightSplit.SplitterDistance = (int)(rightSplit.Height * 0.55); } catch { }
            };

            tabControl.Selected += (s, ev) =>
            {
                if (tabControl.SelectedTab == infoPage && infoText.TextLength == 0)
                    LoadProcessInfo(infoText);
                if (tabControl.SelectedTab == memMapPage && memoryMapList.Items.Count == 0)
                    LoadMemoryMap();
            };

            FormClosing += (s, ev) => { DetachFromProcess(); debugEngine?.Dispose(); };

            // ---- Search state ----
            var searchMatches = new List<ulong>();
            int searchMatchIdx = -1;

            searchBtn.Click += (s, ev) =>
            {
                string query = searchBox.Text;
                if (string.IsNullOrEmpty(query)) return;

                Log("Searching for '{0}'...", query);
                searchMatches.Clear();
                searchResultsList.Items.Clear();
                searchMatchIdx = -1;

                var regions = driver.EnumRegions(processId);
                int found = 0;

                foreach (var (baseAddr, regionSize, protect, state, type) in regions)
                {
                    if (state != 0x1000) continue;
                    if (type != 0x20000 && type != 0x40000 && type != 0x1000000) continue;
                    if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0) continue;

                    int readSize = (int)Math.Min(regionSize, 0x100000);
                    IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)readSize,
                        WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) continue;
                    if (!driver.CopyVirtualMemory(processId, (IntPtr)baseAddr, buf, readSize))
                    {
                        WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                        continue;
                    }
                    byte[] data = new byte[readSize];
                    Marshal.Copy(buf, data, 0, readSize);
                    WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);

                    byte[] searchBytes;
                    string searchType = searchTypeCombo.SelectedItem?.ToString() ?? "Hex Bytes";

                    try
                    {
                        switch (searchType)
                        {
                            case "ASCII": searchBytes = Encoding.ASCII.GetBytes(query); break;
                            case "Unicode": searchBytes = Encoding.Unicode.GetBytes(query); break;
                            case "Int32":
                                searchBytes = BitConverter.GetBytes(int.Parse(query));
                                break;
                            case "Float":
                                searchBytes = BitConverter.GetBytes(float.Parse(query));
                                break;
                            case "Pattern (??)":
                                var parts = query.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                                searchBytes = new byte[parts.Length];
                                for (int pi = 0; pi < parts.Length; pi++)
                                    searchBytes[pi] = parts[pi] == "??" ? (byte)0xCC : Convert.ToByte(parts[pi], 16);
                                break;
                            default:
                                string hex = query.Replace(" ", "").Replace("0x", "");
                                if (hex.Length % 2 != 0) { Log("Invalid hex length"); return; }
                                searchBytes = new byte[hex.Length / 2];
                                for (int bi = 0; bi < searchBytes.Length; bi++)
                                    searchBytes[bi] = Convert.ToByte(hex.Substring(bi * 2, 2), 16);
                                break;
                        }
                    }
                    catch { Log("Invalid search input"); return; }

                    bool isPattern = searchType == "Pattern (??)";
                    for (int off = 0; off <= data.Length - searchBytes.Length && found < 500; off++)
                    {
                        bool match = true;
                        for (int bi = 0; bi < searchBytes.Length; bi++)
                        {
                            if (isPattern && searchBytes[bi] == 0xCC) continue;
                            if (data[off + bi] != searchBytes[bi]) { match = false; break; }
                        }
                        if (match)
                        {
                            ulong matchAddr = baseAddr + (ulong)off;
                            searchMatches.Add(matchAddr);
                            string preview = data.Length > off + 16
                                ? BitConverter.ToString(data, off, Math.Min(16, searchBytes.Length * 2))
                                : "";
                            var lvi = new ListViewItem($"0x{matchAddr:X12}");
                            lvi.SubItems.Add(preview);
                            searchResultsList.Items.Add(lvi);
                            found++;
                        }
                    }
                }

                Log("Search complete: {0} matches", found);
                if (searchMatches.Count > 0) { searchMatchIdx = 0; addressBox.Text = $"0x{searchMatches[0]:X}"; }
            };

            navNextBtn.Click += (s, ev) =>
            {
                if (searchMatches.Count == 0) return;
                searchMatchIdx = (searchMatchIdx + 1) % searchMatches.Count;
                addressBox.Text = $"0x{searchMatches[searchMatchIdx]:X}";
                readMemBtn.PerformClick();
            };

            navPrevBtn.Click += (s, ev) =>
            {
                if (searchMatches.Count == 0) return;
                searchMatchIdx = searchMatchIdx <= 0 ? searchMatches.Count - 1 : searchMatchIdx - 1;
                addressBox.Text = $"0x{searchMatches[searchMatchIdx]:X}";
                readMemBtn.PerformClick();
            };

            bookmarkBtn.Click += (s, ev) =>
            {
                ulong addr;
                if (!ulong.TryParse(addressBox.Text.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out addr)) return;
                var lvi = new ListViewItem(addressBox.Text);
                lvi.SubItems.Add($"0x{addr:X}");
                bookmarkList.Items.Add(lvi);
                Log("Bookmarked: {0}", addressBox.Text);
            };

            typeCombo.SelectedIndexChanged += (s, ev) =>
            {
                if (addressBox.Text.Length > 0) readMemBtn.PerformClick();
            };

            // ---- Import Table handlers ----

            expandAllBtn.Click += (s, ev) => importTree.ExpandAll();
            collapseAllBtn.Click += (s, ev) => importTree.CollapseAll();

            searchImportBox.TextChanged += (s, ev) =>
            {
                string filter = searchImportBox.Text.ToLowerInvariant();
                importTree.BeginUpdate();
                try
                {
                    foreach (TreeNode dllNode in importTree.Nodes)
                    {
                        bool dllMatch = dllNode.Text.ToLowerInvariant().Contains(filter);
                        bool anyChildMatch = false;
                        foreach (TreeNode funcNode in dllNode.Nodes)
                        {
                            bool funcMatch = string.IsNullOrEmpty(filter) || funcNode.Text.ToLowerInvariant().Contains(filter);
                            funcNode.ForeColor = funcMatch ? DarkTheme.TextPrimary : DarkTheme.TextMuted;
                            if (funcMatch) anyChildMatch = true;
                        }
                        dllNode.ForeColor = (dllMatch || anyChildMatch) ? DarkTheme.Accent : DarkTheme.TextMuted;
                        if (dllMatch && !string.IsNullOrEmpty(filter)) dllNode.Expand();
                    }
                }
                finally { importTree.EndUpdate(); }
            };

            refreshImportsBtn.Click += (s, ev) =>
            {
                LoadImportTable(importTree, importCountLbl);
            };

            tabControl.Selected += (s2, ev2) =>
            {
                if (tabControl.SelectedTab == importsPage && importTree.Nodes.Count == 0)
                    LoadImportTable(importTree, importCountLbl);
                if (tabControl.SelectedTab == headersPage && headersView.TextLength == 0)
                    LoadPEHeaders(headersView, headersCountLbl);
            };

            refreshHeadersBtn.Click += (s, ev) => LoadPEHeaders(headersView, headersCountLbl);
        }

        // ---- Import Table Parsing ----

        private void LoadImportTable(TreeView tree, Label countLbl)
        {
            tree.Nodes.Clear();
            Log("Parsing import table...");

            Task.Run(() =>
            {
                try
                {
                    var imports = ParseImportsFromMemory();
                    int totalFuncs = 0;

                    this.SafeInvoke(new Action(() =>
                    {
                        tree.BeginUpdate();
                        try
                        {
                            foreach (var dll in imports)
                            {
                                var dllNode = tree.Nodes.Add(dll.DllName);
                                dllNode.ForeColor = DarkTheme.Accent;
                                dllNode.Tag = dll;

                                foreach (var func in dll.Functions)
                                {
                                    string display = func.IsOrdinal
                                        ? $"Ordinal #{func.Ordinal}  ->  0x{func.Address:X}"
                                        : $"{func.Name}  ->  0x{func.Address:X}";
                                    var funcNode = dllNode.Nodes.Add(display);
                                    funcNode.ForeColor = func.Address != 0 ? DarkTheme.TextPrimary : DarkTheme.TextMuted;
                                    funcNode.Tag = func;
                                    totalFuncs++;
                                }

                                dllNode.Text = $"{dll.DllName} ({dll.Functions.Count})";
                            }
                        }
                        finally { tree.EndUpdate(); }

                        countLbl.Text = $"{imports.Count} DLLs, {totalFuncs} imports";
                        Log("Import table: {0} DLLs, {1} functions", imports.Count, totalFuncs);
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => Log("Import table parse error: {0}", ex.Message)));
                }
            });
        }

        private struct ImportDll
        {
            public string DllName;
            public List<ImportFunc> Functions;
        }

        private struct ImportFunc
        {
            public string Name;
            public ulong Address;
            public bool IsOrdinal;
            public int Ordinal;
        }

        private List<ImportDll> ParseImportsFromMemory()
        {
            var result = new List<ImportDll>();
            bool is64 = true; // Assume x64; detect from PE

            // Read DOS header to find PE
            ulong baseAddr = 0;
            // Get base address from the process info we already have
            // Try reading from the module base - get it from the driver
            var modules = new List<(ulong addr, uint size)>();
            try
            {
                // Use the module list from the driver
                // We need the main module base - read it from the process
                byte[] dosBuf = new byte[64];
                IntPtr dosPtr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)64,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (dosPtr == IntPtr.Zero) return result;

                // Try to find the main module by reading process PEB or using module list
                // For simplicity, get it from the process handle
                // We'll use a simpler approach: read modules from the driver interface
                // and find the main module (first one or .exe)

                // Get module list to find main module base
                var modList = driver.GetModuleSummaryList(processId, out var mods);
                if (modList && mods.Length > 0)
                {
                    baseAddr = mods[0].BaseAddress; // Main module is usually first
                }

                if (baseAddr == 0)
                {
                    WinApi.VirtualFree(dosPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);
                    return result;
                }

                if (!driver.CopyVirtualMemory(processId, (IntPtr)baseAddr, dosPtr, 64))
                {
                    WinApi.VirtualFree(dosPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);
                    return result;
                }
                Marshal.Copy(dosPtr, dosBuf, 0, 64);
                WinApi.VirtualFree(dosPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);

                if (BitConverter.ToUInt16(dosBuf, 0) != 0x5A4D) return result;
                int e_lfanew = BitConverter.ToInt32(dosBuf, 60);

                // Read PE header
                byte[] peBuf = new byte[512];
                IntPtr pePtr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)512,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (pePtr == IntPtr.Zero) return result;
                if (!driver.CopyVirtualMemory(processId, (IntPtr)(baseAddr + (ulong)e_lfanew), pePtr, 512))
                {
                    WinApi.VirtualFree(pePtr, UIntPtr.Zero, WinApi.MEM_RELEASE);
                    return result;
                }
                Marshal.Copy(pePtr, peBuf, 0, 512);
                WinApi.VirtualFree(pePtr, UIntPtr.Zero, WinApi.MEM_RELEASE);

                if (BitConverter.ToUInt32(peBuf, 0) != 0x00004550) return result;

                ushort magic = BitConverter.ToUInt16(peBuf, 24);
                is64 = magic == 0x20b;

                // Import directory is data directory entry [1]
                int dataDirBase = is64 ? 112 : 96;
                uint importDirRVA = BitConverter.ToUInt32(peBuf, 24 + dataDirBase + 8);
                uint importDirSize = BitConverter.ToUInt32(peBuf, 24 + dataDirBase + 12);

                if (importDirRVA == 0 || importDirSize == 0) return result;

                // Read the import directory section
                int readSize = Math.Max((int)importDirSize, 4096);
                byte[] importBuf = new byte[readSize];
                IntPtr importPtr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)readSize,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (importPtr == IntPtr.Zero) return result;
                if (!driver.CopyVirtualMemory(processId, (IntPtr)(baseAddr + importDirRVA), importPtr, readSize))
                {
                    WinApi.VirtualFree(importPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);
                    return result;
                }
                Marshal.Copy(importPtr, importBuf, 0, readSize);
                WinApi.VirtualFree(importPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);

                // Also read extra data for names and thunks (up to 64KB from import dir)
                int extraRead = Math.Min(0x10000, 0x10000);
                byte[] extraBuf = new byte[extraRead];
                IntPtr extraPtr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)extraRead,
                    WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                if (extraPtr == IntPtr.Zero) return result;
                uint extraBase = importDirRVA;
                if (driver.CopyVirtualMemory(processId, (IntPtr)(baseAddr + extraBase), extraPtr, extraRead))
                {
                    Marshal.Copy(extraPtr, extraBuf, 0, extraRead);
                }
                WinApi.VirtualFree(extraPtr, UIntPtr.Zero, WinApi.MEM_RELEASE);

                // Parse import descriptors (20 bytes each)
                int pos = 0;
                int thunkSize = is64 ? 8 : 4;

                while (pos + 20 <= importBuf.Length)
                {
                    uint origFirstThunk = BitConverter.ToUInt32(importBuf, pos);
                    uint timeDateStamp = BitConverter.ToUInt32(importBuf, pos + 4);
                    uint forwarderChain = BitConverter.ToUInt32(importBuf, pos + 8);
                    uint nameRVA = BitConverter.ToUInt32(importBuf, pos + 12);
                    uint firstThunk = BitConverter.ToUInt32(importBuf, pos + 16);

                    if (nameRVA == 0 && firstThunk == 0) break; // Null terminator

                    // Read DLL name
                    string dllName = ReadStringAtRVA(baseAddr, nameRVA);
                    if (string.IsNullOrEmpty(dllName)) { pos += 20; continue; }

                    var dll = new ImportDll { DllName = dllName, Functions = new List<ImportFunc>() };

                    // Read thunks from IAT (firstThunk) or INT (origFirstThunk)
                    uint thunkRVA = origFirstThunk != 0 ? origFirstThunk : firstThunk;
                    if (thunkRVA != 0)
                    {
                        for (int t = 0; t < 4096; t++)
                        {
                            ulong thunkVal = ReadThunkAtRVA(baseAddr, thunkRVA + (uint)(t * thunkSize), is64);
                            if (thunkVal == 0) break;

                            bool isOrdinal = is64 ? (thunkVal & 0x8000000000000000) != 0 : (thunkVal & 0x80000000) != 0;

                            // Read resolved address from IAT
                            ulong resolvedAddr = ReadThunkAtRVA(baseAddr, firstThunk + (uint)(t * thunkSize), is64);

                            if (isOrdinal)
                            {
                                int ordinal = (int)(thunkVal & 0xFFFF);
                                dll.Functions.Add(new ImportFunc { Name = $"#{ordinal}", Address = resolvedAddr, IsOrdinal = true, Ordinal = ordinal });
                            }
                            else
                            {
                                // Import by name: thunkVal is RVA to Hint/Name table
                                uint hintNameRVA = is64 ? (uint)(thunkVal & 0x7FFFFFFF) : (uint)(thunkVal & 0x7FFFFFFF);
                                string funcName = ReadHintNameAtRVA(baseAddr, hintNameRVA);
                                dll.Functions.Add(new ImportFunc { Name = funcName ?? "(unknown)", Address = resolvedAddr, IsOrdinal = false });
                            }
                        }
                    }

                    result.Add(dll);
                    pos += 20;
                }
            }
            catch { }

            return result;
        }

        private string ReadStringAtRVA(ulong baseAddr, uint rva)
        {
            if (rva == 0) return null;
            byte[] buf = new byte[256];
            IntPtr ptr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)256,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (ptr == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)(baseAddr + rva), ptr, 256))
                    return null;
                Marshal.Copy(ptr, buf, 0, 256);
                int end = 0;
                while (end < 256 && buf[end] != 0) end++;
                return end > 0 ? Encoding.ASCII.GetString(buf, 0, end) : null;
            }
            finally { WinApi.VirtualFree(ptr, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private string ReadHintNameAtRVA(ulong baseAddr, uint rva)
        {
            if (rva == 0) return null;
            byte[] buf = new byte[256];
            IntPtr ptr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)256,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (ptr == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)(baseAddr + rva), ptr, 256))
                    return null;
                Marshal.Copy(ptr, buf, 0, 256);
                // Skip 2-byte hint
                int start = 2;
                int end = start;
                while (end < 256 && buf[end] != 0) end++;
                return end > start ? Encoding.ASCII.GetString(buf, start, end - start) : null;
            }
            finally { WinApi.VirtualFree(ptr, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private ulong ReadThunkAtRVA(ulong baseAddr, uint rva, bool is64)
        {
            int size = is64 ? 8 : 4;
            byte[] buf = new byte[size];
            IntPtr ptr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (ptr == IntPtr.Zero) return 0;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)(baseAddr + rva), ptr, size))
                    return 0;
                Marshal.Copy(ptr, buf, 0, size);
                return is64 ? BitConverter.ToUInt64(buf, 0) : BitConverter.ToUInt32(buf, 0);
            }
            finally { WinApi.VirtualFree(ptr, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        // ---- PE Headers Display ----

        private void LoadPEHeaders(RichTextBox view, Label countLbl)
        {
            view.Clear();
            Log("Reading PE headers...");

            Task.Run(() =>
            {
                try
                {
                    ulong baseAddr = 0;
                    if (driver.GetModuleSummaryList(processId, out var mods) && mods.Length > 0)
                        baseAddr = mods[0].BaseAddress;

                    if (baseAddr == 0)
                    {
                        this.SafeInvoke(new Action(() => { view.AppendText("[Cannot determine module base address]\n"); }));
                        return;
                    }

                    // Read DOS header (64 bytes)
                    byte[] dosBuf = ReadBytesAt(baseAddr, 1024);
                    if (dosBuf == null || dosBuf.Length < 64)
                    {
                        this.SafeInvoke(new Action(() => { view.AppendText("[Failed to read DOS header]\n"); }));
                        return;
                    }

                    var sb = new StringBuilder();

                    // DOS Header
                    sb.AppendLine("╔══════════════════════════════════════════════════╗");
                    sb.AppendLine("║                IMAGE_DOS_HEADER                  ║");
                    sb.AppendLine("╚══════════════════════════════════════════════════╝");
                    sb.AppendLine();

                    ushort e_magic = BitConverter.ToUInt16(dosBuf, 0);
                    sb.AppendLine($"  e_magic    = 0x{e_magic:X4}  {(e_magic == 0x5A4D ? "\"MZ\" (valid)" : "INVALID")}");
                    sb.AppendLine($"  e_cblp     = 0x{BitConverter.ToUInt16(dosBuf, 2):X4}");
                    sb.AppendLine($"  e_cp       = 0x{BitConverter.ToUInt16(dosBuf, 4):X4}");
                    sb.AppendLine($"  e_crlc     = 0x{BitConverter.ToUInt16(dosBuf, 6):X4}");
                    sb.AppendLine($"  e_cparhdr  = 0x{BitConverter.ToUInt16(dosBuf, 8):X4}");
                    sb.AppendLine($"  e_minalloc = 0x{BitConverter.ToUInt16(dosBuf, 10):X4}");
                    sb.AppendLine($"  e_maxalloc = 0x{BitConverter.ToUInt16(dosBuf, 12):X4}");
                    sb.AppendLine($"  e_ss       = 0x{BitConverter.ToUInt16(dosBuf, 14):X4}");
                    sb.AppendLine($"  e_sp       = 0x{BitConverter.ToUInt16(dosBuf, 16):X4}");
                    sb.AppendLine($"  e_csum     = 0x{BitConverter.ToUInt16(dosBuf, 18):X4}");
                    sb.AppendLine($"  e_ip       = 0x{BitConverter.ToUInt16(dosBuf, 20):X4}");
                    sb.AppendLine($"  e_cs       = 0x{BitConverter.ToUInt16(dosBuf, 22):X4}");
                    sb.AppendLine($"  e_lfarlc   = 0x{BitConverter.ToUInt16(dosBuf, 24):X4}");
                    sb.AppendLine($"  e_ovno     = 0x{BitConverter.ToUInt16(dosBuf, 26):X4}");
                    int e_lfanew = BitConverter.ToInt32(dosBuf, 60);
                    sb.AppendLine($"  e_lfanew   = 0x{e_lfanew:X8}  (PE header offset)");
                    sb.AppendLine();

                    if (e_lfanew <= 0 || e_lfanew + 4 > dosBuf.Length)
                    {
                        sb.AppendLine("[Invalid e_lfanew - cannot read PE header]");
                        this.SafeInvoke(new Action(() => { view.Text = sb.ToString(); }));
                        return;
                    }

                    // Read PE header (need more data if e_lfanew is far)
                    byte[] peBuf = dosBuf;
                    if (e_lfanew + 512 > dosBuf.Length)
                        peBuf = ReadBytesAt(baseAddr + (ulong)e_lfanew, 1024);

                    if (peBuf == null)
                    {
                        sb.AppendLine("[Failed to read PE header]");
                        this.SafeInvoke(new Action(() => { view.Text = sb.ToString(); }));
                        return;
                    }

                    int peOff = (peBuf == dosBuf) ? e_lfanew : 0;
                    if (peOff + 24 > peBuf.Length)
                    {
                        sb.AppendLine("[PE header truncated]");
                        this.SafeInvoke(new Action(() => { view.Text = sb.ToString(); }));
                        return;
                    }

                    uint peSignature = BitConverter.ToUInt32(peBuf, peOff);
                    sb.AppendLine("╔══════════════════════════════════════════════════╗");
                    sb.AppendLine("║              IMAGE_NT_HEADERS                    ║");
                    sb.AppendLine("╚══════════════════════════════════════════════════╝");
                    sb.AppendLine();
                    sb.AppendLine($"  Signature  = 0x{peSignature:X8}  {(peSignature == 0x00004550 ? "\"PE\\0\\0\" (valid)" : "INVALID")}");
                    sb.AppendLine();

                    // File Header (20 bytes)
                    int fhOff = peOff + 4;
                    sb.AppendLine("  ── IMAGE_FILE_HEADER ──");
                    ushort machine = BitConverter.ToUInt16(peBuf, fhOff);
                    string machineStr = machine == 0x14C ? "x86 (I386)" : machine == 0x8664 ? "x64 (AMD64)" : machine == 0xAA64 ? "ARM64" : machine == 0x1C0 ? "ARM" : $"Unknown (0x{machine:X4})";
                    sb.AppendLine($"  Machine             = 0x{machine:X4}  {machineStr}");

                    ushort numSections = BitConverter.ToUInt16(peBuf, fhOff + 2);
                    sb.AppendLine($"  NumberOfSections    = {numSections}");
                    sb.AppendLine($"  TimeDateStamp       = 0x{BitConverter.ToUInt32(peBuf, fhOff + 4):X8}");
                    sb.AppendLine($"  PointerToSymbolTable= 0x{BitConverter.ToUInt32(peBuf, fhOff + 8):X8}");
                    sb.AppendLine($"  NumberOfSymbols     = {BitConverter.ToUInt32(peBuf, fhOff + 12)}");
                    ushort sizeOptHdr = BitConverter.ToUInt16(peBuf, fhOff + 16);
                    sb.AppendLine($"  SizeOfOptionalHeader= 0x{sizeOptHdr:X4}");

                    ushort characteristics = BitConverter.ToUInt16(peBuf, fhOff + 18);
                    var charFlags = new List<string>();
                    if ((characteristics & 0x0002) != 0) charFlags.Add("EXECUTABLE_IMAGE");
                    if ((characteristics & 0x0020) != 0) charFlags.Add("LARGE_ADDRESS_AWARE");
                    if ((characteristics & 0x0100) != 0) charFlags.Add("32BIT_MACHINE");
                    if ((characteristics & 0x2000) != 0) charFlags.Add("DLL");
                    sb.AppendLine($"  Characteristics     = 0x{characteristics:X4}  [{string.Join(", ", charFlags)}]");
                    sb.AppendLine();

                    // Optional Header
                    int optOff = fhOff + 20;
                    if (optOff + 2 > peBuf.Length)
                    {
                        sb.AppendLine("  [Optional header truncated]");
                        this.SafeInvoke(new Action(() => { view.Text = sb.ToString(); countLbl.Text = "Partial"; }));
                        return;
                    }

                    ushort magic = BitConverter.ToUInt16(peBuf, optOff);
                    bool is64 = magic == 0x20b;
                    sb.AppendLine("  ── IMAGE_OPTIONAL_HEADER ──");
                    sb.AppendLine($"  Magic               = 0x{magic:X4}  {(is64 ? "PE32+ (64-bit)" : "PE32 (32-bit)")}");
                    sb.AppendLine($"  LinkerVersion       = {peBuf[optOff + 2]}.{peBuf[optOff + 3]}");
                    sb.AppendLine($"  SizeOfCode          = 0x{BitConverter.ToUInt32(peBuf, optOff + 4):X8}");
                    sb.AppendLine($"  SizeOfInitializedData = 0x{BitConverter.ToUInt32(peBuf, optOff + 8):X8}");
                    sb.AppendLine($"  SizeOfUninitializedData = 0x{BitConverter.ToUInt32(peBuf, optOff + 12):X8}");
                    sb.AppendLine($"  AddressOfEntryPoint = 0x{BitConverter.ToUInt32(peBuf, optOff + 16):X8}");
                    sb.AppendLine($"  BaseOfCode          = 0x{BitConverter.ToUInt32(peBuf, optOff + 20):X8}");

                    if (is64)
                    {
                        if (optOff + 32 <= peBuf.Length)
                            sb.AppendLine($"  ImageBase           = 0x{BitConverter.ToUInt64(peBuf, optOff + 24):X16}");
                        sb.AppendLine($"  SectionAlignment    = 0x{BitConverter.ToUInt32(peBuf, optOff + 32):X8}");
                        sb.AppendLine($"  FileAlignment       = 0x{BitConverter.ToUInt32(peBuf, optOff + 36):X8}");
                        sb.AppendLine($"  OSVersion           = {BitConverter.ToUInt16(peBuf, optOff + 40)}.{BitConverter.ToUInt16(peBuf, optOff + 42)}");
                        sb.AppendLine($"  ImageVersion        = {BitConverter.ToUInt16(peBuf, optOff + 44)}.{BitConverter.ToUInt16(peBuf, optOff + 46)}");
                        sb.AppendLine($"  SubsystemVersion    = {BitConverter.ToUInt16(peBuf, optOff + 48)}.{BitConverter.ToUInt16(peBuf, optOff + 50)}");
                        sb.AppendLine($"  SizeOfImage         = 0x{BitConverter.ToUInt32(peBuf, optOff + 56):X8}");
                        sb.AppendLine($"  SizeOfHeaders       = 0x{BitConverter.ToUInt32(peBuf, optOff + 60):X8}");
                        sb.AppendLine($"  CheckSum            = 0x{BitConverter.ToUInt32(peBuf, optOff + 64):X8}");
                        ushort subsystem = BitConverter.ToUInt16(peBuf, optOff + 68);
                        string subStr = subsystem == 1 ? "NATIVE" : subsystem == 2 ? "WINDOWS_GUI" : subsystem == 3 ? "WINDOWS_CUI" : subsystem == 7 ? "POSIX_CUI" : subsystem == 9 ? "WINDOWS_CE_GUI" : $"OTHER ({subsystem})";
                        sb.AppendLine($"  Subsystem           = {subsystem}  ({subStr})");

                        ushort dllChars = BitConverter.ToUInt16(peBuf, optOff + 70);
                        var dllFlags = new List<string>();
                        if ((dllChars & 0x0020) != 0) dllFlags.Add("HIGH_ENTROPY_VA");
                        if ((dllChars & 0x0040) != 0) dllFlags.Add("DYNAMIC_BASE");
                        if ((dllChars & 0x0080) != 0) dllFlags.Add("FORCE_INTEGRITY");
                        if ((dllChars & 0x0100) != 0) dllFlags.Add("NX_COMPAT");
                        if ((dllChars & 0x1000) != 0) dllFlags.Add("APPCONTAINER");
                        if ((dllChars & 0x2000) != 0) dllFlags.Add("WDM_DRIVER");
                        if ((dllChars & 0x4000) != 0) dllFlags.Add("GUARD_CF");
                        if ((dllChars & 0x8000) != 0) dllFlags.Add("TERMINAL_SERVER_AWARE");
                        sb.AppendLine($"  DllCharacteristics  = 0x{dllChars:X4}  [{string.Join(", ", dllFlags)}]");

                        sb.AppendLine($"  SizeOfStackReserve  = 0x{BitConverter.ToUInt64(peBuf, optOff + 72):X16}");
                        sb.AppendLine($"  SizeOfStackCommit   = 0x{BitConverter.ToUInt64(peBuf, optOff + 80):X16}");
                        sb.AppendLine($"  SizeOfHeapReserve   = 0x{BitConverter.ToUInt64(peBuf, optOff + 88):X16}");
                        sb.AppendLine($"  SizeOfHeapCommit    = 0x{BitConverter.ToUInt64(peBuf, optOff + 96):X16}");
                        sb.AppendLine($"  NumberOfRvaAndSizes = {BitConverter.ToUInt32(peBuf, optOff + 108)}");
                    }
                    else
                    {
                        if (optOff + 28 <= peBuf.Length)
                            sb.AppendLine($"  ImageBase           = 0x{BitConverter.ToUInt32(peBuf, optOff + 28):X8}");
                        sb.AppendLine($"  SectionAlignment    = 0x{BitConverter.ToUInt32(peBuf, optOff + 32):X8}");
                        sb.AppendLine($"  FileAlignment       = 0x{BitConverter.ToUInt32(peBuf, optOff + 36):X8}");
                        sb.AppendLine($"  SizeOfImage         = 0x{BitConverter.ToUInt32(peBuf, optOff + 56):X8}");
                        sb.AppendLine($"  SizeOfHeaders       = 0x{BitConverter.ToUInt32(peBuf, optOff + 60):X8}");
                        sb.AppendLine($"  CheckSum            = 0x{BitConverter.ToUInt32(peBuf, optOff + 64):X8}");
                    }
                    sb.AppendLine();

                    // Data Directories
                    int dataDirOff = is64 ? optOff + 112 : optOff + 96;
                    string[] dirNames = { "Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
                        "Debug", "Architecture", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
                        "IAT", "DelayImport", "CLR", "Reserved" };

                    sb.AppendLine("  ── Data Directories ──");
                    for (int i = 0; i < 16 && dataDirOff + i * 8 + 8 <= peBuf.Length; i++)
                    {
                        uint rva = BitConverter.ToUInt32(peBuf, dataDirOff + i * 8);
                        uint sz = BitConverter.ToUInt32(peBuf, dataDirOff + i * 8 + 4);
                        if (rva != 0 || sz != 0)
                            sb.AppendLine($"  [{i,2}] {dirNames[i],-14} RVA: 0x{rva:X8}  Size: 0x{sz:X8}");
                    }
                    sb.AppendLine();

                    // Section Headers
                    int secTableOff = (peBuf == dosBuf ? e_lfanew : 0) + 4 + 20 + sizeOptHdr;
                    sb.AppendLine("╔══════════════════════════════════════════════════╗");
                    sb.AppendLine($"║        SECTION HEADERS ({numSections} sections)              ║");
                    sb.AppendLine("╚══════════════════════════════════════════════════╝");
                    sb.AppendLine();

                    for (int i = 0; i < numSections; i++)
                    {
                        int sOff = secTableOff + i * 40;
                        if (sOff + 40 > peBuf.Length)
                        {
                            sb.AppendLine($"  [Section {i}: truncated]");
                            break;
                        }

                        string secName = Encoding.ASCII.GetString(peBuf, sOff, 8).TrimEnd('\0');
                        uint vSize = BitConverter.ToUInt32(peBuf, sOff + 8);
                        uint vAddr = BitConverter.ToUInt32(peBuf, sOff + 12);
                        uint rawSize = BitConverter.ToUInt32(peBuf, sOff + 16);
                        uint rawPtr = BitConverter.ToUInt32(peBuf, sOff + 20);
                        uint chars = BitConverter.ToUInt32(peBuf, sOff + 36);

                        var secFlags = new List<string>();
                        if ((chars & 0x00000020) != 0) secFlags.Add("CODE");
                        if ((chars & 0x00000040) != 0) secFlags.Add("INITIALIZED_DATA");
                        if ((chars & 0x00000080) != 0) secFlags.Add("UNINITIALIZED_DATA");
                        if ((chars & 0x20000000) != 0) secFlags.Add("EXECUTE");
                        if ((chars & 0x40000000) != 0) secFlags.Add("READ");
                        if ((chars & 0x80000000u) != 0) secFlags.Add("WRITE");

                        sb.AppendLine($"  ── [{secName}] ──");
                        sb.AppendLine($"    VirtualSize     = 0x{vSize:X8}");
                        sb.AppendLine($"    VirtualAddress  = 0x{vAddr:X8}");
                        sb.AppendLine($"    SizeOfRawData   = 0x{rawSize:X8}");
                        sb.AppendLine($"    PointerToRawData= 0x{rawPtr:X8}");
                        sb.AppendLine($"    Characteristics = 0x{chars:X8}  [{string.Join(", ", secFlags)}]");
                        sb.AppendLine();
                    }

                    string result = sb.ToString();
                    this.SafeInvoke(new Action(() =>
                    {
                        view.Text = result;
                        countLbl.Text = $"{numSections} sections, {(is64 ? "x64" : "x86")}";
                        Log("PE headers loaded: {0} sections", numSections);
                    }));
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(new Action(() => { view.AppendText($"[Error: {ex.Message}]\n"); }));
                }
            });
        }

        private byte[] ReadBytesAt(ulong address, int size)
        {
            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, buf, size))
                    return null;
                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        // ---- UI Helper factories ----

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }

        private TextBox CreateTextBox(int width)
        {
            return new TextBox
            {
                Width = width, Margin = new Padding(2, 0, 4, 0),
                BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary,
                BorderStyle = BorderStyle.FixedSingle, Font = DarkTheme.UIMonoFont
            };
        }

        private Label MakeLabel(string text)
        {
            return new Label
            {
                Text = text, AutoSize = true, Margin = new Padding(0, 5, 4, 0),
                ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont
            };
        }

        private Control MakeSpacer(int width)
        {
            return new Panel { Width = width, Height = 1 };
        }

        private ListView CreateListView()
        {
            return new ListView
            {
                View = View.Details, FullRowSelect = true,
                MultiSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont
            };
        }

        private void Log(string message, params object[] args)
        {
            logBox.SafeInvoke(() =>
            {
                logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n");
            });
        }

        // ---- Attach / Detach ----

        private void AttachToProcess()
        {
            string methodName = "";

            switch (attachMethod)
            {
                case AttachMethod.Minimal:
                    methodName = "Minimal (Read Only)";
                    processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, processId);
                    break;

                case AttachMethod.Debug:
                    methodName = "Debug (Full Control)";
                    processHandle = OpenProcess(PROCESS_ALL_ACCESS | 0x00080000 /*PROCESS_QUERY_LIMITED_INFORMATION*/, false, processId);
                    if (processHandle == IntPtr.Zero)
                        processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                    break;

                case AttachMethod.SuspendFirst:
                    methodName = "Suspend-First";
                    int suspended = driver.SuspendProcess(processId);
                    Log("Suspended {0} threads before attach", suspended >= 0 ? suspended : 0);
                    System.Threading.Thread.Sleep(200);
                    processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                    if (processHandle == IntPtr.Zero)
                        processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, false, processId);
                    break;

                case AttachMethod.Kernel:
                    methodName = "Kernel (via driver)";
                    if (!driver.IsKernelMode)
                    {
                        infoLbl.Text = $"Failed to attach to {processName}";
                        statusLbl.Text = "Kernel attach requires kernel driver - load driver first";
                        statusLbl.ForeColor = DarkTheme.Error;
                        Log("Kernel attach failed: driver not loaded");
                        return;
                    }
                    processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                    break;

                default: // Standard
                    methodName = "Standard (R/W/Query)";
                    processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, processId);
                    if (processHandle == IntPtr.Zero)
                        processHandle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD, false, processId);
                    break;
            }

            if (processHandle != IntPtr.Zero && processHandle != INVALID_HANDLE_VALUE)
            {
                infoLbl.Text = $"Attached to {processName} (PID: {processId})";
                statusLbl.Text = $"Handle: 0x{processHandle.ToInt64():X}  |  {methodName}  |  Mode: {(driver.IsKernelMode ? "Kernel" : "Usermode")}";
                LoadThreads();
                Log("Attached to process {0} (PID: {1}) via {2}", processName, processId, methodName);
            }
            else
            {
                infoLbl.Text = $"Failed to attach to {processName}";
                statusLbl.Text = "Access denied - try running as admin or load kernel driver";
                statusLbl.ForeColor = DarkTheme.Error;
                Log("Attach failed ({0}): access denied", methodName);
            }
        }

        private void DetachFromProcess()
        {
            if (processHandle != IntPtr.Zero && processHandle != INVALID_HANDLE_VALUE)
            {
                CloseHandle(processHandle);
                processHandle = IntPtr.Zero;
                Log("Detached from process");
            }
        }

        // ---- Threads ----

        private void LoadThreads()
        {
            threadList.Items.Clear();
            var threads = EnumerateThreads(processId);

            foreach (var t in threads)
            {
                var lvi = new ListViewItem(t.ThreadId.ToString());
                lvi.SubItems.Add(t.Priority.ToString());
                lvi.SubItems.Add(t.StartAddress > 0 ? $"0x{t.StartAddress:X}" : "-");
                lvi.SubItems.Add(t.State);
                lvi.SubItems.Add(t.WaitReason);
                lvi.Tag = t;

                if (t.State == "Suspended")
                    lvi.ForeColor = DarkTheme.Warning;
                else if (t.State == "Terminated")
                    lvi.ForeColor = DarkTheme.TextMuted;
                else if (t.State == "Running")
                    lvi.ForeColor = DarkTheme.Success;
                else if (t.State == "Waiting")
                    lvi.ForeColor = DarkTheme.TextSecondary;

                threadList.Items.Add(lvi);
            }

            statusLbl.Text = $"Handle: 0x{processHandle.ToInt64():X}  |  {threads.Count} threads  |  Mode: {(driver.IsKernelMode ? "Kernel" : "Usermode")}";
            Log("Loaded {0} threads", threads.Count);
        }

        private List<ThreadInfo> EnumerateThreads(int pid)
        {
            var threads = new List<ThreadInfo>();

            // Use NtQuerySystemInformation for accurate thread states and start addresses
            int bufSize = 0x100000; // 1MB initial
            IntPtr buffer = Marshal.AllocHGlobal(bufSize);
            try
            {
                int status = NtQuerySystemInformation(5, buffer, bufSize, out int retLen);
                if (status == 0xC0000004) // STATUS_INFO_LENGTH_MISMATCH
                {
                    bufSize = retLen + 0x10000;
                    Marshal.FreeHGlobal(buffer);
                    buffer = Marshal.AllocHGlobal(bufSize);
                    status = NtQuerySystemInformation(5, buffer, bufSize, out retLen);
                }
                if (status != 0) return threads;

                int offset = 0;
                while (offset < retLen)
                {
                    IntPtr current = buffer + offset;
                    int nextOffset = Marshal.ReadInt32(current, 0);
                    int procId = Marshal.ReadInt32(current, IntPtr.Size == 8 ? 88 : 68); // UniqueProcessId offset

                    if (procId == pid)
                    {
                        int threadCount = Marshal.ReadInt32(current, IntPtr.Size == 8 ? 68 : 64); // NumberOfThreads
                        IntPtr threadArray = current + (IntPtr.Size == 8 ? 112 : 84); // Threads array offset

                        // SYSTEM_THREAD_INFORMATION (verified offsets from ReactOS/Process Hacker):
                        // x64:
                        //   KernelTime:0  UserTime:8  CreateTime:16  WaitTime:24
                        //   StartAddress:24(8bytes)  ClientId.PID:32  ClientId.TID:40
                        //   Priority:48  BasePriority:52  ContextSwitches:56
                        //   ThreadState:60  WaitReason:64  StructSize:72
                        // x86:
                        //   KernelTime:0  UserTime:8  CreateTime:16  WaitTime:24
                        //   StartAddress:24(4bytes)  ClientId.PID:28  ClientId.TID:32
                        //   Priority:36  BasePriority:40  ContextSwitches:44
                        //   ThreadState:48  WaitReason:52  StructSize:56

                        int offStartAddr = 24;
                        int offThreadId = IntPtr.Size == 8 ? 40 : 32;
                        int offBasePri = IntPtr.Size == 8 ? 52 : 40;
                        int offThreadState = IntPtr.Size == 8 ? 60 : 48;
                        int offWaitReason = IntPtr.Size == 8 ? 64 : 52;
                        int structSize = IntPtr.Size == 8 ? 72 : 56;

                        for (int i = 0; i < threadCount; i++)
                        {
                            IntPtr tInfo = threadArray + (i * structSize);

                            ulong startAddr = IntPtr.Size == 8
                                ? (ulong)Marshal.ReadInt64(tInfo, offStartAddr)
                                : (ulong)(uint)Marshal.ReadInt32(tInfo, offStartAddr);
                            uint tid = (uint)(IntPtr.Size == 8
                                ? Marshal.ReadInt64(tInfo, offThreadId)
                                : Marshal.ReadInt32(tInfo, offThreadId));
                            int basePri = Marshal.ReadInt32(tInfo, offBasePri);
                            int threadState = Marshal.ReadInt32(tInfo, offThreadState);
                            int waitReason = Marshal.ReadInt32(tInfo, offWaitReason);

                            var info = new ThreadInfo
                            {
                                ThreadId = tid,
                                Priority = basePri,
                                StartAddress = startAddr,
                                State = GetThreadStateString(threadState),
                                WaitReason = threadState == 5 ? GetWaitReasonString(waitReason) : "-"
                            };

                            // Check suspend count
                            IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, false, tid);
                            if (hThread != IntPtr.Zero)
                            {
                                try
                                {
                                    uint sc = SuspendThread(hThread);
                                    if (sc != uint.MaxValue)
                                    {
                                        if (sc > 0) info.State = "Suspended";
                                        ResumeThread(hThread);
                                    }
                                }
                                finally { CloseHandle(hThread); }
                            }

                            threads.Add(info);
                        }
                        break;
                    }

                    if (nextOffset == 0) break;
                    offset += nextOffset;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }

            return threads;
        }

        private static string GetThreadStateString(int state)
        {
            switch (state)
            {
                case 0: return "Initialized";
                case 1: return "Ready";
                case 2: return "Running";
                case 3: return "Standby";
                case 4: return "Terminated";
                case 5: return "Waiting";
                case 6: return "Transition";
                default: return $"State({state})";
            }
        }

        private static string GetWaitReasonString(int reason)
        {
            switch (reason)
            {
                case 0: return "Executive";
                case 1: return "FreePage";
                case 2: return "PageIn";
                case 3: return "PoolAllocation";
                case 4: return "DelayExecution";
                case 5: return "Suspended";
                case 6: return "UserRequest";
                case 7: return "WrExecutive";
                case 8: return "WrFreePage";
                case 9: return "WrPageIn";
                case 10: return "WrPoolAllocation";
                case 11: return "WrDelayExecution";
                case 12: return "WrSuspended";
                case 13: return "WrUserRequest";
                case 14: return "WrEventPair";
                case 15: return "WrQueue";
                case 16: return "WrLpcReceive";
                case 17: return "WrLpcReply";
                case 18: return "WrVirtualMemory";
                case 19: return "WrPageOut";
                case 20: return "WrRendezvous";
                default: return $"Wait({reason})";
            }
        }

        private void SuspendThread_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem item in threadList.SelectedItems)
            {
                var t = (ThreadInfo)item.Tag;
                IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, t.ThreadId);
                if (hThread != IntPtr.Zero) { SuspendThread(hThread); CloseHandle(hThread); }
                Log("Suspended thread {0}", t.ThreadId);
            }
            LoadThreads();
        }

        private void ResumeThread_Click(object sender, EventArgs e)
        {
            foreach (ListViewItem item in threadList.SelectedItems)
            {
                var t = (ThreadInfo)item.Tag;
                IntPtr hThread = OpenThread(THREAD_SUSPEND_RESUME, false, t.ThreadId);
                if (hThread != IntPtr.Zero) { ResumeThread(hThread); CloseHandle(hThread); }
                Log("Resumed thread {0}", t.ThreadId);
            }
            LoadThreads();
        }

        private void KillThread_Click(object sender, EventArgs e)
        {
            if (threadList.SelectedItems.Count == 0) return;
            var confirm = MessageBox.Show($"Kill {threadList.SelectedItems.Count} thread(s)?", "Kill Thread", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (confirm != DialogResult.Yes) return;

            foreach (ListViewItem item in threadList.SelectedItems)
            {
                var t = (ThreadInfo)item.Tag;
                IntPtr hThread = OpenThread(THREAD_TERMINATE, false, t.ThreadId);
                if (hThread != IntPtr.Zero) { TerminateThread(hThread, 1); CloseHandle(hThread); }
                Log("Killed thread {0}", t.ThreadId);
            }
            LoadThreads();
        }

        // ---- Memory R/W ----

        private void ReadMemory_Click(object sender, EventArgs e)
        {
            ulong addr;
            if (!ulong.TryParse(addressBox.Text.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out addr))
            { Log("Invalid address"); return; }

            int size;
            if (!int.TryParse(sizeBox.Text, out size) || size <= 0) size = 256;

            byte[] buffer = new byte[size];
            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero)
            {
                memoryView.Clear();
                memoryView.AppendText("[Failed to allocate buffer]\n");
                return;
            }
            bool ok = driver.CopyVirtualMemory(processId, (IntPtr)addr, buf, size);
            if (ok) Marshal.Copy(buf, buffer, 0, size);
            WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);

            if (!ok)
            {
                memoryView.Clear();
                memoryView.AppendText($"[Read failed at 0x{addr:X}]\n");
                Log("Read failed at 0x{0:X}", addr);
                return;
            }

            memoryView.Clear();
            memoryView.AppendText($"0x{addr:X16}  ({size} bytes)\n\n");

            // Find the type combo from parent controls
            ComboBox typeCombo = null;
            foreach (Control c in memoryView.Parent.Controls)
                if (c is FlowLayoutPanel fp) foreach (Control fc in fp.Controls) if (fc is ComboBox cb && cb.Items.Contains("Hex Dump")) { typeCombo = cb; break; }
            string interpretAs = typeCombo?.SelectedItem?.ToString() ?? "Hex Dump";

            switch (interpretAs)
            {
                case "Int32":
                    memoryView.AppendText("Offset      Value (dec)     Value (hex)   Unsigned\n");
                    memoryView.AppendText(new string('-', 60) + "\n");
                    for (int i = 0; i + 4 <= size; i += 4)
                    {
                        int val = BitConverter.ToInt32(buffer, i);
                        uint uval = BitConverter.ToUInt32(buffer, i);
                        memoryView.AppendText($"0x{i:X4}   {val,12}   0x{val:X8}   {uval}\n");
                    }
                    break;
                case "UInt32":
                    memoryView.AppendText("Offset      Value (dec)     Value (hex)\n");
                    memoryView.AppendText(new string('-', 50) + "\n");
                    for (int i = 0; i + 4 <= size; i += 4)
                    {
                        uint uval = BitConverter.ToUInt32(buffer, i);
                        memoryView.AppendText($"0x{i:X4}   {uval,12}   0x{uval:X8}\n");
                    }
                    break;
                case "Int64":
                    memoryView.AppendText("Offset      Value (dec)              Value (hex)\n");
                    memoryView.AppendText(new string('-', 60) + "\n");
                    for (int i = 0; i + 8 <= size; i += 8)
                    {
                        long val = BitConverter.ToInt64(buffer, i);
                        memoryView.AppendText($"0x{i:X4}   {val,20}   0x{val:X16}\n");
                    }
                    break;
                case "Float":
                    memoryView.AppendText("Offset      Value          Hex\n");
                    memoryView.AppendText(new string('-', 50) + "\n");
                    for (int i = 0; i + 4 <= size; i += 4)
                    {
                        float fval = BitConverter.ToSingle(buffer, i);
                        uint hex = BitConverter.ToUInt32(buffer, i);
                        memoryView.AppendText($"0x{i:X4}   {fval,-12:G7}   0x{hex:X8}\n");
                    }
                    break;
                case "Double":
                    memoryView.AppendText("Offset      Value                    Hex\n");
                    memoryView.AppendText(new string('-', 60) + "\n");
                    for (int i = 0; i + 8 <= size; i += 8)
                    {
                        double dval = BitConverter.ToDouble(buffer, i);
                        long hex = BitConverter.ToInt64(buffer, i);
                        memoryView.AppendText($"0x{i:X4}   {dval,-22:G15}   0x{hex:X16}\n");
                    }
                    break;
                case "ASCII String":
                    memoryView.AppendText(Encoding.ASCII.GetString(buffer).Replace("\0", "\\0").Replace("\r", "\\r").Replace("\n", "\\n"));
                    break;
                case "Unicode String":
                    memoryView.AppendText(Encoding.Unicode.GetString(buffer).Replace("\0", "\\0").Replace("\r", "\\r").Replace("\n", "\\n"));
                    break;
                case "Pointer Chain":
                    memoryView.AppendText("Offset      Pointer              -> Target\n");
                    memoryView.AppendText(new string('-', 55) + "\n");
                    for (int i = 0; i + 8 <= size; i += 8)
                    {
                        ulong ptr = BitConverter.ToUInt64(buffer, i);
                        if (ptr == 0) continue;
                        byte[] targetBuf = new byte[8];
                        IntPtr tBuf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)8,
                            WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                        bool tOk = false;
                        ulong target = 0;
                        if (tBuf != IntPtr.Zero)
                        {
                            tOk = driver.CopyVirtualMemory(processId, (IntPtr)ptr, tBuf, 8);
                            if (tOk) { Marshal.Copy(tBuf, targetBuf, 0, 8); target = BitConverter.ToUInt64(targetBuf, 0); }
                            WinApi.VirtualFree(tBuf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                        }
                        memoryView.AppendText($"0x{i:X4}   0x{ptr:X16}   -> 0x{target:X16}{(tOk ? "" : " [unreadable]")}\n");
                    }
                    break;
                default: // Hex Dump
                    for (int offset = 0; offset < size; offset += 16)
                    {
                        memoryView.AppendText($"{addr + (ulong)offset:X16}  ");
                        for (int i = 0; i < 16; i++)
                        {
                            if (offset + i < size)
                                memoryView.AppendText($"{buffer[offset + i]:X2} ");
                            else
                                memoryView.AppendText("   ");
                            if (i == 7) memoryView.AppendText(" ");
                        }
                        memoryView.AppendText(" |");
                        for (int i = 0; i < 16 && offset + i < size; i++)
                        {
                            byte b = buffer[offset + i];
                            memoryView.AppendText(b >= 0x20 && b < 0x7F ? ((char)b).ToString() : ".");
                        }
                        memoryView.AppendText("|\n");
                    }
                    break;
            }

            Log("Read {0} bytes at 0x{1:X} [{2}]", size, addr, interpretAs);
        }

        private void WriteMemory_Click(object sender, EventArgs e)
        {
            ulong addr;
            if (!ulong.TryParse(addressBox.Text.Replace("0x", ""), System.Globalization.NumberStyles.HexNumber, null, out addr))
            { Log("Invalid address"); return; }

            string hexInput = writeValueBox.Text.Replace(" ", "").Replace("0x", "");
            if (hexInput.Length == 0 || hexInput.Length % 2 != 0)
            { Log("Invalid hex bytes"); return; }

            byte[] bytes = new byte[hexInput.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                if (!byte.TryParse(hexInput.Substring(i * 2, 2), System.Globalization.NumberStyles.HexNumber, null, out bytes[i]))
                { Log("Invalid byte at position {0}", i); return; }
            }

            uint oldProtect;
            VirtualProtectEx(processHandle, (IntPtr)addr, (uint)bytes.Length, 0x40, out oldProtect);

            IntPtr buf = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, buf, bytes.Length);
            bool ok = WriteProcessMemory(processHandle, (IntPtr)addr, buf, bytes.Length, out _);
            Marshal.FreeHGlobal(buf);

            VirtualProtectEx(processHandle, (IntPtr)addr, (uint)bytes.Length, oldProtect, out _);

            Log(ok ? "Wrote {0} bytes at 0x{1:X}" : "Write failed at 0x{1:X}", bytes.Length, addr);
            if (ok) ReadMemory_Click(sender, e);
        }

        // ---- Memory Map ----

        private void LoadMemoryMap()
        {
            memoryMapList.Items.Clear();
            var regions = driver.EnumRegions(processId);

            foreach (var (baseAddr, regionSize, protect, state, type) in regions)
            {
                var lvi = new ListViewItem($"0x{baseAddr:X12}");
                lvi.SubItems.Add(FormatSize(regionSize));
                lvi.SubItems.Add(FormatProtect(protect));
                lvi.SubItems.Add(FormatState(state));
                lvi.SubItems.Add(FormatType(type));
                lvi.Tag = (baseAddr, regionSize);

                if ((protect & 0x40) != 0 || (protect & 0x20) != 0)
                    lvi.ForeColor = DarkTheme.Error;
                else if ((protect & 0x04) != 0 || (protect & 0x02) != 0)
                    lvi.ForeColor = DarkTheme.TextPrimary;
                else if (protect == 0x01)
                    lvi.ForeColor = DarkTheme.TextMuted;

                memoryMapList.Items.Add(lvi);
            }

            Log("Memory map: {0} regions", regions.Count);
        }

        private static string FormatSize(ulong bytes)
        {
            if (bytes >= 1024 * 1024) return $"{bytes / (1024 * 1024)} MB";
            if (bytes >= 1024) return $"{bytes / 1024} KB";
            return $"{bytes} B";
        }

        private static string FormatProtect(uint p)
        {
            var parts = new List<string>();
            if ((p & 0x01) != 0) parts.Add("NOACCESS");
            if ((p & 0x02) != 0) parts.Add("R");
            if ((p & 0x04) != 0) parts.Add("RW");
            if ((p & 0x10) != 0) parts.Add("RX");
            if ((p & 0x20) != 0) parts.Add("RWX");
            if ((p & 0x40) != 0) parts.Add("RWX");
            if ((p & 0x80) != 0) parts.Add("WC");
            if ((p & 0x100) != 0) parts.Add("+GUARD");
            return parts.Count > 0 ? string.Join("|", parts) : "0x" + p.ToString("X");
        }

        private static string FormatState(uint s)
        {
            if (s == 0x1000) return "COMMIT";
            if (s == 0x2000) return "RESERVE";
            if (s == 0x10000) return "FREE";
            return "0x" + s.ToString("X");
        }

        private static string FormatType(uint t)
        {
            if (t == 0x20000) return "PRIVATE";
            if (t == 0x40000) return "MAPPED";
            if (t == 0x1000000) return "IMAGE";
            return t == 0 ? "-" : "0x" + t.ToString("X");
        }

        // ---- DLL Injection ----

        private void BrowseInject_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog())
            {
                ofd.Filter = "DLL Files|*.dll|All Files|*.*";
                ofd.Title = "Select DLL to inject";
                if (ofd.ShowDialog() == DialogResult.OK)
                    injectPathBox.Text = ofd.FileName;
            }
        }

        private async void InjectDll_Click(object sender, EventArgs e)
        {
            string dllPath = injectPathBox.Text.Trim();
            if (string.IsNullOrEmpty(dllPath) || !File.Exists(dllPath))
            { Log("Select a valid DLL path first"); return; }

            if (processHandle == IntPtr.Zero || processHandle == INVALID_HANDLE_VALUE)
            { Log("Not attached to process"); return; }

            Log("Injecting {0} into PID {1}...", Path.GetFileName(dllPath), processId);

            await Task.Run(() =>
            {
                try
                {
                    byte[] dllPathBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
                    IntPtr remoteMem = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)dllPathBytes.Length, 0x1000 | 0x2000, 0x40);
                    if (remoteMem == IntPtr.Zero) { Log("VirtualAllocEx failed (code: {0})", Marshal.GetLastWin32Error()); return; }

                    IntPtr pathBuf = Marshal.AllocHGlobal(dllPathBytes.Length);
                    Marshal.Copy(dllPathBytes, 0, pathBuf, dllPathBytes.Length);
                    WriteProcessMemory(processHandle, remoteMem, pathBuf, dllPathBytes.Length, out _);
                    Marshal.FreeHGlobal(pathBuf);

                    IntPtr hKernel32 = GetModuleHandle("kernel32.dll");
                    IntPtr loadLibAddr = GetProcAddress(hKernel32, "LoadLibraryA");

                    IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, 0, loadLibAddr, remoteMem, 0, out _);
                    if (hThread != IntPtr.Zero)
                    {
                        WaitForSingleObject(hThread, 10000);
                        CloseHandle(hThread);
                        Log("DLL injected successfully via CreateRemoteThread + LoadLibraryA");
                    }
                    else
                    {
                        Log("CreateRemoteThread failed (code: {0})", Marshal.GetLastWin32Error());
                    }

                    VirtualFreeEx(processHandle, remoteMem, 0, 0x8000);
                }
                catch (Exception ex)
                {
                    Log("Injection error: {0}", ex.Message);
                }
            });
        }

        // ---- Process Info ----

        private void LoadProcessInfo(RichTextBox infoText)
        {
            infoText.Clear();
            infoText.AppendText($"Process: {processName}\n");
            infoText.AppendText($"PID: {processId}\n");
            infoText.AppendText($"Handle: 0x{processHandle.ToInt64():X}\n");
            infoText.AppendText($"Mode: {(driver.IsKernelMode ? "Kernel" : "Usermode")}\n\n");

            if (processHandle != IntPtr.Zero)
            {
                if (GetProcessTimes(processHandle, out var created, out var exit, out var kernel, out var user))
                {
                    long createdTicks = ((long)created.dwHighDateTime << 32) | (uint)created.dwLowDateTime;
                    var startTime = DateTime.FromFileTimeUtc(createdTicks);
                    infoText.AppendText($"Start Time: {startTime.ToLocalTime():yyyy-MM-dd HH:mm:ss}\n");
                }

                bool isWow64;
                IsWow64Process(processHandle, out isWow64);
                infoText.AppendText($"Architecture: {(isWow64 ? "x86 (WOW64)" : "x64")}\n");

                if (GetProcessMemoryInfo(processHandle, out var memCounters, Marshal.SizeOf<PROCESS_MEMORY_COUNTERS>()))
                {
                    infoText.AppendText($"Working Set: {memCounters.WorkingSetSize / 1024 / 1024} MB\n");
                    infoText.AppendText($"Peak Working Set: {memCounters.PeakWorkingSetSize / 1024 / 1024} MB\n");
                    infoText.AppendText($"Page File Usage: {memCounters.PagefileUsage / 1024 / 1024} MB\n");
                }

                uint handleCount;
                GetProcessHandleCount(processHandle, out handleCount);
                infoText.AppendText($"Handle Count: {handleCount}\n");

                bool isDebugged;
                CheckRemoteDebuggerPresent(processHandle, out isDebugged);
                infoText.AppendText($"Debugged: {(isDebugged ? "Yes" : "No")}\n");
            }
        }

        // ---- Debugger ----

        private void DebuggerCheck_Changed(object sender, EventArgs e)
        {
            debugModeCombo.Enabled = debuggerCheck.Checked;
            debugAttachBtn.Enabled = debuggerCheck.Checked;
            if (!debuggerCheck.Checked && debugEngine != null && debugEngine.IsAttached)
            {
                debugEngine.DetachDebugger();
                Log("Debugger detached via checkbox");
            }
        }

        private void DebugAttach_Click(object sender, EventArgs e)
        {
            if (!debuggerCheck.Checked) return;

            if (debugEngine != null && debugEngine.IsAttached)
            {
                debugEngine.DetachDebugger();
                debugAttachBtn.Text = "Attach";
                debugAttachBtn.BackColor = DarkTheme.AccentSubtle;
                Log("Debugger detached");
                return;
            }

            DebugMode mode;
            switch (debugModeCombo.SelectedIndex)
            {
                case 1: mode = DebugMode.Stealth; break;
                case 2: mode = DebugMode.VEH; break;
                case 3: mode = DebugMode.HardwareBP; break;
                case 4: mode = DebugMode.Kernel; break;
                default: mode = DebugMode.Standard; break;
            }

            debugEngine = new DebugAttachEngine(processId);
            debugEngine.OnLog += msg => Log(msg);
            debugEngine.OnDebugEvent += evt =>
            {
                try
                {
                    this.SafeInvoke(new Action(() =>
                    {
                        Log("[{0}] Event: {1}", evt.EventCode == 1 ? "EXC" : "DBG", evt.Description);
                    }));
                }
                catch { }
            };

            bool ok = debugEngine.AttachDebugger(processHandle, mode, driver, msg => Log(msg));

            if (ok)
            {
                debugAttachBtn.Text = "Detach";
                debugAttachBtn.BackColor = DarkTheme.Error;
                Log("Debugger attached ({0})", mode);
            }
            else
            {
                Log("Debugger attach failed");
                debugEngine.Dispose();
                debugEngine = null;
            }
        }

        // ---- P/Invoke ----

        private struct ThreadInfo
        {
            public uint ThreadId;
            public int Priority;
            public ulong StartAddress;
            public string State;
            public string WaitReason;
        }

        private const uint PROCESS_ALL_ACCESS = 0x1FFFFF;
        private const uint PROCESS_VM_WRITE = 0x0020;
        private const uint PROCESS_VM_OPERATION = 0x0008;
        private const uint PROCESS_CREATE_THREAD = 0x0002;
        private const uint THREAD_SUSPEND_RESUME = 0x0002;
        private const uint THREAD_QUERY_INFORMATION = 0x0040;
        private const uint THREAD_TERMINATE = 0x0001;
        private const uint TH32CS_SNAPTHREAD = 0x00000004;

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateThread(IntPtr hThread, uint dwExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize,
            IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out uint lpThreadId);

        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(IntPtr ThreadHandle, int ThreadInformationClass, byte[] ThreadInformation, int ThreadInformationLength, ref int ReturnLength);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, out int ReturnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessTimes(IntPtr hProcess, out FILETIME lpCreationTime, out FILETIME lpExitTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetProcessHandleCount(IntPtr hProcess, out uint lpdwHandleCount);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, out bool pbDebuggerPresent);

        [DllImport("psapi.dll", SetLastError = true)]
        private static extern bool GetProcessMemoryInfo(IntPtr hProcess, out PROCESS_MEMORY_COUNTERS counters, int cb);

        [StructLayout(LayoutKind.Sequential)]
        private struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_MEMORY_COUNTERS
        {
            public uint cb;
            public uint PageFaultCount;
            public uint PeakWorkingSetSize;
            public uint WorkingSetSize;
            public uint QuotaPeakPagedPoolUsage;
            public uint QuotaPagedPoolUsage;
            public uint QuotaPeakNonPagedPoolUsage;
            public uint QuotaNonPagedPoolUsage;
            public uint PagefileUsage;
            public uint PeakPagefileUsage;
        }
    }
}
