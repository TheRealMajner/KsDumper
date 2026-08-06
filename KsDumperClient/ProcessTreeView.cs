using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Process Tree View showing parent-child process hierarchy with color-coded
    /// process types, integrity levels, and protection status.
    /// </summary>
    public class ProcessTreeView : Form
    {
        private readonly IMemoryReader driver;
        private TreeView processTree;
        private RichTextBox detailsBox;
        private Button refreshBtn;
        private Button expandAllBtn;
        private Button collapseAllBtn;
        private CheckBox showSystemCheck;
        private Label statsLbl;

        private struct ProcessNode
        {
            public int Pid;
            public int ParentPid;
            public string Name;
            public string Path;
            public string User;
            public string Integrity;
            public long MemoryMB;
            public int ThreadCount;
            public int HandleCount;
            public bool IsElevated;
            public bool IsDotNet;
            public bool IsProtected;
            public bool IsSuspended;
            public bool IsWow64;
            public DateTime StartTime;
        }

        public ProcessTreeView(IMemoryReader driver)
        {
            this.driver = driver;
            InitializeComponent();
            RefreshTree();
        }

        private void InitializeComponent()
        {
            Text = "Process Tree";
            Size = new Size(900, 700);
            StartPosition = FormStartPosition.CenterParent;
            MinimumSize = new Size(700, 500);
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshTree();
            expandAllBtn = CreateButton("Expand All", 80);
            expandAllBtn.Click += (s, e) => processTree.ExpandAll();
            collapseAllBtn = CreateButton("Collapse All", 85);
            collapseAllBtn.Click += (s, e) => processTree.CollapseAll();
            showSystemCheck = new DarkCheckBox { Text = "Show System", AutoSize = true, Checked = true, Margin = new Padding(12, 4, 0, 0) };
            showSystemCheck.CheckedChanged += (s, e) => RefreshTree();
            statsLbl = new Label { Text = "Processes: 0", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };

            toolbar.Controls.AddRange(new Control[] { refreshBtn, expandAllBtn, collapseAllBtn, showSystemCheck, statsLbl });

            // Split: tree + details
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 450 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            // Process tree
            processTree = new TreeView
            {
                Dock = DockStyle.Fill, BorderStyle = BorderStyle.None,
                BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont, ShowLines = true, HideSelection = false,
                FullRowSelect = true, ShowPlusMinus = true, Indent = 20
            };
            processTree.AfterSelect += ProcessTree_AfterSelect;

            // Details panel
            detailsBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            split.Panel1.Controls.Add(processTree);
            split.Panel2.Controls.Add(detailsBox);

            Controls.Add(split);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshTree()
        {
            processTree.BeginUpdate();
            processTree.Nodes.Clear();

            try
            {
                var processes = EnumerateProcesses();
                var byParent = new Dictionary<int, List<ProcessNode>>();

                foreach (var proc in processes)
                {
                    if (!showSystemCheck.Checked)
                    {
                        if (proc.Path.StartsWith(Environment.GetFolderPath(Environment.SpecialFolder.Windows), StringComparison.OrdinalIgnoreCase) ||
                            proc.Path.StartsWith(@"\"))
                            continue;
                    }

                    if (!byParent.ContainsKey(proc.ParentPid))
                        byParent[proc.ParentPid] = new List<ProcessNode>();
                    byParent[proc.ParentPid].Add(proc);
                }

                // Build tree starting from root processes (parent = 0 or not found)
                var rootPids = new HashSet<int> { 0, 4 }; // System Idle and System
                BuildTreeNodes(processTree.Nodes, rootPids, byParent, processes, 0);

                processTree.ExpandAll();
                statsLbl.Text = $"Processes: {processes.Count}";
            }
            catch (Exception ex)
            {
                detailsBox.Text = $"Error building process tree: {ex.Message}";
            }
            finally
            {
                processTree.EndUpdate();
            }
        }

        private void BuildTreeNodes(TreeNodeCollection parentNodes, HashSet<int> parentPids, Dictionary<int, List<ProcessNode>> byParent, List<ProcessNode> allProcesses, int depth)
        {
            if (depth > 20) return; // Prevent infinite recursion

            foreach (int pid in parentPids)
            {
                if (!byParent.ContainsKey(pid)) continue;

                foreach (var proc in byParent[pid])
                {
                    string label = $"[{proc.Pid}] {proc.Name}";
                    if (proc.IsElevated) label += " ★";
                    if (proc.IsProtected) label += " 🔒";
                    if (proc.IsDotNet) label += " .NET";

                    var node = parentNodes.Add(label);
                    node.Tag = proc;

                    // Color coding
                    if (proc.IsProtected)
                        node.ForeColor = Color.FromArgb(248, 81, 73); // Red
                    else if (proc.IsElevated && proc.Integrity == "System")
                        node.ForeColor = Color.FromArgb(188, 140, 255); // Purple
                    else if (proc.IsElevated)
                        node.ForeColor = Color.FromArgb(88, 166, 255); // Blue
                    else if (proc.IsDotNet)
                        node.ForeColor = Color.FromArgb(63, 185, 80); // Green
                    else if (proc.IsSuspended)
                        node.ForeColor = Color.FromArgb(139, 148, 158); // Gray
                    else
                        node.ForeColor = DarkTheme.TextPrimary;

                    // Recurse into children
                    var childPids = new HashSet<int> { proc.Pid };
                    BuildTreeNodes(node.Nodes, childPids, byParent, allProcesses, depth + 1);
                }
            }
        }

        private void ProcessTree_AfterSelect(object sender, TreeViewEventArgs e)
        {
            if (e.Node?.Tag == null) { detailsBox.Clear(); return; }
            var proc = (ProcessNode)e.Node.Tag;

            detailsBox.Clear();
            detailsBox.SelectionColor = DarkTheme.Accent;
            detailsBox.AppendText($"Process: {proc.Name}\n");
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText(new string('═', 60) + "\n\n");

            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            detailsBox.AppendText($"  PID:           {proc.Pid}\n");
            detailsBox.AppendText($"  Parent PID:    {proc.ParentPid}\n");
            detailsBox.AppendText($"  Path:          {proc.Path}\n");
            detailsBox.AppendText($"  User:          {proc.User}\n");

            detailsBox.SelectionColor = GetIntegrityColor(proc.Integrity);
            detailsBox.AppendText($"  Integrity:     {proc.Integrity}\n");

            detailsBox.SelectionColor = DarkTheme.TextPrimary;
            detailsBox.AppendText($"  Memory:        {proc.MemoryMB} MB\n");
            detailsBox.AppendText($"  Threads:       {proc.ThreadCount}\n");
            detailsBox.AppendText($"  Handles:       {proc.HandleCount}\n");
            detailsBox.AppendText($"  Architecture:  {(proc.IsWow64 ? "x86 (WOW64)" : "x64")}\n");
            detailsBox.AppendText($"  Start Time:    {proc.StartTime:yyyy-MM-dd HH:mm:ss}\n\n");

            // Flags
            detailsBox.SelectionColor = DarkTheme.TextSecondary;
            detailsBox.AppendText("  Flags:\n");
            detailsBox.SelectionColor = DarkTheme.TextPrimary;

            var flags = new List<string>();
            if (proc.IsElevated) flags.Add("Elevated");
            if (proc.IsProtected) flags.Add("Protected");
            if (proc.IsDotNet) flags.Add(".NET");
            if (proc.IsSuspended) flags.Add("Suspended");
            if (proc.IsWow64) flags.Add("WOW64");

            if (flags.Count > 0)
            {
                foreach (var flag in flags)
                {
                    detailsBox.SelectionColor = GetFlagColor(flag);
                    detailsBox.AppendText($"    • {flag}\n");
                }
            }
            else
            {
                detailsBox.AppendText("    (none)\n");
            }
        }

        private Color GetIntegrityColor(string integrity)
        {
            switch (integrity)
            {
                case "System": return Color.FromArgb(188, 140, 255);
                case "High": return Color.FromArgb(88, 166, 255);
                case "Medium": return DarkTheme.TextPrimary;
                case "Low": return Color.FromArgb(210, 153, 34);
                case "Untrusted": return Color.FromArgb(248, 81, 73);
                default: return DarkTheme.TextMuted;
            }
        }

        private Color GetFlagColor(string flag)
        {
            switch (flag)
            {
                case "Elevated": return Color.FromArgb(88, 166, 255);
                case "Protected": return Color.FromArgb(248, 81, 73);
                case ".NET": return Color.FromArgb(63, 185, 80);
                case "Suspended": return Color.FromArgb(139, 148, 158);
                case "WOW64": return Color.FromArgb(210, 153, 34);
                default: return DarkTheme.TextPrimary;
            }
        }

        private List<ProcessNode> EnumerateProcesses()
        {
            var result = new List<ProcessNode>();
            string sysRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

            foreach (var proc in Process.GetProcesses())
            {
                try
                {
                    var node = new ProcessNode
                    {
                        Pid = proc.Id,
                        ParentPid = 0,
                        Name = proc.ProcessName,
                        Path = "",
                        User = "",
                        Integrity = "Medium",
                        MemoryMB = proc.WorkingSet64 / (1024 * 1024),
                        ThreadCount = proc.Threads.Count,
                        HandleCount = proc.HandleCount,
                        IsElevated = false,
                        IsDotNet = false,
                        IsProtected = false,
                        IsSuspended = false,
                        IsWow64 = false,
                        StartTime = DateTime.MinValue
                    };

                    try { node.StartTime = proc.StartTime; } catch { }
                    try { node.Path = proc.MainModule?.FileName ?? ""; } catch { node.Path = proc.ProcessName; }

                    // Parent PID via NtQueryInformationProcess
                    try
                    {
                        IntPtr hProc = OpenProcess(0x0400, false, proc.Id);
                        if (hProc != IntPtr.Zero)
                        {
                            byte[] pbi = new byte[48];
                            int retLen = 0;
                            if (NtQueryInformationProcess(hProc, 0, pbi, pbi.Length, ref retLen) == 0)
                            {
                                // PROCESS_BASIC_INFORMATION: ExitStatus(8), PebBaseAddress(8), AffinityMask(8), BasePriority(8), UniqueProcessId(8), InheritedFromUniqueProcessId(8)
                                node.ParentPid = (int)BitConverter.ToInt64(pbi, 40);
                            }

                            // Check WOW64
                            bool isWow64;
                            IsWow64Process(hProc, out isWow64);
                            node.IsWow64 = isWow64;

                            // Check elevation via token
                            IntPtr hToken;
                            if (OpenProcessToken(hProc, 0x0008, out hToken))
                            {
                                uint elevType = 0;
                                uint retLen2 = 0;
                                GetTokenInformation(hToken, 18, ref elevType, 4, out retLen2);
                                node.IsElevated = elevType == 2;

                                // Integrity level
                                byte[] intBuf = new byte[256];
                                if (GetTokenInformation(hToken, 25, intBuf, 256, out retLen2))
                                {
                                    IntPtr pSid = Marshal.ReadIntPtr(intBuf, 0);
                                    if (pSid != IntPtr.Zero)
                                    {
                                        int subAuthCount = Marshal.ReadByte(pSid, 1);
                                        if (subAuthCount > 0)
                                        {
                                            uint rid = (uint)Marshal.ReadInt32(pSid, 8 + (subAuthCount - 1) * 4);
                                            if (rid >= 0x4000) node.Integrity = "System";
                                            else if (rid >= 0x3000) node.Integrity = "High";
                                            else if (rid >= 0x2000) node.Integrity = "Medium";
                                            else if (rid >= 0x1000) node.Integrity = "Low";
                                            else node.Integrity = "Untrusted";
                                        }
                                    }
                                }

                                // User name
                                byte[] userBuf = new byte[512];
                                if (GetTokenInformation(hToken, 1, userBuf, 512, out retLen2))
                                {
                                    IntPtr pUserSid = Marshal.ReadIntPtr(userBuf, 0);
                                    if (pUserSid != IntPtr.Zero)
                                    {
                                        IntPtr pName = IntPtr.Zero, pDomain = IntPtr.Zero;
                                        uint nameLen = 0, domainLen = 0;
                                        int sidUse = 0;
                                        LookupAccountSid(null, pUserSid, pName, ref nameLen, pDomain, ref domainLen, ref sidUse);
                                        if (nameLen > 0)
                                        {
                                            pName = Marshal.AllocHGlobal((int)nameLen * 2);
                                            pDomain = Marshal.AllocHGlobal((int)domainLen * 2);
                                            try
                                            {
                                                if (LookupAccountSid(null, pUserSid, pName, ref nameLen, pDomain, ref domainLen, ref sidUse))
                                                {
                                                    string domain = Marshal.PtrToStringUni(pDomain);
                                                    string user = Marshal.PtrToStringUni(pName);
                                                    node.User = string.IsNullOrEmpty(domain) ? user : $"{domain}\\{user}";
                                                }
                                            }
                                            finally
                                            {
                                                Marshal.FreeHGlobal(pName);
                                                Marshal.FreeHGlobal(pDomain);
                                            }
                                        }
                                    }
                                }
                                CloseHandle(hToken);
                            }

                            // Check .NET
                            try
                            {
                                foreach (ProcessModule mod in proc.Modules)
                                {
                                    string modName = mod.ModuleName.ToLower();
                                    if (modName == "mscoree.dll" || modName == "clr.dll" || modName == "coreclr.dll" ||
                                        modName == "mscorlib.dll" || modName == "clrjit.dll")
                                    {
                                        node.IsDotNet = true;
                                        break;
                                    }
                                }
                            }
                            catch { }

                            // Check suspended (all threads waiting/suspended)
                            if (node.ThreadCount > 0)
                            {
                                bool allSuspended = true;
                                foreach (ProcessThread t in proc.Threads)
                                {
                                    if (t.ThreadState != ThreadState.Wait || t.WaitReason != ThreadWaitReason.Suspended)
                                    {
                                        allSuspended = false;
                                        break;
                                    }
                                }
                                node.IsSuspended = allSuspended;
                            }

                            // Check protected (can't open with full access)
                            IntPtr hFull = OpenProcess(0x1FFFFF, false, proc.Id);
                            if (hFull == IntPtr.Zero) node.IsProtected = true;
                            else CloseHandle(hFull);

                            CloseHandle(hProc);
                        }
                    }
                    catch { }

                    result.Add(node);
                }
                catch { }
            }

            return result;
        }

        // ==================== P/Invoke ====================

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr hProcess, uint access, out IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr hToken, int infoClass, byte[] buffer, uint bufSize, out uint retLen);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr hToken, int infoClass, ref uint buffer, uint bufSize, out uint retLen);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupAccountSid(string system, IntPtr sid, IntPtr name, ref uint nameLen, IntPtr domain, ref uint domainLen, ref int use);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr hProcess, int infoClass, byte[] buffer, int bufSize, ref int retLen);

        private Button CreateButton(string text, int width)
        {
            var btn = new Button { Text = text, Size = new Size(width, 26), Margin = new Padding(2, 0, 4, 0) };
            DarkControlsHelper.StyleButton(btn);
            return btn;
        }
    }
}
