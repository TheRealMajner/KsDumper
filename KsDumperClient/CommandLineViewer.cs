using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Process Command Line Viewer - reads the full command line and working directory
    /// from a target process's PEB.
    /// </summary>
    public class CommandLineViewer : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private RichTextBox cmdLineBox;
        private RichTextBox workDirBox;
        private RichTextBox detailsBox;
        private Button refreshBtn;

        public CommandLineViewer(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            RefreshInfo();
        }

        private void InitializeComponent()
        {
            Text = $"Command Line - {processName} (PID: {processId})";
            Size = new Size(800, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshInfo();
            toolbar.Controls.Add(refreshBtn);

            // Main layout
            var mainPanel = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8) };

            // Command Line section
            var cmdLabel = new Label { Text = "  Command Line", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            cmdLineBox = new RichTextBox { Dock = DockStyle.Top, Height = 80, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.Accent, ScrollBars = RichTextBoxScrollBars.Vertical, WordWrap = true };

            // Working Directory section
            var workLabel = new Label { Text = "  Working Directory", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            workDirBox = new RichTextBox { Dock = DockStyle.Top, Height = 50, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = Color.FromArgb(88, 166, 255), ScrollBars = RichTextBoxScrollBars.Vertical, WordWrap = true };

            // Details section
            var detailsLabel = new Label { Text = "  PEB Details", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            detailsBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };

            mainPanel.Controls.Add(detailsBox);
            mainPanel.Controls.Add(detailsLabel);
            mainPanel.Controls.Add(workDirBox);
            mainPanel.Controls.Add(workLabel);
            mainPanel.Controls.Add(cmdLineBox);
            mainPanel.Controls.Add(cmdLabel);

            Controls.Add(mainPanel);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshInfo()
        {
            cmdLineBox.Clear();
            workDirBox.Clear();
            detailsBox.Clear();

            try
            {
                IntPtr hProc = WinApi.OpenProcess(0x0400 | 0x0010, false, processId);
                if (hProc == IntPtr.Zero) { detailsBox.Text = "Failed to open process"; return; }

                try
                {
                    // Get PEB
                    byte[] pbi = new byte[48];
                    int retLen = 0;
                    if (NtQueryInformationProcess(hProc, 0, pbi, pbi.Length, ref retLen) != 0) { detailsBox.Text = "Failed to get PEB"; return; }
                    ulong pebAddr = BitConverter.ToUInt64(pbi, 8);
                    if (pebAddr == 0) { detailsBox.Text = "PEB address is null"; return; }

                    // Read ProcessParameters pointer (PEB + 0x20 on x64)
                    byte[] ppBuf = new byte[8];
                    IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)8, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) { detailsBox.Text = "Failed to allocate memory"; return; }
                    try
                    {
                        if (!driver.CopyVirtualMemory(processId, (IntPtr)(pebAddr + 0x20), buf, 8))
                        {
                            detailsBox.Text = "Failed to read ProcessParameters";
                            return;
                        }
                        Marshal.Copy(buf, ppBuf, 0, 8);
                    }
                    finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }

                    ulong ppAddr = BitConverter.ToUInt64(ppBuf, 0);
                    if (ppAddr == 0) { detailsBox.Text = "ProcessParameters is null"; return; }

                    // Read RTL_USER_PROCESS_PARAMETERS
                    // CommandLine: offset 0x70, UNICODE_STRING (Length(2) + MaxLen(2) + Padding(4) + Buffer(8)) = 16 bytes
                    // CurrentDirectory: offset 0x40, CURDIR (DosPath UNICODE_STRING(16) + Handle(8)) = 24 bytes
                    byte[] ppData = new byte[0x100];
                    buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)0x100, WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                    if (buf == IntPtr.Zero) { detailsBox.Text = "Failed to allocate memory"; return; }
                    try
                    {
                        if (!driver.CopyVirtualMemory(processId, (IntPtr)ppAddr, buf, 0x100))
                        {
                            detailsBox.Text = "Failed to read RTL_USER_PROCESS_PARAMETERS";
                            return;
                        }
                        Marshal.Copy(buf, ppData, 0, 0x100);
                    }
                    finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }

                    // Parse CommandLine UNICODE_STRING at offset 0x70
                    ushort cmdLen = BitConverter.ToUInt16(ppData, 0x70);
                    ushort cmdMaxLen = BitConverter.ToUInt16(ppData, 0x72);
                    ulong cmdBufPtr = BitConverter.ToUInt64(ppData, 0x78);

                    string cmdLine = "";
                    if (cmdBufPtr != 0 && cmdLen > 0)
                    {
                        byte[] cmdBuf = new byte[cmdLen + 2];
                        buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)(cmdLen + 2), WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                        if (buf != IntPtr.Zero)
                        {
                            try
                            {
                                if (driver.CopyVirtualMemory(processId, (IntPtr)cmdBufPtr, buf, cmdLen + 2))
                                {
                                    Marshal.Copy(buf, cmdBuf, 0, cmdLen + 2);
                                    cmdLine = Encoding.Unicode.GetString(cmdBuf, 0, cmdLen);
                                }
                            }
                            finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
                        }
                    }

                    // Parse CurrentDirectory at offset 0x40
                    // CURDIR: DosPath (UNICODE_STRING at offset 0) + Handle (8 bytes at offset 16)
                    ushort dirLen = BitConverter.ToUInt16(ppData, 0x40);
                    ushort dirMaxLen = BitConverter.ToUInt16(ppData, 0x42);
                    ulong dirBufPtr = BitConverter.ToUInt64(ppData, 0x48);

                    string workDir = "";
                    if (dirBufPtr != 0 && dirLen > 0)
                    {
                        byte[] dirBuf = new byte[dirLen + 2];
                        buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)(dirLen + 2), WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                        if (buf != IntPtr.Zero)
                        {
                            try
                            {
                                if (driver.CopyVirtualMemory(processId, (IntPtr)dirBufPtr, buf, dirLen + 2))
                                {
                                    Marshal.Copy(buf, dirBuf, 0, dirLen + 2);
                                    workDir = Encoding.Unicode.GetString(dirBuf, 0, dirLen);
                                }
                            }
                            finally { WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
                        }
                    }

                    // Display
                    cmdLineBox.Text = string.IsNullOrEmpty(cmdLine) ? "(empty)" : cmdLine;
                    workDirBox.Text = string.IsNullOrEmpty(workDir) ? "(empty)" : workDir;

                    // PEB details
                    detailsBox.SelectionColor = DarkTheme.TextPrimary;
                    detailsBox.AppendText($"  PEB Address:        0x{pebAddr:X}\n");
                    detailsBox.AppendText($"  ProcessParameters:  0x{ppAddr:X}\n");
                    detailsBox.AppendText($"  CmdLine Buffer:     0x{cmdBufPtr:X} ({cmdLen} bytes)\n");
                    detailsBox.AppendText($"  CmdLine MaxLen:     {cmdMaxLen}\n");
                    detailsBox.AppendText($"  WorkDir Buffer:     0x{dirBufPtr:X} ({dirLen} bytes)\n");
                    detailsBox.AppendText($"  WorkDir MaxLen:     {dirMaxLen}\n\n");

                    // Parse command line arguments
                    if (!string.IsNullOrEmpty(cmdLine))
                    {
                        detailsBox.SelectionColor = DarkTheme.TextSecondary;
                        detailsBox.AppendText("  Parsed Arguments:\n");
                        detailsBox.SelectionColor = DarkTheme.TextPrimary;

                        string[] parts = cmdLine.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                        for (int i = 0; i < parts.Length; i++)
                        {
                            if (i == 0)
                            {
                                detailsBox.SelectionColor = Color.FromArgb(63, 185, 80);
                                detailsBox.AppendText($"    [0] Executable: {parts[i]}\n");
                            }
                            else
                            {
                                detailsBox.SelectionColor = DarkTheme.TextPrimary;
                                detailsBox.AppendText($"    [{i}] {parts[i]}\n");
                            }
                        }
                    }
                }
                finally { CloseHandle(hProc); }
            }
            catch (Exception ex) { detailsBox.Text = $"Error: {ex.Message}"; }
        }

        [DllImport("ntdll.dll")] private static extern int NtQueryInformationProcess(IntPtr h, int c, byte[] b, int s, ref int r);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
