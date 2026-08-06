using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// IPC Object Enumerator - enumerates named pipes, mutexes, events,
    /// and sections owned by a process for IPC analysis.
    /// </summary>
    public class IpcObjectEnumerator : Form
    {
        private readonly int processId;
        private readonly string processName;

        private ListView objectList;
        private RichTextBox detailsBox;
        private Button refreshBtn;
        private ComboBox filterCombo;
        private Label statsLbl;

        private struct IpcObject
        {
            public string Type;
            public string Name;
            public string Handle;
            public string Details;
        }

        public IpcObjectEnumerator(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            RefreshObjects();
        }

        private void InitializeComponent()
        {
            Text = $"IPC Objects - {processName} (PID: {processId})";
            Size = new Size(900, 600);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshObjects();
            toolbar.Controls.Add(MakeLabel("Filter:"));
            filterCombo = new DarkComboBox { Width = 120 };
            filterCombo.Items.AddRange(new object[] { "All", "Pipe", "Mutex", "Event", "Section", "Semaphore" });
            filterCombo.SelectedIndex = 0;
            filterCombo.SelectedIndexChanged += (s, e) => RefreshObjects();
            toolbar.Controls.Add(filterCombo);
            statsLbl = new Label { Text = "", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.Add(statsLbl);

            // Split: list + details
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 350 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            objectList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            objectList.Columns.Add("Type", 80);
            objectList.Columns.Add("Name", 350);
            objectList.Columns.Add("Handle", 80);
            objectList.Columns.Add("Details", 300);
            objectList.Resize += (s, e) => { if (objectList.Columns.Count > 0) objectList.Columns[objectList.Columns.Count - 1].Width = -2; };

            detailsBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            split.Panel1.Controls.Add(objectList);
            split.Panel2.Controls.Add(detailsBox);

            Controls.Add(split);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void RefreshObjects()
        {
            objectList.Items.Clear();
            string filter = filterCombo.SelectedItem?.ToString() ?? "All";

            var objects = EnumerateIpcObjects();
            int count = 0;

            foreach (var obj in objects)
            {
                if (filter != "All" && !obj.Type.Equals(filter, StringComparison.OrdinalIgnoreCase))
                    continue;

                var lvi = new ListViewItem(obj.Type);
                lvi.SubItems.Add(obj.Name);
                lvi.SubItems.Add(obj.Handle);
                lvi.SubItems.Add(obj.Details);

                switch (obj.Type)
                {
                    case "Pipe": lvi.ForeColor = Color.FromArgb(88, 166, 255); break;
                    case "Mutex": lvi.ForeColor = Color.FromArgb(210, 153, 34); break;
                    case "Event": lvi.ForeColor = Color.FromArgb(63, 185, 80); break;
                    case "Section": lvi.ForeColor = Color.FromArgb(180, 140, 255); break;
                    case "Semaphore": lvi.ForeColor = Color.FromArgb(255, 165, 0); break;
                    default: lvi.ForeColor = DarkTheme.TextPrimary; break;
                }

                objectList.Items.Add(lvi);
                count++;
            }

            statsLbl.Text = $"Objects: {count}";
        }

        private List<IpcObject> EnumerateIpcObjects()
        {
            var result = new List<IpcObject>();

            try
            {
                // Use NtQuerySystemInformation with SystemHandleInformation to find handles
                // Then query each handle for its type and name
                int bufSize = 0x400000; // 4MB
                IntPtr buffer = Marshal.AllocHGlobal(bufSize);
                try
                {
                    int status = NtQuerySystemInformation(16, buffer, bufSize, out int retLen); // SystemHandleInformation = 16
                    if (status == unchecked((int)0xC0000004))
                    {
                        bufSize = retLen + 0x10000;
                        Marshal.FreeHGlobal(buffer);
                        buffer = Marshal.AllocHGlobal(bufSize);
                        status = NtQuerySystemInformation(16, buffer, bufSize, out retLen);
                    }
                    if (status != 0) return result;

                    // Parse handle table
                    long numHandles = Marshal.ReadInt64(buffer, 0);
                    int entrySize = IntPtr.Size == 8 ? 24 : 16;
                    int entryOffset = 8;

                    var seenNames = new HashSet<string>();

                    for (long i = 0; i < Math.Min(numHandles, 100000); i++)
                    {
                        int off = entryOffset + (int)(i * entrySize);
                        if (off + entrySize > retLen) break;

                        int pid = Marshal.ReadInt32(buffer, off);
                        if (pid != processId) continue;

                        short handleValue = Marshal.ReadInt16(buffer, off + (IntPtr.Size == 8 ? 8 : 4));

                        // Try to query handle type and name by duplicating the handle
                        try
                        {
                            IntPtr hProc = OpenProcess(0x0040, false, processId); // PROCESS_DUP_HANDLE
                            if (hProc == IntPtr.Zero) continue;

                            IntPtr hDup;
                            if (!DuplicateHandle(hProc, (IntPtr)handleValue, GetCurrentProcess(), out hDup, 0, false, 0x00000002)) // DUPLICATE_SAME_ACCESS
                            {
                                CloseHandle(hProc);
                                continue;
                            }

                            try
                            {
                                // Query object type
                                byte[] typeBuf = new byte[512];
                                int typeLen = 0;
                                if (NtQueryObject(hDup, 2, typeBuf, 512, out typeLen) == 0) // ObjectTypeInformation = 2
                                {
                                    int nameLen = Marshal.ReadInt32(typeBuf, 0);
                                    if (nameLen > 0 && nameLen < 256)
                                    {
                                        IntPtr namePtr = Marshal.ReadIntPtr(typeBuf, IntPtr.Size);
                                        if (namePtr != IntPtr.Zero)
                                        {
                                            string typeName = Marshal.PtrToStringUni(namePtr, nameLen / 2);

                                            // Only track IPC-relevant types
                                            if (typeName == "File" || typeName == "Mutant" || typeName == "Event" ||
                                                typeName == "Section" || typeName == "Semaphore" || typeName == "ALPC Port" ||
                                                typeName == "Directory" || typeName == "KeyedEvent")
                                            {
                                                // Query object name
                                                byte[] nameBuf = new byte[1024];
                                                int objNameLen = 0;
                                                string objName = "";
                                                if (NtQueryObject(hDup, 1, nameBuf, 1024, out objNameLen) == 0) // ObjectNameInformation = 1
                                                {
                                                    int nLen = Marshal.ReadInt32(nameBuf, 0);
                                                    if (nLen > 0 && nLen < 512)
                                                    {
                                                        IntPtr nPtr = Marshal.ReadIntPtr(nameBuf, IntPtr.Size);
                                                        if (nPtr != IntPtr.Zero)
                                                            objName = Marshal.PtrToStringUni(nPtr, nLen / 2);
                                                    }
                                                }

                                                // Map type names
                                                string displayType = typeName;
                                                if (typeName == "Mutant") displayType = "Mutex";

                                                // Filter to IPC-relevant names
                                                if (!string.IsNullOrEmpty(objName) &&
                                                    (objName.Contains("\\Device\\NamedPipe\\") ||
                                                     objName.Contains("\\BaseNamedObjects\\") ||
                                                     objName.Contains("\\Sessions\\") ||
                                                     typeName == "Section" || typeName == "ALPC Port"))
                                                {
                                                    string key = $"{displayType}:{objName}";
                                                    if (!seenNames.Contains(key))
                                                    {
                                                        seenNames.Add(key);
                                                        result.Add(new IpcObject
                                                        {
                                                            Type = displayType,
                                                            Name = objName,
                                                            Handle = $"0x{handleValue:X4}",
                                                            Details = GetTypeDetails(typeName, objName)
                                                        });
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            finally { CloseHandle(hDup); }

                            CloseHandle(hProc);
                        }
                        catch { }
                    }
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            catch { }

            return result;
        }

        private string GetTypeDetails(string typeName, string objName)
        {
            if (objName.Contains("\\Device\\NamedPipe\\"))
            {
                string pipeName = objName.Replace("\\Device\\NamedPipe\\", "");
                return $"Named pipe: {pipeName}";
            }
            if (objName.Contains("\\BaseNamedObjects\\"))
            {
                string obj = objName.Replace("\\BaseNamedObjects\\", "");
                return $"Global/shared: {obj}";
            }
            if (objName.Contains("\\Sessions\\"))
            {
                int idx = objName.LastIndexOf('\\');
                if (idx >= 0)
                    return $"Session object: {objName.Substring(idx + 1)}";
            }
            return objName;
        }

        // ==================== P/Invoke ====================

        [DllImport("ntdll.dll")] private static extern int NtQuerySystemInformation(int c, IntPtr b, int s, out int r);
        [DllImport("ntdll.dll")] private static extern int NtQueryObject(IntPtr h, int c, byte[] b, int s, out int r);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr OpenProcess(uint a, bool i, int p);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool DuplicateHandle(IntPtr hp, IntPtr h, IntPtr ht, out IntPtr hd, uint a, bool i, uint o);
        [DllImport("kernel32.dll", SetLastError = true)] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll", SetLastError = true)] private static extern bool CloseHandle(IntPtr h);

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
    }
}
