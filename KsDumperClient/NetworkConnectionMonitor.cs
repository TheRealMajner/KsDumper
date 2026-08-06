using System;
using System.Collections.Generic;
using System.Drawing;
using System.Net;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// Network Connection Monitor - shows all TCP/UDP connections for a process
    /// with real-time monitoring, state tracking, and remote endpoint details.
    /// </summary>
    public class NetworkConnectionMonitor : Form
    {
        private readonly int processId;
        private readonly string processName;

        private ListView connList;
        private Button refreshBtn;
        private Button startMonitorBtn;
        private Button stopMonitorBtn;
        private CheckBox showUdpCheck;
        private Label statsLbl;
        private RichTextBox logBox;

        private System.Windows.Forms.Timer monitorTimer;
        private readonly HashSet<string> knownConnections;

        private struct NetworkConnection
        {
            public string Protocol;
            public string LocalAddress;
            public int LocalPort;
            public string RemoteAddress;
            public int RemotePort;
            public string State;
            public int Pid;
            public bool IsNew;
        }

        public NetworkConnectionMonitor(int processId, string processName)
        {
            this.processId = processId;
            this.processName = processName;
            knownConnections = new HashSet<string>();
            InitializeComponent();
            RefreshConnections();
        }

        private void InitializeComponent()
        {
            Text = $"Network Connections - {processName} (PID: {processId})";
            Size = new Size(1000, 650);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };
            refreshBtn = CreateButton("Refresh", 70);
            refreshBtn.Click += (s, e) => RefreshConnections();
            startMonitorBtn = CreateButton("Start Monitor", 110);
            startMonitorBtn.Click += StartMonitor_Click;
            stopMonitorBtn = CreateButton("Stop", 60);
            stopMonitorBtn.Enabled = false;
            stopMonitorBtn.Click += StopMonitor_Click;
            showUdpCheck = new DarkCheckBox { Text = "Show UDP", AutoSize = true, Checked = true, Margin = new Padding(12, 4, 0, 0) };
            showUdpCheck.CheckedChanged += (s, e) => RefreshConnections();
            statsLbl = new Label { Text = "", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 4, 0, 0) };
            toolbar.Controls.AddRange(new Control[] { refreshBtn, startMonitorBtn, stopMonitorBtn, showUdpCheck, statsLbl });

            connList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            connList.Columns.Add("Protocol", 60);
            connList.Columns.Add("Local Address", 160);
            connList.Columns.Add("Local Port", 80);
            connList.Columns.Add("Remote Address", 160);
            connList.Columns.Add("Remote Port", 80);
            connList.Columns.Add("State", 100);
            connList.Columns.Add("Status", 60);
            connList.Resize += (s, e) => { if (connList.Columns.Count > 0) connList.Columns[connList.Columns.Count - 1].Width = -2; };

            var logPanel = new Panel { Dock = DockStyle.Bottom, Height = 120, BackColor = DarkTheme.Surface };
            var logLabel = new Label { Text = "   Connection Log", Dock = DockStyle.Top, Height = 22, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFontBold, TextAlign = ContentAlignment.MiddleLeft, BackColor = DarkTheme.SurfaceElevated };
            logBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical };
            logPanel.Controls.Add(logBox);
            logPanel.Controls.Add(logLabel);

            Controls.Add(connList);
            Controls.Add(logPanel);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);

            FormClosing += (s, e) => { monitorTimer?.Stop(); };
        }

        private void RefreshConnections()
        {
            connList.Items.Clear();
            var connections = GetProcessConnections();
            int tcp = 0, udp = 0, established = 0, newConns = 0;

            foreach (var conn in connections)
            {
                if (conn.Protocol == "UDP" && !showUdpCheck.Checked) continue;

                string key = $"{conn.Protocol}:{conn.LocalAddress}:{conn.LocalPort}:{conn.RemoteAddress}:{conn.RemotePort}";
                bool isNew = knownConnections.Add(key);
                if (isNew) newConns++;

                var lvi = new ListViewItem(conn.Protocol);
                lvi.SubItems.Add(conn.LocalAddress);
                lvi.SubItems.Add(conn.LocalPort.ToString());
                lvi.SubItems.Add(conn.RemoteAddress);
                lvi.SubItems.Add(conn.RemotePort.ToString());
                lvi.SubItems.Add(conn.State);
                lvi.SubItems.Add(isNew ? "NEW" : "");

                // Color by state
                switch (conn.State)
                {
                    case "ESTABLISHED": lvi.ForeColor = DarkTheme.Success; established++; break;
                    case "LISTEN": lvi.ForeColor = Color.FromArgb(88, 166, 255); break;
                    case "TIME_WAIT": lvi.ForeColor = DarkTheme.TextMuted; break;
                    case "CLOSE_WAIT": lvi.ForeColor = DarkTheme.Warning; break;
                    case "SYN_SENT": case "SYN_RECV": lvi.ForeColor = Color.FromArgb(210, 153, 34); break;
                    case "UDP": lvi.ForeColor = Color.FromArgb(180, 140, 255); break;
                    default: lvi.ForeColor = DarkTheme.TextPrimary; break;
                }

                if (isNew && monitorTimer != null)
                    lvi.ForeColor = DarkTheme.Accent;

                if (conn.Protocol == "TCP") tcp++; else udp++;
                connList.Items.Add(lvi);
            }

            statsLbl.Text = $"TCP: {tcp} | UDP: {udp} | Established: {established}{(newConns > 0 ? $" | New: {newConns}" : "")}";

            if (newConns > 0 && monitorTimer != null)
                Log("{0} new connection(s) detected", newConns);
        }

        private List<NetworkConnection> GetProcessConnections()
        {
            var result = new List<NetworkConnection>();

            // TCP connections via GetExtendedTcpTable
            int bufSize = 0x10000;
            IntPtr buf = Marshal.AllocHGlobal(bufSize);
            try
            {
                int ret = GetExtendedTcpTable(buf, ref bufSize, true, 2, 5, 0); // AF_INET, TCP_TABLE_OWNER_PID_ALL
                if (ret == 122) // ERROR_INSUFFICIENT_BUFFER
                {
                    Marshal.FreeHGlobal(buf);
                    buf = Marshal.AllocHGlobal(bufSize);
                    ret = GetExtendedTcpTable(buf, ref bufSize, true, 2, 5, 0);
                }

                if (ret == 0)
                {
                    int count = Marshal.ReadInt32(buf, 0);
                    int entrySize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                    for (int i = 0; i < count; i++)
                    {
                        int off = 4 + i * entrySize;
                        if (off + entrySize > bufSize) break;

                        var row = (MIB_TCPROW_OWNER_PID)Marshal.PtrToStructure(buf + off, typeof(MIB_TCPROW_OWNER_PID));
                        if (row.dwOwningPid != processId) continue;

                        string localAddr = new IPAddress(row.dwLocalAddr).ToString();
                        string remoteAddr = new IPAddress(row.dwRemoteAddr).ToString();
                        int localPort = (int)((row.dwLocalPort >> 8) | ((row.dwLocalPort & 0xFF) << 8));
                        int remotePort = (int)((row.dwRemotePort >> 8) | ((row.dwRemotePort & 0xFF) << 8));

                        result.Add(new NetworkConnection
                        {
                            Protocol = "TCP",
                            LocalAddress = localAddr,
                            LocalPort = localPort,
                            RemoteAddress = remoteAddr,
                            RemotePort = remotePort,
                            State = GetTcpState((int)row.dwState),
                            Pid = (int)row.dwOwningPid
                        });
                    }
                }

                // TCPv6
                bufSize = 0x10000;
                ret = GetExtendedTcpTable(buf, ref bufSize, true, 23, 5, 0); // AF_INET6
                if (ret == 0)
                {
                    int count = Marshal.ReadInt32(buf, 0);
                    // MIB_TCP6ROW_OWNER_PID is larger, simplified parsing
                    // Each entry: state(4) + localAddr(16) + localScope(4) + localPort(4) + remoteAddr(16) + remoteScope(4) + remotePort(4) + pid(4) = 52 bytes
                    int entrySize6 = 52;
                    for (int i = 0; i < count; i++)
                    {
                        int off = 4 + i * entrySize6;
                        if (off + entrySize6 > bufSize) break;

                        int pid = Marshal.ReadInt32(buf, off + 48);
                        if (pid != processId) continue;

                        int state = Marshal.ReadInt32(buf, off);
                        byte[] addr6 = new byte[16];
                        Marshal.Copy(buf + off + 4, addr6, 0, 16);
                        int localPort = Marshal.ReadInt32(buf, off + 20);
                        localPort = (localPort >> 8) | ((localPort & 0xFF) << 8);
                        byte[] remAddr6 = new byte[16];
                        Marshal.Copy(buf + off + 28, remAddr6, 0, 16);
                        int remotePort = Marshal.ReadInt32(buf, off + 44);
                        remotePort = (remotePort >> 8) | ((remotePort & 0xFF) << 8);

                        result.Add(new NetworkConnection
                        {
                            Protocol = "TCP6",
                            LocalAddress = new IPAddress(addr6).ToString(),
                            LocalPort = localPort,
                            RemoteAddress = new IPAddress(remAddr6).ToString(),
                            RemotePort = remotePort,
                            State = GetTcpState(state),
                            Pid = pid
                        });
                    }
                }

                // UDP connections
                bufSize = 0x10000;
                ret = GetExtendedUdpTable(buf, ref bufSize, true, 2, 5, 0); // AF_INET, UDP_TABLE_OWNER_PID
                if (ret == 122)
                {
                    Marshal.FreeHGlobal(buf);
                    buf = Marshal.AllocHGlobal(bufSize);
                    ret = GetExtendedUdpTable(buf, ref bufSize, true, 2, 5, 0);
                }

                if (ret == 0)
                {
                    int count = Marshal.ReadInt32(buf, 0);
                    int entrySizeU = 12; // localAddr(4) + localPort(4) + pid(4)
                    for (int i = 0; i < count; i++)
                    {
                        int off = 4 + i * entrySizeU;
                        if (off + entrySizeU > bufSize) break;

                        uint localAddr = (uint)Marshal.ReadInt32(buf, off);
                        int localPort = Marshal.ReadInt32(buf, off + 4);
                        localPort = (localPort >> 8) | ((localPort & 0xFF) << 8);
                        int pid = Marshal.ReadInt32(buf, off + 8);

                        if (pid != processId) continue;

                        result.Add(new NetworkConnection
                        {
                            Protocol = "UDP",
                            LocalAddress = new IPAddress(localAddr).ToString(),
                            LocalPort = localPort,
                            RemoteAddress = "*",
                            RemotePort = 0,
                            State = "UDP",
                            Pid = pid
                        });
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }

            return result;
        }

        private string GetTcpState(int state)
        {
            switch (state)
            {
                case 1: return "CLOSED";
                case 2: return "LISTEN";
                case 3: return "SYN_SENT";
                case 4: return "SYN_RECV";
                case 5: return "ESTABLISHED";
                case 6: return "FIN_WAIT1";
                case 7: return "FIN_WAIT2";
                case 8: return "CLOSE_WAIT";
                case 9: return "CLOSING";
                case 10: return "LAST_ACK";
                case 11: return "TIME_WAIT";
                case 12: return "DELETE_TCB";
                default: return $"STATE({state})";
            }
        }

        private void StartMonitor_Click(object sender, EventArgs e)
        {
            startMonitorBtn.Enabled = false;
            stopMonitorBtn.Enabled = true;
            knownConnections.Clear();
            RefreshConnections(); // Establish baseline
            Log("Network monitoring started");

            monitorTimer = new System.Windows.Forms.Timer { Interval = 2000 };
            monitorTimer.Tick += (s, ev) => RefreshConnections();
            monitorTimer.Start();
        }

        private void StopMonitor_Click(object sender, EventArgs e)
        {
            monitorTimer?.Stop();
            startMonitorBtn.Enabled = true;
            stopMonitorBtn.Enabled = false;
            Log("Network monitoring stopped");
        }

        private void Log(string message, params object[] args)
        {
            try { logBox.Invoke(new Action(() => logBox.AppendText($"[{DateTime.Now:HH:mm:ss}] {string.Format(message, args)}\n"))); } catch { }
        }

        // ==================== P/Invoke ====================

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetExtendedTcpTable(IntPtr pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        private static extern int GetExtendedUdpTable(IntPtr pUdpTable, ref int pdwSize, bool bOrder, int ulAf, int tableClass, uint reserved);

        [StructLayout(LayoutKind.Sequential)]
        private struct MIB_TCPROW_OWNER_PID
        {
            public uint dwState;
            public uint dwLocalAddr;
            public uint dwLocalPort;
            public uint dwRemoteAddr;
            public uint dwRemotePort;
            public uint dwOwningPid;
        }

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
    }
}
