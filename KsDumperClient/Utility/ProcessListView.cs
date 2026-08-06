using System;
using System.Collections;
using System.IO;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace KsDumperClient.Utility
{
    public class ProcessListView : ListView
    {
        public bool SystemProcessesHidden { get; private set; } = true;

        private int sortColumnIndex = 1;
        private ProcessSummary[] processCache;
        private string filterText = "";
        private int hoveredIndex = -1;

        public ProcessListView()
        {
            DoubleBuffered = true;
            Sorting = SortOrder.Ascending;
            SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint, true);
        }

        public void LoadProcesses(ProcessSummary[] processSummaries)
        {
            processCache = processSummaries;
            ReloadItems();
        }

        public void FilterProcesses(string text)
        {
            filterText = text?.Trim().ToLowerInvariant() ?? "";
            ReloadItems();
        }

        public void ShowSystemProcesses()
        {
            SystemProcessesHidden = false;
            ReloadItems();
        }

        public void HideSystemProcesses()
        {
            SystemProcessesHidden = true;
            ReloadItems();
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);
            var hitItem = GetItemAt(e.X, e.Y);
            if (hitItem != null)
            {
                int newIndex = hitItem.Index;
                if (newIndex != hoveredIndex)
                {
                    hoveredIndex = newIndex;
                    Invalidate();
                }
            }
            else
            {
                if (hoveredIndex != -1)
                {
                    hoveredIndex = -1;
                    Invalidate();
                }
            }
        }

        protected override void OnMouseLeave(EventArgs e)
        {
            base.OnMouseLeave(e);
            if (hoveredIndex != -1)
            {
                hoveredIndex = -1;
                Invalidate();
            }
        }

        private void ReloadItems()
        {
            Items.Clear();

            if (processCache == null)
                return;

            string systemRootFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
            int count = 0;

            foreach (ProcessSummary processSummary in processCache)
            {
                if (SystemProcessesHidden &&
                    (processSummary.MainModuleFileName.ToLower().StartsWith(systemRootFolder) ||
                    processSummary.MainModuleFileName.StartsWith(@"\")))
                {
                    continue;
                }

                if (!string.IsNullOrEmpty(filterText))
                {
                    if (!processSummary.ProcessName.ToLower().Contains(filterText) &&
                        !processSummary.ProcessId.ToString().Contains(filterText) &&
                        !processSummary.MainModuleFileName.ToLower().Contains(filterText))
                    {
                        continue;
                    }
                }

                count++;

                // Analyze process for protection/elevation/etc.
                var analysis = ProcessAnalyzer.Analyze(processSummary.ProcessId, processSummary.ProcessName, processSummary.MainModuleFileName);

                ListViewItem lvi = new ListViewItem(processSummary.ProcessId.ToString());
                lvi.SubItems.Add(Path.GetFileName(processSummary.MainModuleFileName));
                lvi.SubItems.Add(processSummary.MainModuleFileName);
                lvi.SubItems.Add(string.Format("0x{0:x8}", processSummary.MainModuleBase));
                lvi.SubItems.Add(string.Format("0x{0:x8}", processSummary.MainModuleEntryPoint));
                lvi.SubItems.Add(string.Format("0x{0:x4}", processSummary.MainModuleImageSize));
                lvi.SubItems.Add(processSummary.IsWOW64 ? "x86" : "x64");
                lvi.SubItems.Add(analysis.StatusText);
                lvi.SubItems.Add(analysis.IntegrityLevel ?? "Medium");
                lvi.Tag = processSummary;

                // Color coding based on analysis
                if ((analysis.Flags & ProcessAnalyzer.ProcessFlags.Protected) != 0 ||
                    (analysis.Flags & ProcessAnalyzer.ProcessFlags.Secure) != 0)
                {
                    lvi.ForeColor = Color.FromArgb(248, 81, 73); // Red - protected/secure
                }
                else if ((analysis.Flags & ProcessAnalyzer.ProcessFlags.StrippedHandles) != 0 ||
                         (analysis.Flags & ProcessAnalyzer.ProcessFlags.AntiDebug) != 0)
                {
                    lvi.ForeColor = Color.FromArgb(210, 153, 34); // Orange - handle-stripped/anti-debug
                }
                else if ((analysis.Flags & ProcessAnalyzer.ProcessFlags.Elevated) != 0 &&
                         analysis.IntegrityLevel == "System")
                {
                    lvi.ForeColor = Color.FromArgb(188, 140, 255); // Purple - SYSTEM process
                }
                else if ((analysis.Flags & ProcessAnalyzer.ProcessFlags.Elevated) != 0)
                {
                    lvi.ForeColor = Color.FromArgb(88, 166, 255); // Blue - elevated
                }
                else if ((analysis.Flags & ProcessAnalyzer.ProcessFlags.Suspended) != 0)
                {
                    lvi.ForeColor = Color.FromArgb(139, 148, 158); // Gray - suspended
                }
                else if ((analysis.Flags & ProcessAnalyzer.ProcessFlags.DotNet) != 0)
                {
                    lvi.ForeColor = Color.FromArgb(63, 185, 80); // Green - .NET
                }

                // Tooltip with detailed info
                string tooltip = $"PID: {processSummary.ProcessId}\n" +
                    $"Path: {processSummary.MainModuleFileName}\n" +
                    $"Base: 0x{processSummary.MainModuleBase:x}\n" +
                    $"Entry: 0x{processSummary.MainModuleEntryPoint:x}\n" +
                    $"Size: 0x{processSummary.MainModuleImageSize:x}\n" +
                    $"Arch: {(processSummary.IsWOW64 ? "x86" : "x64")}\n" +
                    $"Integrity: {analysis.IntegrityLevel ?? "Medium"}\n" +
                    $"User: {analysis.UserName ?? "Unknown"}\n" +
                    $"Threads: {analysis.ThreadCount}\n" +
                    $"Handles: {analysis.HandleCount}\n" +
                    $"Memory: {analysis.WorkingSetMB} MB\n" +
                    $"Status: {analysis.StatusText}";
                lvi.ToolTipText = tooltip;

                Items.Add(lvi);
            }

            ListViewItemSorter = new ProcessListViewItemComparer(sortColumnIndex, Sorting);
            Sort();
            ResizeLastColumn();
        }

        protected override void OnColumnClick(ColumnClickEventArgs e)
        {
            if (e.Column != sortColumnIndex)
            {
                sortColumnIndex = e.Column;
                Sorting = SortOrder.Ascending;
            }
            else
            {
                if (Sorting == SortOrder.Ascending)
                {
                    Sorting = SortOrder.Descending;
                }
                else
                {
                    Sorting = SortOrder.Ascending;
                }
            }

            ListViewItemSorter = new ProcessListViewItemComparer(e.Column, Sorting);
            Sort();
        }

        private class ProcessListViewItemComparer : IComparer
        {
            private readonly int columnIndex;
            private readonly SortOrder sortOrder;

            public ProcessListViewItemComparer(int columnIndex, SortOrder sortOrder)
            {
                this.columnIndex = columnIndex;
                this.sortOrder = sortOrder;
            }

            public int Compare(object x, object y)
            {
                if ((x is ListViewItem) && (y is ListViewItem))
                {
                    ProcessSummary p1 = ((ListViewItem)x).Tag as ProcessSummary;
                    ProcessSummary p2 = ((ListViewItem)y).Tag as ProcessSummary;

                    if (!(p1 == null || p2 == null))
                    {
                        int result = 0;

                        switch (columnIndex)
                        {
                            case 0:
                                result = p1.ProcessId.CompareTo(p2.ProcessId);
                                break;
                            case 1:
                                result = p1.ProcessName.CompareTo(p2.ProcessName);
                                break;
                            case 2:
                                result = p1.MainModuleFileName.CompareTo(p2.MainModuleFileName);
                                break;
                            case 3:
                                result = p1.MainModuleBase.CompareTo(p2.MainModuleBase);
                                break;
                            case 4:
                                result = p1.MainModuleEntryPoint.CompareTo(p2.MainModuleEntryPoint);
                                break;
                            case 5:
                                result = p1.MainModuleImageSize.CompareTo(p2.MainModuleImageSize);
                                break;
                            case 6:
                                result = p1.IsWOW64.CompareTo(p2.IsWOW64);
                                break;
                        }

                        if (sortOrder == SortOrder.Descending)
                        {
                            result = -result;
                        }
                        return result;
                    }
                }
                return 0;
            }
        }

        private void ResizeLastColumn()
        {
            if (View != View.Details || Columns.Count == 0) return;
            try
            {
                BeginUpdate();
                // -2 tells WinForms to auto-fill remaining width exactly
                Columns[Columns.Count - 1].Width = -2;
            }
            finally
            {
                EndUpdate();
            }
        }

        protected override void OnResize(EventArgs e)
        {
            base.OnResize(e);
            ResizeLastColumn();
        }

        protected override void OnSizeChanged(EventArgs e)
        {
            base.OnSizeChanged(e);
            ResizeLastColumn();
        }

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        private extern static int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string pszSubIdList);
    }
}
