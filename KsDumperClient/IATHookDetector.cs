using System;
using System.Collections.Generic;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Text;
using System.Windows.Forms;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// IAT Hook Detector - detects Import Address Table hooks by comparing
    /// IAT entries against actual function code in target modules.
    /// </summary>
    public class IATHookDetector : Form
    {
        private readonly IMemoryReader driver;
        private readonly int processId;
        private readonly string processName;

        private ListView hookList;
        private Button scanBtn;
        private Button refreshModulesBtn;
        private ComboBox moduleCombo;
        private RichTextBox detailsBox;
        private Label statsLbl;

        private struct IATHookInfo
        {
            public string Module;
            public string Function;
            public ulong IATAddress;
            public ulong IATValue;
            public ulong ExpectedAddress;
            public string TargetModule;
            public string HookType; // Inline, IAT, EAT, None
            public ulong Displacement;
        }

        public IATHookDetector(IMemoryReader driver, int processId, string processName)
        {
            this.driver = driver;
            this.processId = processId;
            this.processName = processName;
            InitializeComponent();
            LoadModules();
        }

        private void InitializeComponent()
        {
            Text = $"IAT Hook Detector - {processName} (PID: {processId})";
            Size = new Size(1000, 650);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            var toolbar = new Panel { Dock = DockStyle.Top, Height = 80, BackColor = DarkTheme.Surface, Padding = new Padding(8) };

            var row1 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            row1.Controls.Add(MakeLabel("Module:"));
            moduleCombo = new DarkComboBox { Width = 300 };
            row1.Controls.Add(moduleCombo);
            refreshModulesBtn = CreateButton("Refresh", 70);
            refreshModulesBtn.Click += (s, e) => LoadModules();
            scanBtn = CreateButton("Scan for Hooks", 120);
            scanBtn.Click += Scan_Click;
            row1.Controls.AddRange(new Control[] { refreshModulesBtn, scanBtn });

            var row2 = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 32, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false };
            statsLbl = new Label { Text = "Select a module and click Scan", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(0, 4, 0, 0) };
            row2.Controls.Add(statsLbl);

            toolbar.Controls.Add(row2);
            toolbar.Controls.Add(row1);

            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Horizontal, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 350 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            hookList = new ListView
            {
                View = View.Details, FullRowSelect = true, BorderStyle = BorderStyle.None,
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont
            };
            hookList.Columns.Add("Function", 200);
            hookList.Columns.Add("IAT Address", 120);
            hookList.Columns.Add("IAT Value", 130);
            hookList.Columns.Add("Expected", 130);
            hookList.Columns.Add("Displacement", 100);
            hookList.Columns.Add("Hook Type", 80);
            hookList.Columns.Add("Target Module", 200);
            hookList.Resize += (s, e) => { if (hookList.Columns.Count > 0) hookList.Columns[hookList.Columns.Count - 1].Width = -2; };

            detailsBox = new RichTextBox
            {
                Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None,
                Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Vertical
            };

            split.Panel1.Controls.Add(hookList);
            split.Panel2.Controls.Add(detailsBox);

            Controls.Add(split);
            Controls.Add(toolbar);
            DarkTheme.ApplyTo(this);
        }

        private void LoadModules()
        {
            moduleCombo.Items.Clear();
            try
            {
                if (driver.GetModuleSummaryList(processId, out var modules) && modules != null)
                {
                    foreach (var mod in modules)
                        moduleCombo.Items.Add($"{mod.ModuleName} (0x{mod.BaseAddress:X})");
                    if (moduleCombo.Items.Count > 0) moduleCombo.SelectedIndex = 0;
                }
            }
            catch { }
        }

        private async void Scan_Click(object sender, EventArgs e)
        {
            if (moduleCombo.SelectedIndex < 0) return;

            scanBtn.Enabled = false;
            hookList.Items.Clear();
            detailsBox.Clear();
            statsLbl.Text = "Scanning...";

            await System.Threading.Tasks.Task.Run(() =>
            {
                try
                {
                    if (driver.GetModuleSummaryList(processId, out var modules) && modules != null)
                    {
                        var mod = modules[moduleCombo.SelectedIndex];
                        var hooks = ScanModuleIAT(mod);

                        this.SafeInvoke(() =>
                        {
                            int hookCount = 0;
                            int totalImports = 0;

                            foreach (var hook in hooks)
                            {
                                totalImports++;
                                if (hook.HookType != "None") hookCount++;

                                var lvi = new ListViewItem(hook.Function);
                                lvi.SubItems.Add($"0x{hook.IATAddress:X}");
                                lvi.SubItems.Add($"0x{hook.IATValue:X}");
                                lvi.SubItems.Add($"0x{hook.ExpectedAddress:X}");
                                lvi.SubItems.Add(hook.Displacement != 0 ? $"+0x{hook.Displacement:X}" : "0");
                                lvi.SubItems.Add(hook.HookType);
                                lvi.SubItems.Add(hook.TargetModule);

                                switch (hook.HookType)
                                {
                                    case "IAT Hook": lvi.ForeColor = DarkTheme.Error; break;
                                    case "Inline": lvi.ForeColor = DarkTheme.Warning; break;
                                    case "Redirect": lvi.ForeColor = Color.FromArgb(255, 165, 0); break;
                                    case "None": lvi.ForeColor = DarkTheme.Success; break;
                                    default: lvi.ForeColor = DarkTheme.TextPrimary; break;
                                }

                                hookList.Items.Add(lvi);
                            }

                            statsLbl.Text = $"Imports: {totalImports} | Hooks detected: {hookCount}";
                            statsLbl.ForeColor = hookCount > 0 ? DarkTheme.Error : DarkTheme.Success;

                            detailsBox.SelectionColor = DarkTheme.Accent;
                            detailsBox.AppendText($"IAT Hook Scan Results\n");
                            detailsBox.SelectionColor = DarkTheme.TextSecondary;
                            detailsBox.AppendText(new string('═', 60) + "\n\n");
                            detailsBox.SelectionColor = DarkTheme.TextPrimary;
                            detailsBox.AppendText($"  Module:        {mod.ModuleName}\n");
                            detailsBox.AppendText($"  Base Address:  0x{mod.BaseAddress:X}\n");
                            detailsBox.AppendText($"  Total Imports: {totalImports}\n");

                            detailsBox.SelectionColor = hookCount > 0 ? DarkTheme.Error : DarkTheme.Success;
                            detailsBox.AppendText($"  Hooks Found:   {hookCount}\n\n");

                            if (hookCount > 0)
                            {
                                detailsBox.SelectionColor = DarkTheme.TextSecondary;
                                detailsBox.AppendText("  Hook Types:\n");
                                detailsBox.SelectionColor = DarkTheme.Error;
                                detailsBox.AppendText("    IAT Hook  = IAT entry points to wrong function\n");
                                detailsBox.SelectionColor = DarkTheme.Warning;
                                detailsBox.AppendText("    Inline    = Function prologue has JMP/PUSH+RET\n");
                                detailsBox.SelectionColor = Color.FromArgb(255, 165, 0);
                                detailsBox.AppendText("    Redirect  = IAT points to different module\n");
                            }
                        });
                    }
                }
                catch (Exception ex)
                {
                    this.SafeInvoke(() => { detailsBox.Text = $"Error: {ex.Message}"; statsLbl.Text = "Error"; });
                }
            });

            scanBtn.Enabled = true;
        }

        private const ulong MAX_USER_ADDR = 0x00007FFFFFFEFFFF;

        private List<IATHookInfo> ScanModuleIAT(ModuleSummary mod)
        {
            var result = new List<IATHookInfo>();

            var exportMap = driver.GetExportMap(processId);

            ModuleSummary[] allModules = null;
            driver.GetModuleSummaryList(processId, out allModules);

            byte[] headers = new byte[0x1000];
            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)0x1000,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return result;
            if (!driver.CopyVirtualMemory(processId, (IntPtr)mod.BaseAddress, buf, 0x1000))
            {
                WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                return result;
            }
            Marshal.Copy(buf, headers, 0, 0x1000);
            WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);

            if (BitConverter.ToUInt16(headers, 0) != 0x5A4D) return result;
            int e_lfanew = BitConverter.ToInt32(headers, 60);
            if (e_lfanew < 0 || e_lfanew + 4 > headers.Length) return result;
            if (BitConverter.ToUInt32(headers, e_lfanew) != 0x00004550) return result;

            ushort magic = BitConverter.ToUInt16(headers, e_lfanew + 24);
            bool is64 = magic == 0x20b;
            int dataDirBase = is64 ? 112 : 96;

            if (e_lfanew + 24 + dataDirBase + 16 > headers.Length) return result;
            uint importDirRVA = BitConverter.ToUInt32(headers, e_lfanew + 24 + dataDirBase + 8);
            if (importDirRVA == 0) return result;

            byte[] importDir = new byte[0x1000];
            buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)0x1000,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return result;
            if (!driver.CopyVirtualMemory(processId, (IntPtr)(mod.BaseAddress + importDirRVA), buf, 0x1000))
            {
                WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
                return result;
            }
            Marshal.Copy(buf, importDir, 0, 0x1000);
            WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);

            int pos = 0;
            int thunkSize = is64 ? 8 : 4;

            while (pos + 20 <= importDir.Length)
            {
                uint origFirstThunk = BitConverter.ToUInt32(importDir, pos);
                uint nameRVA = BitConverter.ToUInt32(importDir, pos + 12);
                uint firstThunk = BitConverter.ToUInt32(importDir, pos + 16);

                if (nameRVA == 0 && firstThunk == 0) break;

                string dllName = ReadString(mod.BaseAddress + nameRVA, 128);
                if (string.IsNullOrEmpty(dllName)) { pos += 20; continue; }

                uint thunkRVA = origFirstThunk != 0 ? origFirstThunk : firstThunk;
                for (int t = 0; t < 4096; t++)
                {
                    try
                    {
                        ulong iatAddr = mod.BaseAddress + firstThunk + (uint)(t * thunkSize);
                        ulong thunkVal = ReadThunk(mod.BaseAddress + thunkRVA + (uint)(t * thunkSize), is64);
                        ulong iatVal = ReadThunk(iatAddr, is64);

                        if (thunkVal == 0) break;

                        bool isOrdinal = is64 ? (thunkVal & 0x8000000000000000) != 0 : (thunkVal & 0x80000000) != 0;
                        string funcName = "";

                        if (!isOrdinal)
                        {
                            uint hintNameRVA = (uint)(thunkVal & 0x7FFFFFFF);
                            funcName = ReadHintName(mod.BaseAddress + hintNameRVA);
                        }
                        else
                        {
                            funcName = $"Ordinal #{thunkVal & 0xFFFF}";
                        }

                        if (string.IsNullOrEmpty(funcName)) continue;

                        ulong expectedAddr = 0;
                        string targetModule = "";
                        string hookType = "None";
                        ulong displacement = 0;

                        foreach (var kvp in exportMap)
                        {
                            if (kvp.Value.dllName.Equals(dllName, StringComparison.OrdinalIgnoreCase) &&
                                kvp.Value.funcName.Equals(funcName, StringComparison.OrdinalIgnoreCase))
                            {
                                expectedAddr = kvp.Key;
                                targetModule = kvp.Value.dllName;
                                break;
                            }
                        }

                        if (expectedAddr != 0 && iatVal != expectedAddr)
                        {
                            displacement = iatVal > expectedAddr ? iatVal - expectedAddr : expectedAddr - iatVal;

                            if (displacement > 0x10000)
                            {
                                if (allModules != null)
                                {
                                    foreach (var m in allModules)
                                    {
                                        if (iatVal >= m.BaseAddress && iatVal < m.BaseAddress + m.ImageSize)
                                        {
                                            targetModule = m.ModuleName;
                                            hookType = m.ModuleName.Equals(dllName, StringComparison.OrdinalIgnoreCase)
                                                ? "IAT Hook" : "Redirect";
                                            break;
                                        }
                                    }
                                }
                                if (hookType == "None") hookType = "IAT Hook";
                            }
                            else
                            {
                                hookType = "Inline";
                            }
                        }
                        else if (expectedAddr == 0 && iatVal != 0 && iatVal <= MAX_USER_ADDR)
                        {
                            byte[] prologue = new byte[6];
                            IntPtr prologueBuf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)6,
                                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
                            if (prologueBuf != IntPtr.Zero)
                            {
                                try
                                {
                                    if (driver.CopyVirtualMemory(processId, (IntPtr)iatVal, prologueBuf, 6))
                                    {
                                        Marshal.Copy(prologueBuf, prologue, 0, 6);
                                        if (prologue[0] == 0xE9 || (prologue[0] == 0x68 && prologue[5] == 0xC3) || prologue[0] == 0xFF)
                                            hookType = "Inline";
                                    }
                                }
                                finally { WinApi.VirtualFree(prologueBuf, UIntPtr.Zero, WinApi.MEM_RELEASE); }
                            }
                        }

                        result.Add(new IATHookInfo
                        {
                            Module = dllName,
                            Function = funcName,
                            IATAddress = iatAddr,
                            IATValue = iatVal,
                            ExpectedAddress = expectedAddr,
                            TargetModule = string.IsNullOrEmpty(targetModule) ? dllName : targetModule,
                            HookType = hookType,
                            Displacement = displacement
                        });
                    }
                    catch { }
                }

                pos += 20;
            }

            return result;
        }

        private string ReadString(ulong address, int maxLen)
        {
            byte[] buf = new byte[maxLen];
            IntPtr ptr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)maxLen,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (ptr == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, ptr, maxLen)) return null;
                Marshal.Copy(ptr, buf, 0, maxLen);
                int end = Array.IndexOf(buf, (byte)0);
                return end > 0 ? Encoding.ASCII.GetString(buf, 0, end) : null;
            }
            finally { WinApi.VirtualFree(ptr, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private string ReadHintName(ulong address)
        {
            byte[] buf = new byte[256];
            IntPtr ptr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)256,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (ptr == IntPtr.Zero) return null;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, ptr, 256)) return null;
                Marshal.Copy(ptr, buf, 0, 256);
                // Skip 2-byte hint
                int start = 2;
                int end = start;
                while (end < 256 && buf[end] != 0) end++;
                return end > start ? Encoding.ASCII.GetString(buf, start, end - start) : null;
            }
            finally { WinApi.VirtualFree(ptr, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private ulong ReadThunk(ulong address, bool is64)
        {
            int size = is64 ? 8 : 4;
            byte[] buf = new byte[size];
            IntPtr ptr = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (ptr == IntPtr.Zero) return 0;
            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, ptr, size)) return 0;
                Marshal.Copy(ptr, buf, 0, size);
                return is64 ? BitConverter.ToUInt64(buf, 0) : BitConverter.ToUInt32(buf, 0);
            }
            finally { WinApi.VirtualFree(ptr, UIntPtr.Zero, WinApi.MEM_RELEASE); }
        }

        private Button CreateButton(string t, int w) { var b = new Button { Text = t, Size = new Size(w, 26), Margin = new Padding(2, 0, 4, 0) }; DarkControlsHelper.StyleButton(b); return b; }
        private Label MakeLabel(string t) => new Label { Text = t, AutoSize = true, Margin = new Padding(0, 5, 4, 0), ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont };
    }
}
