using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Windows.Forms;
using KsDumperClient.DotNet;
using KsDumperClient.Utility;

namespace KsDumperClient
{
    /// <summary>
    /// dnSpy-style .NET assembly inspector. Browse types, view IL disassembly,
    /// inspect metadata tables, and see basic decompiled output.
    /// </summary>
    public class DotNetInspectorWindow : Form
    {
        private byte[] peBytes;
        private CliHeader cliHeader;
        private MetadataTableParser metadata;
        private ILDisassembler disassembler;
        private Decompiler decompiler;

        private TreeView treeView;
        private TabControl tabControl;
        private RichTextBox detailsBox;
        private RichTextBox ilBox;
        private RichTextBox csharpBox;
        private DataGridView metadataGrid;
        private ListView stringsList;
        private TextBox searchBox;
        private Label statusLbl;

        public DotNetInspectorWindow()
        {
            InitializeComponent();
        }

        private void InitializeComponent()
        {
            Text = ".NET Assembly Inspector";
            Size = new Size(1200, 800);
            StartPosition = FormStartPosition.CenterParent;
            BackColor = DarkTheme.Background;
            ForeColor = DarkTheme.TextPrimary;
            try { Icon = AppIcon.Get(); } catch { }

            // Toolbar
            var toolbar = new FlowLayoutPanel { Dock = DockStyle.Top, Height = 36, BackColor = DarkTheme.Surface, FlowDirection = FlowDirection.LeftToRight, WrapContents = false, Padding = new Padding(8, 4, 8, 4) };

            var openBtn = new Button { Text = "Open File...", Size = new Size(90, 26), FlatStyle = FlatStyle.Flat, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont };
            openBtn.FlatAppearance.BorderSize = 0;
            openBtn.Click += Open_Click;
            toolbar.Controls.Add(openBtn);

            toolbar.Controls.Add(new Label { Text = "  Search:", AutoSize = true, ForeColor = DarkTheme.TextSecondary, Font = DarkTheme.UIFont, Margin = new Padding(8, 5, 4, 0) });
            searchBox = new TextBox { Width = 200, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, BorderStyle = BorderStyle.None };
            searchBox.KeyDown += (s, e) => { if (e.KeyCode == Keys.Enter) DoSearch(); };
            toolbar.Controls.Add(searchBox);

            var searchBtn = new Button { Text = "Find", Size = new Size(50, 26), FlatStyle = FlatStyle.Flat, BackColor = DarkTheme.SurfaceElevated, ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIFont };
            searchBtn.FlatAppearance.BorderSize = 0;
            searchBtn.Click += (s, e) => DoSearch();
            toolbar.Controls.Add(searchBtn);

            statusLbl = new Label { Text = "Open a .NET assembly to inspect", AutoSize = true, ForeColor = DarkTheme.Accent, Font = DarkTheme.UIFontBold, Margin = new Padding(16, 5, 0, 0) };
            toolbar.Controls.Add(statusLbl);

            Controls.Add(toolbar);

            // Split: tree | tabs
            var split = new SplitContainer { Dock = DockStyle.Fill, Orientation = Orientation.Vertical, BackColor = DarkTheme.Border, SplitterWidth = 3, SplitterDistance = 350 };
            split.Panel1.BackColor = DarkTheme.Background;
            split.Panel2.BackColor = DarkTheme.Background;

            // Tree view
            treeView = new TreeView
            {
                Dock = DockStyle.Fill, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary,
                Font = DarkTheme.UIFont, BorderStyle = BorderStyle.None, ShowLines = true,
                ShowPlusMinus = true, ShowRootLines = true, HideSelection = false
            };
            treeView.AfterSelect += TreeView_AfterSelect;
            split.Panel1.Controls.Add(treeView);

            // Tab control with detail views
            tabControl = new TabControl { Dock = DockStyle.Fill, BackColor = DarkTheme.Background, Font = DarkTheme.UIFont };

            // Tab: Details
            var detailsTab = new TabPage("Details") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            detailsBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both, WordWrap = false };
            detailsTab.Controls.Add(detailsBox);
            tabControl.TabPages.Add(detailsTab);

            // Tab: IL Code
            var ilTab = new TabPage("IL Code") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            ilBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both, WordWrap = false };
            ilTab.Controls.Add(ilBox);
            tabControl.TabPages.Add(ilTab);

            // Tab: C# View
            var csTab = new TabPage("C# View") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            csharpBox = new RichTextBox { Dock = DockStyle.Fill, ReadOnly = true, BorderStyle = BorderStyle.None, Font = DarkTheme.UIMonoFont, BackColor = DarkTheme.Surface, ForeColor = DarkTheme.TextPrimary, ScrollBars = RichTextBoxScrollBars.Both, WordWrap = false };
            csTab.Controls.Add(csharpBox);
            tabControl.TabPages.Add(csTab);

            // Tab: Metadata
            var metaTab = new TabPage("Metadata Tables") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            metadataGrid = new DataGridView
            {
                Dock = DockStyle.Fill, ReadOnly = true, AllowUserToAddRows = false,
                AllowUserToDeleteRows = false, SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                BackgroundColor = DarkTheme.Surface, GridColor = DarkTheme.BorderSubtle,
                BorderStyle = BorderStyle.None, RowHeadersVisible = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.AllCells,
                Font = DarkTheme.UIMonoFont
            };
            metadataGrid.DefaultCellStyle.BackColor = DarkTheme.Surface;
            metadataGrid.DefaultCellStyle.ForeColor = DarkTheme.TextPrimary;
            metadataGrid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(40, 56, 139, 253);
            metadataGrid.DefaultCellStyle.SelectionForeColor = DarkTheme.TextPrimary;
            metadataGrid.ColumnHeadersDefaultCellStyle.BackColor = DarkTheme.SurfaceElevated;
            metadataGrid.ColumnHeadersDefaultCellStyle.ForeColor = DarkTheme.TextSecondary;
            metadataGrid.ColumnHeadersDefaultCellStyle.Font = DarkTheme.UIFontBold;
            metadataGrid.EnableHeadersVisualStyles = false;
            metaTab.Controls.Add(metadataGrid);
            tabControl.TabPages.Add(metaTab);

            // Tab: Strings
            var strTab = new TabPage("Strings") { BackColor = DarkTheme.Background, ForeColor = DarkTheme.TextPrimary };
            stringsList = new ListView
            {
                Dock = DockStyle.Fill, View = View.Details, FullRowSelect = true,
                BorderStyle = BorderStyle.None, BackColor = DarkTheme.Surface,
                ForeColor = DarkTheme.TextPrimary, Font = DarkTheme.UIMonoFont
            };
            stringsList.Columns.Add("Index", 80);
            stringsList.Columns.Add("Value", 600);
            strTab.Controls.Add(stringsList);
            tabControl.TabPages.Add(strTab);

            split.Panel2.Controls.Add(tabControl);
            Controls.Add(split);

            DarkTheme.ApplyTo(this);
        }

        private void Open_Click(object sender, EventArgs e)
        {
            using (var ofd = new OpenFileDialog())
            {
                ofd.Filter = ".NET Assemblies|*.dll;*.exe|All Files|*.*";
                ofd.Title = "Open .NET Assembly";
                if (ofd.ShowDialog() != DialogResult.OK) return;

                try
                {
                    peBytes = File.ReadAllBytes(ofd.FileName);
                    LoadAssembly(Path.GetFileName(ofd.FileName));
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"Error loading file:\n{ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void LoadAssembly(string fileName)
        {
            statusLbl.Text = $"Loading {fileName}...";

            cliHeader = CliHeader.Parse(peBytes);
            if (cliHeader == null)
            {
                statusLbl.Text = "Not a .NET assembly (no CLI header)";
                detailsBox.Text = "This file does not contain a valid CLI/COM+ header.\nIt may not be a .NET managed assembly.";
                return;
            }

            metadata = MetadataTableParser.Parse(peBytes, cliHeader);
            if (metadata == null)
            {
                statusLbl.Text = "Failed to parse metadata";
                detailsBox.Text = "Could not parse the #~ metadata stream.";
                return;
            }

            disassembler = new ILDisassembler(metadata, peBytes);
            decompiler = new Decompiler(metadata, disassembler);

            BuildTree(fileName);
            PopulateStrings();

            int typeCount = metadata.TypeDefs?.Length ?? 0;
            int methodCount = metadata.MethodDefs?.Length ?? 0;
            int fieldCount = metadata.Fields?.Length ?? 0;
            statusLbl.Text = $"{fileName}: {typeCount} types, {methodCount} methods, {fieldCount} fields (v{cliHeader.MajorRuntimeVersion}.{cliHeader.MinorRuntimeVersion})";
        }

        private void BuildTree(string fileName)
        {
            treeView.BeginUpdate();
            treeView.Nodes.Clear();

            var root = new TreeNode(fileName) { ForeColor = DarkTheme.Accent };

            // Types
            var typesNode = new TreeNode("Types") { ForeColor = DarkTheme.TextSecondary };
            if (metadata.TypeDefs != null)
            {
                // Group by namespace
                var groups = new Dictionary<string, List<int>>();
                for (int i = 0; i < metadata.TypeDefs.Length; i++)
                {
                    var td = metadata.TypeDefs[i];
                    string name = metadata.ReadString(td.NameIndex);
                    if (string.IsNullOrEmpty(name) || name == "<Module>") continue;

                    string ns = metadata.ReadString(td.NamespaceIndex);
                    if (string.IsNullOrEmpty(ns)) ns = "<Global>";

                    if (!groups.ContainsKey(ns))
                        groups[ns] = new List<int>();
                    groups[ns].Add(i);
                }

                foreach (var nsGroup in groups.OrderBy(g => g.Key))
                {
                    var nsNode = new TreeNode(nsGroup.Key) { ForeColor = DarkTheme.TextSecondary };

                    foreach (int typeIdx in nsGroup.Value)
                    {
                        var td = metadata.TypeDefs[typeIdx];
                        string name = metadata.ReadString(td.NameIndex);
                        string typeKind = GetTypeKind(td.Flags);

                        var typeNode = new TreeNode($"{typeKind} {name}")
                        {
                            Tag = new NodeTag { Kind = NodeKind.Type, Index = typeIdx },
                            ForeColor = DarkTheme.TextPrimary
                        };

                        // Add methods
                        if (metadata.MethodDefs != null)
                        {
                            int start = (int)td.MethodList - 1;
                            int end = (int)td.MethodList - 1 + CountMethods(typeIdx);
                            for (int m = start; m < end && m < metadata.MethodDefs.Length; m++)
                            {
                                var md = metadata.MethodDefs[m];
                                string methodName = metadata.ReadString(md.NameIndex);
                                var methodNode = new TreeNode($"{methodName}()")
                                {
                                    Tag = new NodeTag { Kind = NodeKind.Method, Index = m },
                                    ForeColor = Color.FromArgb(121, 192, 255)
                                };
                                typeNode.Nodes.Add(methodNode);
                            }
                        }

                        // Add fields
                        if (metadata.Fields != null)
                        {
                            int start = (int)td.FieldList - 1;
                            int end = (int)td.FieldList - 1 + CountFields(typeIdx);
                            for (int f = start; f < end && f < metadata.Fields.Length; f++)
                            {
                                var fd = metadata.Fields[f];
                                string fieldName = metadata.ReadString(fd.NameIndex);
                                var fieldNode = new TreeNode(fieldName)
                                {
                                    Tag = new NodeTag { Kind = NodeKind.Field, Index = f },
                                    ForeColor = DarkTheme.Success
                                };
                                typeNode.Nodes.Add(fieldNode);
                            }
                        }

                        nsNode.Nodes.Add(typeNode);
                    }

                    typesNode.Nodes.Add(nsNode);
                }
            }
            root.Nodes.Add(typesNode);

            // Metadata Tables
            var tablesNode = new TreeNode("Metadata Tables") { ForeColor = DarkTheme.TextSecondary };
            string[] tableNames = { "Module", "TypeRef", "TypeDef", "", "Field", "", "MethodDef", "", "Param",
                "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute", "FieldMarshal", "DeclSecurity",
                "ClassLayout", "FieldLayout", "StandAloneSig", "EventMap", "", "Event", "PropertyMap", "",
                "Property", "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap", "FieldRVA",
                "", "", "", "Assembly", "", "", "AssemblyRef", "", "", "File", "ExportedType",
                "ManifestResource", "NestedClass", "GenericParam", "MethodSpec", "GenericParamConstraint" };

            for (int i = 0; i < 46; i++)
            {
                if (metadata.RowCounts[i] > 0)
                {
                    string name = (i < tableNames.Length && !string.IsNullOrEmpty(tableNames[i])) ? tableNames[i] : $"Table 0x{i:X2}";
                    var tableTreeNode = new TreeNode($"{name} ({metadata.RowCounts[i]} rows)")
                    {
                        Tag = new NodeTag { Kind = NodeKind.Table, Index = i },
                        ForeColor = DarkTheme.Warning
                    };
                    tablesNode.Nodes.Add(tableTreeNode);
                }
            }
            root.Nodes.Add(tablesNode);

            // Heaps
            var heapsNode = new TreeNode("Heaps") { ForeColor = DarkTheme.TextSecondary };
            if (metadata.StringsHeap != null)
                heapsNode.Nodes.Add(new TreeNode($"#Strings ({metadata.StringsHeap.Length} bytes)") { Tag = new NodeTag { Kind = NodeKind.Heap, Index = 0 }, ForeColor = Color.FromArgb(188, 140, 255) });
            if (metadata.UserStringHeap != null)
                heapsNode.Nodes.Add(new TreeNode($"#US ({metadata.UserStringHeap.Length} bytes)") { Tag = new NodeTag { Kind = NodeKind.Heap, Index = 1 }, ForeColor = Color.FromArgb(188, 140, 255) });
            if (metadata.BlobHeap != null)
                heapsNode.Nodes.Add(new TreeNode($"#Blob ({metadata.BlobHeap.Length} bytes)") { Tag = new NodeTag { Kind = NodeKind.Heap, Index = 2 }, ForeColor = Color.FromArgb(188, 140, 255) });
            if (metadata.GuidHeap != null)
                heapsNode.Nodes.Add(new TreeNode($"#GUID ({metadata.GuidHeap.Length} bytes)") { Tag = new NodeTag { Kind = NodeKind.Heap, Index = 3 }, ForeColor = Color.FromArgb(188, 140, 255) });
            root.Nodes.Add(heapsNode);

            treeView.Nodes.Add(root);
            root.Expand();
            typesNode.Expand();
            treeView.EndUpdate();
        }

        private void TreeView_AfterSelect(object sender, TreeViewEventArgs e)
        {
            var tag = e.Node?.Tag as NodeTag;
            if (tag == null) return;

            switch (tag.Kind)
            {
                case NodeKind.Type:
                    ShowTypeDef(tag.Index);
                    break;
                case NodeKind.Method:
                    ShowMethod(tag.Index);
                    break;
                case NodeKind.Field:
                    ShowField(tag.Index);
                    break;
                case NodeKind.Table:
                    ShowMetadataTable(tag.Index);
                    break;
                case NodeKind.Heap:
                    ShowHeap(tag.Index);
                    break;
            }
        }

        private void ShowTypeDef(int index)
        {
            if (metadata.TypeDefs == null || index >= metadata.TypeDefs.Length) return;
            var td = metadata.TypeDefs[index];

            string name = metadata.ReadString(td.NameIndex);
            string ns = metadata.ReadString(td.NamespaceIndex);
            string fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
            string baseType = metadata.ResolveTypeDefOrRef(td.Extends);
            string typeKind = GetTypeKind(td.Flags);
            string access = GetTypeAccess(td.Flags);

            int methodCount = CountMethods(index);
            int fieldCount = CountFields(index);

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Type: {fullName}");
            sb.AppendLine($"Kind: {typeKind}");
            sb.AppendLine($"Access: {access}");
            sb.AppendLine($"Base: {baseType}");
            sb.AppendLine($"Flags: 0x{td.Flags:X8}");
            sb.AppendLine($"Token: 0x02{(index + 1):X6}");
            sb.AppendLine($"Methods: {methodCount}");
            sb.AppendLine($"Fields: {fieldCount}");

            detailsBox.Text = sb.ToString();
            ilBox.Text = "// Select a method in the tree to see IL";
            csharpBox.Text = "// Select a method in the tree to see decompiled output";
            tabControl.SelectedTab = tabControl.TabPages[0];
        }

        private void ShowMethod(int index)
        {
            if (metadata.MethodDefs == null || index >= metadata.MethodDefs.Length) return;
            var md = metadata.MethodDefs[index];

            string name = metadata.ReadString(md.NameIndex);

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Method: {name}");
            sb.AppendLine($"Token: 0x06{(index + 1):X6}");
            sb.AppendLine($"RVA: 0x{md.Rva:X8}");
            sb.AppendLine($"Flags: 0x{md.Flags:X4}");
            sb.AppendLine($"ImplFlags: 0x{md.ImplFlags:X4}");

            string access = GetMethodAccess(md.Flags);
            sb.AppendLine($"Access: {access}");
            if ((md.Flags & 0x0010) != 0) sb.AppendLine("Static: yes");
            if ((md.Flags & 0x0040) != 0) sb.AppendLine("Virtual: yes");
            if ((md.Flags & 0x0400) != 0) sb.AppendLine("Abstract: yes");

            detailsBox.Text = sb.ToString();

            // IL disassembly
            ilBox.Text = disassembler.DisassembleMethod(index);
            tabControl.SelectedTab = tabControl.TabPages[1];

            // C# decompilation
            csharpBox.Text = decompiler.DecompileMethod(index);
        }

        private void ShowField(int index)
        {
            if (metadata.Fields == null || index >= metadata.Fields.Length) return;
            var fd = metadata.Fields[index];

            string name = metadata.ReadString(fd.NameIndex);
            string access = GetFieldAccess(fd.Flags);

            var sb = new System.Text.StringBuilder();
            sb.AppendLine($"Field: {name}");
            sb.AppendLine($"Token: 0x04{(index + 1):X6}");
            sb.AppendLine($"Flags: 0x{fd.Flags:X4}");
            sb.AppendLine($"Access: {access}");
            if ((fd.Flags & 0x0010) != 0) sb.AppendLine("Static: yes");
            if ((fd.Flags & 0x0040) != 0) sb.AppendLine("InitOnly: yes");
            if ((fd.Flags & 0x0080) != 0) sb.AppendLine("Literal: yes");

            detailsBox.Text = sb.ToString();
            tabControl.SelectedTab = tabControl.TabPages[0];
        }

        private void ShowMetadataTable(int tableId)
        {
            metadataGrid.Columns.Clear();
            metadataGrid.Rows.Clear();

            switch (tableId)
            {
                case 0x02: // TypeDef
                    metadataGrid.Columns.Add("Index", "#");
                    metadataGrid.Columns.Add("Name", "Name");
                    metadataGrid.Columns.Add("Namespace", "Namespace");
                    metadataGrid.Columns.Add("Flags", "Flags");
                    metadataGrid.Columns.Add("Extends", "Extends");
                    metadataGrid.Columns.Add("Methods", "Methods");
                    metadataGrid.Columns.Add("Fields", "Fields");
                    metadataGrid.Columns.Add("Token", "Token");

                    if (metadata.TypeDefs != null)
                    {
                        for (int i = 0; i < metadata.TypeDefs.Length; i++)
                        {
                            var td = metadata.TypeDefs[i];
                            metadataGrid.Rows.Add(
                                i.ToString(),
                                metadata.ReadString(td.NameIndex),
                                metadata.ReadString(td.NamespaceIndex),
                                $"0x{td.Flags:X8}",
                                metadata.ResolveTypeDefOrRef(td.Extends),
                                CountMethods(i).ToString(),
                                CountFields(i).ToString(),
                                $"0x02{(i + 1):X6}");
                        }
                    }
                    break;

                case 0x06: // MethodDef
                    metadataGrid.Columns.Add("Index", "#");
                    metadataGrid.Columns.Add("Name", "Name");
                    metadataGrid.Columns.Add("RVA", "RVA");
                    metadataGrid.Columns.Add("Flags", "Flags");
                    metadataGrid.Columns.Add("ImplFlags", "ImplFlags");

                    if (metadata.MethodDefs != null)
                    {
                        for (int i = 0; i < metadata.MethodDefs.Length; i++)
                        {
                            var md = metadata.MethodDefs[i];
                            metadataGrid.Rows.Add(
                                i.ToString(),
                                metadata.ReadString(md.NameIndex),
                                $"0x{md.Rva:X8}",
                                $"0x{md.Flags:X4}",
                                $"0x{md.ImplFlags:X4}");
                        }
                    }
                    break;

                case 0x0A: // MemberRef
                    metadataGrid.Columns.Add("Index", "#");
                    metadataGrid.Columns.Add("Class", "Class");
                    metadataGrid.Columns.Add("Name", "Name");

                    if (metadata.MemberRefs != null)
                    {
                        for (int i = 0; i < metadata.MemberRefs.Length; i++)
                        {
                            var mr = metadata.MemberRefs[i];
                            metadataGrid.Rows.Add(
                                i.ToString(),
                                metadata.ResolveMemberRefParent(mr.Class),
                                metadata.ReadString(mr.NameIndex));
                        }
                    }
                    break;

                default:
                    metadataGrid.Columns.Add("Info", "Info");
                    metadataGrid.Rows.Add($"Table 0x{tableId:X2}: {metadata.RowCounts[tableId]} rows");
                    metadataGrid.Rows.Add("(Detailed view not yet implemented for this table)");
                    break;
            }

            tabControl.SelectedTab = tabControl.TabPages[3];
        }

        private void ShowHeap(int heapIndex)
        {
            stringsList.Items.Clear();
            byte[] heap = null;
            string name = "";

            switch (heapIndex)
            {
                case 0: heap = metadata.StringsHeap; name = "#Strings"; break;
                case 1: heap = metadata.UserStringHeap; name = "#US"; break;
                case 2: heap = metadata.BlobHeap; name = "#Blob"; break;
                case 3: heap = metadata.GuidHeap; name = "#GUID"; break;
            }

            if (heap == null || heap.Length == 0)
            {
                stringsList.Items.Add(new ListViewItem(new[] { "0", "(empty)" }));
                return;
            }

            int count = 0;
            if (heapIndex == 0) // #Strings — null-terminated UTF-8
            {
                int pos = 0;
                while (pos < heap.Length && count < 10000)
                {
                    string s = CliHeader.ReadUtf8NullTerminated(heap, pos);
                    if (!string.IsNullOrEmpty(s))
                    {
                        stringsList.Items.Add(new ListViewItem(new[] { pos.ToString(), s }));
                        count++;
                    }
                    while (pos < heap.Length && heap[pos] != 0) pos++;
                    pos++;
                }
            }
            else if (heapIndex == 1) // #US — compressed length prefix + UTF-16
            {
                int pos = 1; // skip first null byte
                while (pos < heap.Length && count < 10000)
                {
                    int startPos = pos;
                    int length = MetadataTableParser.ReadCompressedUInt(heap, ref pos);
                    if (length <= 0 || pos + length > heap.Length) break;

                    int charLen = (length - 1) / 2;
                    string s = charLen > 0 ? System.Text.Encoding.Unicode.GetString(heap, pos, charLen * 2) : "";
                    stringsList.Items.Add(new ListViewItem(new[] { startPos.ToString(), s.Length > 200 ? s.Substring(0, 200) + "..." : s }));
                    count++;
                    pos += length;
                }
            }
            else
            {
                stringsList.Items.Add(new ListViewItem(new[] { "0", $"{name}: {heap.Length} bytes (raw view not implemented)" }));
            }

            tabControl.SelectedTab = tabControl.TabPages[4];
        }

        private void PopulateStrings()
        {
            // Pre-populate #Strings heap in the Strings tab
            ShowHeap(0);
        }

        private void DoSearch()
        {
            string query = searchBox.Text.Trim().ToLower();
            if (string.IsNullOrEmpty(query) || metadata?.TypeDefs == null) return;

            treeView.BeginUpdate();
            treeView.CollapseAll();

            bool found = false;
            foreach (TreeNode nsNode in treeView.Nodes[0].Nodes[0].Nodes) // root > Types > namespaces
            {
                foreach (TreeNode typeNode in nsNode.Nodes)
                {
                    if (typeNode.Text.ToLower().Contains(query))
                    {
                        nsNode.Expand();
                        typeNode.EnsureVisible();
                        treeView.SelectedNode = typeNode;
                        found = true;
                        break;
                    }

                    // Search methods
                    foreach (TreeNode methodNode in typeNode.Nodes)
                    {
                        if (methodNode.Text.ToLower().Contains(query))
                        {
                            nsNode.Expand();
                            typeNode.Expand();
                            methodNode.EnsureVisible();
                            treeView.SelectedNode = methodNode;
                            found = true;
                            break;
                        }
                    }
                    if (found) break;
                }
                if (found) break;
            }

            treeView.EndUpdate();
            if (!found)
                statusLbl.Text = $"No results for '{query}'";
        }

        private int CountMethods(int typeIndex)
        {
            if (metadata.TypeDefs == null || metadata.MethodDefs == null) return 0;
            var td = metadata.TypeDefs[typeIndex];
            if (typeIndex + 1 < metadata.TypeDefs.Length)
            {
                int nextStart = (int)metadata.TypeDefs[typeIndex + 1].MethodList - 1;
                return Math.Max(0, nextStart - ((int)td.MethodList - 1));
            }
            return Math.Max(0, metadata.MethodDefs.Length - ((int)td.MethodList - 1));
        }

        private int CountFields(int typeIndex)
        {
            if (metadata.TypeDefs == null || metadata.Fields == null) return 0;
            var td = metadata.TypeDefs[typeIndex];
            if (typeIndex + 1 < metadata.TypeDefs.Length)
            {
                int nextStart = (int)metadata.TypeDefs[typeIndex + 1].FieldList - 1;
                return Math.Max(0, nextStart - ((int)td.FieldList - 1));
            }
            return Math.Max(0, metadata.Fields.Length - ((int)td.FieldList - 1));
        }

        private string GetTypeKind(uint flags)
        {
            if ((flags & 0x00000020) != 0) // tdInterface
                return "interface";
            // Check base type for value types... simplified
            return "class";
        }

        private string GetTypeAccess(uint flags)
        {
            uint vis = flags & 0x07;
            switch (vis)
            {
                case 0x00: return "not public";
                case 0x01: return "public";
                case 0x02: return "nested public";
                case 0x03: return "nested private";
                case 0x04: return "nested family";
                case 0x05: return "nested assembly";
                case 0x06: return "nested famandassem";
                case 0x07: return "nested famorassem";
                default: return "unknown";
            }
        }

        private string GetMethodAccess(ushort flags)
        {
            uint access = (uint)(flags & 0x0007);
            switch (access)
            {
                case 0x01: return "private";
                case 0x02: return "famandassem";
                case 0x03: return "assembly";
                case 0x04: return "family";
                case 0x05: return "famorassem";
                case 0x06: return "public";
                default: return "compilercontrolled";
            }
        }

        private string GetFieldAccess(ushort flags)
        {
            uint access = (uint)(flags & 0x0007);
            switch (access)
            {
                case 0x0001: return "private";
                case 0x0002: return "famandassem";
                case 0x0003: return "assembly";
                case 0x0004: return "family";
                case 0x0005: return "famorassem";
                case 0x0006: return "public";
                default: return "compilercontrolled";
            }
        }

        // ---- Tag classes ----

        private enum NodeKind { Type, Method, Field, Table, Heap }

        private class NodeTag
        {
            public NodeKind Kind;
            public int Index;
        }
    }
}
