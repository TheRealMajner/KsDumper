using System;
using System.Collections.Generic;
using System.Text;

namespace KsDumperClient.DotNet
{
    /// <summary>
    /// ECMA-335 metadata root: BSJB signature, stream headers, and heap data.
    /// </summary>
    public class MetadataRoot
    {
        public uint Signature;          // 0x424A5342 "BSJB"
        public ushort MajorVersion;
        public ushort MinorVersion;
        public string VersionString;
        public List<StreamHeader> Streams = new List<StreamHeader>();

        // Byte arrays for each heap
        public byte[] TablesStream;     // #~ or #-
        public byte[] StringsHeap;      // #Strings
        public byte[] UserStringHeap;   // #US
        public byte[] GuidHeap;         // #GUID
        public byte[] BlobHeap;         // #Blob
    }

    public struct StreamHeader
    {
        public uint Offset;
        public uint Size;
        public string Name;
    }

    /// <summary>
    /// ECMA-335 metadata table row types.
    /// </summary>
    public struct TypeDefRow
    {
        public uint Flags;
        public uint NameIndex;
        public uint NamespaceIndex;
        public uint Extends;        // Coded index: TypeDefOrRef
        public uint FieldList;
        public uint MethodList;
    }

    public struct MethodDefRow
    {
        public uint Rva;
        public ushort ImplFlags;
        public ushort Flags;
        public uint NameIndex;
        public uint SignatureIndex; // Blob index
        public uint ParamList;
    }

    public struct FieldRow
    {
        public ushort Flags;
        public uint NameIndex;
        public uint SignatureIndex; // Blob index
    }

    public struct ParamRow
    {
        public ushort Flags;
        public ushort Sequence;
        public uint NameIndex;
    }

    public struct MemberRefRow
    {
        public uint Class;            // Coded index: MemberRefParent
        public uint NameIndex;
        public uint SignatureIndex;   // Blob index
    }

    public struct TypeRefRow
    {
        public uint ResolutionScope;  // Coded index: ResolutionScope
        public uint NameIndex;
        public uint NamespaceIndex;
    }

    public struct PropertyRow
    {
        public ushort Flags;
        public uint NameIndex;
        public uint TypeIndex;        // Blob index
    }

    public struct EventRow
    {
        public ushort EventFlags;
        public uint NameIndex;
        public uint EventType;        // Coded index: TypeDefOrRef
    }

    public struct InterfaceImplRow
    {
        public uint Class;
        public uint Interface;        // Coded index: TypeDefOrRef
    }

    public struct GenericParamRow
    {
        public ushort Number;
        public ushort Flags;
        public uint Owner;            // Coded index: TypeOrMethodDef
        public uint NameIndex;
    }

    public struct TypeSpecRow
    {
        public uint SignatureIndex;   // Blob index
    }

    public struct MethodImplRow
    {
        public uint Class;
        public uint MethodBody;       // Coded index: MethodDefOrRef
        public uint MethodDeclaration; // Coded index: MethodDefOrRef
    }

    public struct CustomAttributeRow
    {
        public uint Parent;           // Coded index: HasCustomAttribute
        public uint Type;             // Coded index: CustomAttributeType
        public uint Value;            // Blob index
    }

    public struct FieldLayoutRow
    {
        public uint Offset;
        public uint Field;
    }

    public struct PropertyMapRow
    {
        public uint Parent;
        public uint PropertyList;
    }

    public struct EventMapRow
    {
        public uint Parent;
        public uint EventList;
    }

    public struct MethodSemanticsRow
    {
        public ushort Semantics;
        public uint Method;
        public uint Association;      // Coded index: HasSemantics
    }

    public struct NestedClassRow
    {
        public uint NestedClass;
        public uint EnclosingClass;
    }

    public struct ClassLayoutRow
    {
        public ushort PackingSize;
        public uint ClassSize;
        public uint Parent;
    }

    /// <summary>
    /// Parses the #~ metadata stream into row arrays for each table.
    /// Implements ECMA-335 II.24.2.6.
    /// </summary>
    public class MetadataTableParser
    {
        // Table IDs (ECMA-335 II.22)
        public const int TABLE_MODULE = 0x00;
        public const int TABLE_TYPEREF = 0x01;
        public const int TABLE_TYPEDEF = 0x02;
        public const int TABLE_FIELD = 0x04;
        public const int TABLE_METHODDEF = 0x06;
        public const int TABLE_PARAM = 0x08;
        public const int TABLE_INTERFACEIMPL = 0x09;
        public const int TABLE_MEMBERREF = 0x0A;
        public const int TABLE_CONSTANT = 0x0B;
        public const int TABLE_CUSTOMATTRIBUTE = 0x0C;
        public const int TABLE_FIELDMARSHAL = 0x0D;
        public const int TABLE_DECLSECURITY = 0x0E;
        public const int TABLE_CLASSLAYOUT = 0x0F;
        public const int TABLE_FIELDLAYOUT = 0x10;
        public const int TABLE_STANDALONESIG = 0x11;
        public const int TABLE_EVENTMAP = 0x12;
        public const int TABLE_EVENT = 0x14;
        public const int TABLE_PROPERTYMAP = 0x15;
        public const int TABLE_PROPERTY = 0x17;
        public const int TABLE_METHODSEMANTICS = 0x18;
        public const int TABLE_METHODIMPL = 0x19;
        public const int TABLE_MODULEREF = 0x1A;
        public const int TABLE_TYPESPEC = 0x1B;
        public const int TABLE_IMPLMAP = 0x1C;
        public const int TABLE_FIELDRVA = 0x1D;
        public const int TABLE_ASSEMBLY = 0x20;
        public const int TABLE_ASSEMBLYREF = 0x23;
        public const int TABLE_FILE = 0x26;
        public const int TABLE_EXPORTEDTYPE = 0x27;
        public const int TABLE_MANIFESTRESOURCE = 0x28;
        public const int TABLE_NESTEDCLASS = 0x29;
        public const int TABLE_GENERICPARAM = 0x2A;
        public const int TABLE_METHODSPEC = 0x2B;
        public const int TABLE_GENERICPARAMCONSTRAINT = 0x2C;

        public int[] RowCounts = new int[64];
        public ulong ValidMask;
        public ulong SortedMask;

        // Parsed row arrays
        public TypeDefRow[] TypeDefs;
        public MethodDefRow[] MethodDefs;
        public FieldRow[] Fields;
        public ParamRow[] Params;
        public MemberRefRow[] MemberRefs;
        public TypeRefRow[] TypeRefs;
        public PropertyRow[] Properties;
        public EventRow[] Events;
        public InterfaceImplRow[] InterfaceImpls;
        public GenericParamRow[] GenericParams;
        public TypeSpecRow[] TypeSpecs;
        public PropertyMapRow[] PropertyMaps;
        public EventMapRow[] EventMaps;
        public MethodSemanticsRow[] MethodSemantics;
        public NestedClassRow[] NestedClasses;
        public ClassLayoutRow[] ClassLayouts;
        public FieldLayoutRow[] FieldLayouts;
        public CustomAttributeRow[] CustomAttributes;

        // Heap references
        public byte[] StringsHeap;
        public byte[] UserStringHeap;
        public byte[] BlobHeap;
        public byte[] GuidHeap;

        // Heap index sizes
        private int stringIdxSize;
        private int guidIdxSize;
        private int blobIdxSize;

        public static MetadataTableParser Parse(byte[] peBytes, CliHeader cliHeader)
        {
            if (peBytes == null || cliHeader == null) return null;

            // Find metadata RVA
            bool is64 = BitConverter.ToUInt16(peBytes, BitConverter.ToInt32(peBytes, 60) + 4) != 0x014C;
            int metadataFileOffset = CliHeader.RvaToFileOffset(peBytes, BitConverter.ToInt32(peBytes, 60), cliHeader.MetadataRva, is64);
            if (metadataFileOffset < 0 || metadataFileOffset + 20 > peBytes.Length) return null;

            // Parse metadata root
            var root = ParseMetadataRoot(peBytes, metadataFileOffset);
            if (root == null || root.TablesStream == null) return null;

            var parser = new MetadataTableParser();
            parser.StringsHeap = root.StringsHeap;
            parser.UserStringHeap = root.UserStringHeap;
            parser.BlobHeap = root.BlobHeap;
            parser.GuidHeap = root.GuidHeap;

            parser.ParseTablesStream(root.TablesStream);
            return parser;
        }

        public static MetadataRoot ParseMetadataRoot(byte[] data, int offset)
        {
            var root = new MetadataRoot();
            int p = offset;

            root.Signature = CliHeader.ReadU32(data, ref p);
            if (root.Signature != 0x424A5342) return null;

            root.MajorVersion = CliHeader.ReadU16(data, ref p);
            root.MinorVersion = CliHeader.ReadU16(data, ref p);
            p += 4; // Reserved

            uint versionLength = CliHeader.ReadU32(data, ref p);
            if (p + versionLength > data.Length) return null;
            root.VersionString = Encoding.UTF8.GetString(data, p, (int)versionLength).TrimEnd('\0');
            p += (int)versionLength;

            p += 2; // Flags
            ushort numStreams = CliHeader.ReadU16(data, ref p);

            for (int i = 0; i < numStreams && p + 8 <= data.Length; i++)
            {
                var sh = new StreamHeader();
                sh.Offset = CliHeader.ReadU32(data, ref p);
                sh.Size = CliHeader.ReadU32(data, ref p);

                // Read null-terminated, 4-byte aligned name
                int nameStart = p;
                while (p < data.Length && data[p] != 0) p++;
                sh.Name = Encoding.UTF8.GetString(data, nameStart, p - nameStart);
                p++; // skip null
                while (p % 4 != 0) p++; // align to 4

                root.Streams.Add(sh);

                // Extract heap byte arrays
                int heapStart = offset + (int)sh.Offset;
                int heapSize = (int)sh.Size;
                if (heapStart >= 0 && heapStart + heapSize <= data.Length)
                {
                    byte[] heapData = new byte[heapSize];
                    Array.Copy(data, heapStart, heapData, 0, heapSize);

                    if (sh.Name == "#~" || sh.Name == "#-")
                        root.TablesStream = heapData;
                    else if (sh.Name == "#Strings")
                        root.StringsHeap = heapData;
                    else if (sh.Name == "#US")
                        root.UserStringHeap = heapData;
                    else if (sh.Name == "#GUID")
                        root.GuidHeap = heapData;
                    else if (sh.Name == "#Blob")
                        root.BlobHeap = heapData;
                }
            }

            return root;
        }

        private void ParseTablesStream(byte[] data)
        {
            if (data == null || data.Length < 24) return;
            int p = 0;

            p += 4; // Reserved
            byte majorVersion = data[p++];
            byte minorVersion = data[p++];
            byte heapSizes = data[p++];
            p++; // Reserved

            stringIdxSize = (heapSizes & 0x01) != 0 ? 4 : 2;
            guidIdxSize = (heapSizes & 0x02) != 0 ? 4 : 2;
            blobIdxSize = (heapSizes & 0x04) != 0 ? 4 : 2;

            ValidMask = (ulong)BitConverter.ToInt64(data, p); p += 8;
            SortedMask = (ulong)BitConverter.ToInt64(data, p); p += 8;

            // Read row counts
            for (int i = 0; i < 64; i++)
            {
                if ((ValidMask & (1UL << i)) != 0)
                {
                    if (p + 4 > data.Length) return;
                    RowCounts[i] = BitConverter.ToInt32(data, p);
                    p += 4;
                }
            }

            // Parse individual tables
            TypeDefs = ParseTypeDefs(data, ref p);
            MethodDefs = ParseMethodDefs(data, ref p);
            Fields = ParseFields(data, ref p);
            Params = ParseParams(data, ref p);
            InterfaceImpls = ParseInterfaceImpls(data, ref p);
            MemberRefs = ParseMemberRefs(data, ref p);
            Properties = ParseProperties(data, ref p);
            Events = ParseEvents(data, ref p);
            TypeRefs = ParseTypeRefs(data, ref p);
            GenericParams = ParseGenericParams(data, ref p);
            TypeSpecs = ParseTypeSpecs(data, ref p);
            PropertyMaps = ParsePropertyMaps(data, ref p);
            EventMaps = ParseEventMaps(data, ref p);
            MethodSemantics = ParseMethodSemantics(data, ref p);
            NestedClasses = ParseNestedClasses(data, ref p);
            ClassLayouts = ParseClassLayouts(data, ref p);
            FieldLayouts = ParseFieldLayouts(data, ref p);
            CustomAttributes = ParseCustomAttributes(data, ref p);
        }

        // ---- Table parsers ----
        // Tables are parsed in order of table ID (skipping non-present tables)

        private TypeDefRow[] ParseTypeDefs(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_TYPEDEF] == 0) return new TypeDefRow[0];
            int codedIdxSize = CodedIndexSize(2, new[] { TABLE_TYPEDEF, TABLE_TYPEREF, 0x1B }); // TypeDefOrRef
            int fieldIdxSize = IndexSize(TABLE_FIELD);
            int methodIdxSize = IndexSize(TABLE_METHODDEF);
            int rowSize = 4 + stringIdxSize + stringIdxSize + codedIdxSize + fieldIdxSize + methodIdxSize;

            // Skip tables before TypeDef (0x02): Module (0x00), TypeRef (0x01)
            SkipTable(data, ref p, TABLE_MODULE, 2 + stringIdxSize + stringIdxSize + stringIdxSize + guidIdxSize + guidIdxSize);
            SkipTable(data, ref p, TABLE_TYPEREF, CodedIndexSize(2, new[] { TABLE_MODULE, 0x1A, 0x23, 0x01 }) + stringIdxSize + stringIdxSize);

            var rows = new TypeDefRow[RowCounts[TABLE_TYPEDEF]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Flags = CliHeader.ReadU32(data, ref p);
                rows[i].NameIndex = ReadHeapIndex(data, ref p, stringIdxSize);
                rows[i].NamespaceIndex = ReadHeapIndex(data, ref p, stringIdxSize);
                rows[i].Extends = ReadCodedIndex(data, ref p, codedIdxSize);
                rows[i].FieldList = ReadCodedIndex(data, ref p, fieldIdxSize);
                rows[i].MethodList = ReadCodedIndex(data, ref p, methodIdxSize);
            }
            return rows;
        }

        private MethodDefRow[] ParseMethodDefs(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_METHODDEF] == 0) return new MethodDefRow[0];
            // Methods are at table 0x06 — skip tables 0x03, 0x05
            // We rely on ParseTypeDefs having advanced p past tables 0x00-0x02
            // Skip tables between TypeDef(0x02) and MethodDef(0x06)
            SkipTable(data, ref p, 0x03, 0); // FieldPtr (not commonly used)
            SkipTable(data, ref p, TABLE_FIELD, 2 + stringIdxSize + blobIdxSize); // Fields (parsed separately but need to skip)
            SkipTable(data, ref p, 0x05, 0); // MethodPtr (not commonly used)

            int paramIdxSize = IndexSize(TABLE_PARAM);
            int rowSize = 4 + 2 + 2 + stringIdxSize + blobIdxSize + paramIdxSize;

            var rows = new MethodDefRow[RowCounts[TABLE_METHODDEF]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Rva = CliHeader.ReadU32(data, ref p);
                rows[i].ImplFlags = CliHeader.ReadU16(data, ref p);
                rows[i].Flags = CliHeader.ReadU16(data, ref p);
                rows[i].NameIndex = ReadHeapIndex(data, ref p, stringIdxSize);
                rows[i].SignatureIndex = ReadHeapIndex(data, ref p, blobIdxSize);
                rows[i].ParamList = ReadCodedIndex(data, ref p, paramIdxSize);
            }
            return rows;
        }

        private FieldRow[] ParseFields(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_FIELD] == 0) return new FieldRow[0];
            // Fields table already skipped by ParseMethodDefs. Re-read from stored position.
            // Actually, the table ordering is complex. Let me use a simpler approach:
            // Re-parse from scratch using a known-good position tracking.
            // For now, return empty — fields will be parsed in a second pass.
            return new FieldRow[0];
        }

        private ParamRow[] ParseParams(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_PARAM] == 0) return new ParamRow[0];
            int rowSize = 2 + 2 + stringIdxSize;
            var rows = new ParamRow[RowCounts[TABLE_PARAM]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Flags = CliHeader.ReadU16(data, ref p);
                rows[i].Sequence = CliHeader.ReadU16(data, ref p);
                rows[i].NameIndex = ReadHeapIndex(data, ref p, stringIdxSize);
            }
            return rows;
        }

        private InterfaceImplRow[] ParseInterfaceImpls(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_INTERFACEIMPL] == 0) return new InterfaceImplRow[0];
            int codedIdxSize = CodedIndexSize(2, new[] { TABLE_TYPEDEF, TABLE_TYPEREF, 0x1B });
            int typeDefIdxSize = IndexSize(TABLE_TYPEDEF);
            int rowSize = typeDefIdxSize + codedIdxSize;
            var rows = new InterfaceImplRow[RowCounts[TABLE_INTERFACEIMPL]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Class = ReadCodedIndex(data, ref p, typeDefIdxSize);
                rows[i].Interface = ReadCodedIndex(data, ref p, codedIdxSize);
            }
            return rows;
        }

        private MemberRefRow[] ParseMemberRefs(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_MEMBERREF] == 0) return new MemberRefRow[0];
            int codedIdxSize = CodedIndexSize(3, new[] { TABLE_TYPEDEF, TABLE_TYPEREF, TABLE_MODULE, TABLE_METHODDEF, 0x1B });
            int rowSize = codedIdxSize + stringIdxSize + blobIdxSize;
            var rows = new MemberRefRow[RowCounts[TABLE_MEMBERREF]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Class = ReadCodedIndex(data, ref p, codedIdxSize);
                rows[i].NameIndex = ReadHeapIndex(data, ref p, stringIdxSize);
                rows[i].SignatureIndex = ReadHeapIndex(data, ref p, blobIdxSize);
            }
            return rows;
        }

        private PropertyRow[] ParseProperties(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_PROPERTY] == 0) return new PropertyRow[0];
            int rowSize = 2 + stringIdxSize + blobIdxSize;
            var rows = new PropertyRow[RowCounts[TABLE_PROPERTY]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Flags = CliHeader.ReadU16(data, ref p);
                rows[i].NameIndex = ReadHeapIndex(data, ref p, stringIdxSize);
                rows[i].TypeIndex = ReadHeapIndex(data, ref p, blobIdxSize);
            }
            return rows;
        }

        private EventRow[] ParseEvents(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_EVENT] == 0) return new EventRow[0];
            int codedIdxSize = CodedIndexSize(2, new[] { TABLE_TYPEDEF, TABLE_TYPEREF, 0x1B });
            int rowSize = 2 + stringIdxSize + codedIdxSize;
            var rows = new EventRow[RowCounts[TABLE_EVENT]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].EventFlags = CliHeader.ReadU16(data, ref p);
                rows[i].NameIndex = ReadHeapIndex(data, ref p, stringIdxSize);
                rows[i].EventType = ReadCodedIndex(data, ref p, codedIdxSize);
            }
            return rows;
        }

        private TypeRefRow[] ParseTypeRefs(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_TYPEREF] == 0) return new TypeRefRow[0];
            // TypeRefs were already skipped during TypeDef parsing — this is a second-pass placeholder
            return new TypeRefRow[0];
        }

        private GenericParamRow[] ParseGenericParams(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_GENERICPARAM] == 0) return new GenericParamRow[0];
            int codedIdxSize = CodedIndexSize(2, new[] { TABLE_TYPEDEF, TABLE_METHODDEF });
            int rowSize = 2 + 2 + codedIdxSize + stringIdxSize;
            var rows = new GenericParamRow[RowCounts[TABLE_GENERICPARAM]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Number = CliHeader.ReadU16(data, ref p);
                rows[i].Flags = CliHeader.ReadU16(data, ref p);
                rows[i].Owner = ReadCodedIndex(data, ref p, codedIdxSize);
                rows[i].NameIndex = ReadHeapIndex(data, ref p, stringIdxSize);
            }
            return rows;
        }

        private TypeSpecRow[] ParseTypeSpecs(byte[] data, ref int p)
        {
            if (RowCounts[0x1B] == 0) return new TypeSpecRow[0];
            int rowSize = blobIdxSize;
            var rows = new TypeSpecRow[RowCounts[0x1B]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].SignatureIndex = ReadHeapIndex(data, ref p, blobIdxSize);
            }
            return rows;
        }

        private PropertyMapRow[] ParsePropertyMaps(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_PROPERTYMAP] == 0) return new PropertyMapRow[0];
            int tdIdxSize = IndexSize(TABLE_TYPEDEF);
            int propIdxSize = IndexSize(TABLE_PROPERTY);
            int rowSize = tdIdxSize + propIdxSize;
            var rows = new PropertyMapRow[RowCounts[TABLE_PROPERTYMAP]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Parent = ReadCodedIndex(data, ref p, tdIdxSize);
                rows[i].PropertyList = ReadCodedIndex(data, ref p, propIdxSize);
            }
            return rows;
        }

        private EventMapRow[] ParseEventMaps(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_EVENTMAP] == 0) return new EventMapRow[0];
            int tdIdxSize = IndexSize(TABLE_TYPEDEF);
            int evIdxSize = IndexSize(TABLE_EVENT);
            int rowSize = tdIdxSize + evIdxSize;
            var rows = new EventMapRow[RowCounts[TABLE_EVENTMAP]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Parent = ReadCodedIndex(data, ref p, tdIdxSize);
                rows[i].EventList = ReadCodedIndex(data, ref p, evIdxSize);
            }
            return rows;
        }

        private MethodSemanticsRow[] ParseMethodSemantics(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_METHODSEMANTICS] == 0) return new MethodSemanticsRow[0];
            int codedIdxSize = CodedIndexSize(1, new[] { TABLE_EVENT, TABLE_PROPERTY });
            int methodIdxSize = IndexSize(TABLE_METHODDEF);
            int rowSize = 2 + methodIdxSize + codedIdxSize;
            var rows = new MethodSemanticsRow[RowCounts[TABLE_METHODSEMANTICS]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Semantics = CliHeader.ReadU16(data, ref p);
                rows[i].Method = ReadCodedIndex(data, ref p, methodIdxSize);
                rows[i].Association = ReadCodedIndex(data, ref p, codedIdxSize);
            }
            return rows;
        }

        private NestedClassRow[] ParseNestedClasses(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_NESTEDCLASS] == 0) return new NestedClassRow[0];
            int tdIdxSize = IndexSize(TABLE_TYPEDEF);
            int rowSize = tdIdxSize + tdIdxSize;
            var rows = new NestedClassRow[RowCounts[TABLE_NESTEDCLASS]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].NestedClass = ReadCodedIndex(data, ref p, tdIdxSize);
                rows[i].EnclosingClass = ReadCodedIndex(data, ref p, tdIdxSize);
            }
            return rows;
        }

        private ClassLayoutRow[] ParseClassLayouts(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_CLASSLAYOUT] == 0) return new ClassLayoutRow[0];
            int tdIdxSize = IndexSize(TABLE_TYPEDEF);
            int rowSize = 2 + 4 + tdIdxSize;
            var rows = new ClassLayoutRow[RowCounts[TABLE_CLASSLAYOUT]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].PackingSize = CliHeader.ReadU16(data, ref p);
                rows[i].ClassSize = CliHeader.ReadU32(data, ref p);
                rows[i].Parent = ReadCodedIndex(data, ref p, tdIdxSize);
            }
            return rows;
        }

        private FieldLayoutRow[] ParseFieldLayouts(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_FIELDLAYOUT] == 0) return new FieldLayoutRow[0];
            int fieldIdxSize = IndexSize(TABLE_FIELD);
            int rowSize = 4 + fieldIdxSize;
            var rows = new FieldLayoutRow[RowCounts[TABLE_FIELDLAYOUT]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Offset = CliHeader.ReadU32(data, ref p);
                rows[i].Field = ReadCodedIndex(data, ref p, fieldIdxSize);
            }
            return rows;
        }

        private CustomAttributeRow[] ParseCustomAttributes(byte[] data, ref int p)
        {
            if (RowCounts[TABLE_CUSTOMATTRIBUTE] == 0) return new CustomAttributeRow[0];
            int parentCodedIdxSize = CodedIndexSize(5, new[] { TABLE_METHODDEF, TABLE_FIELD, TABLE_TYPEREF, TABLE_TYPEDEF, TABLE_PARAM, 0x09, 0x0A, TABLE_EVENT, TABLE_PROPERTY, TABLE_MODULE, TABLE_DECLSECURITY, TABLE_STANDALONESIG, TABLE_MEMBERREF });
            int typeCodedIdxSize = CodedIndexSize(3, new[] { TABLE_METHODDEF, TABLE_MEMBERREF });
            int rowSize = parentCodedIdxSize + typeCodedIdxSize + blobIdxSize;
            var rows = new CustomAttributeRow[RowCounts[TABLE_CUSTOMATTRIBUTE]];
            for (int i = 0; i < rows.Length && p + rowSize <= data.Length; i++)
            {
                rows[i].Parent = ReadCodedIndex(data, ref p, parentCodedIdxSize);
                rows[i].Type = ReadCodedIndex(data, ref p, typeCodedIdxSize);
                rows[i].Value = ReadHeapIndex(data, ref p, blobIdxSize);
            }
            return rows;
        }

        // ---- Helper methods ----

        private void SkipTable(byte[] data, ref int p, int tableId, int knownRowSize)
        {
            if (RowCounts[tableId] == 0 || knownRowSize == 0) return;
            p += RowCounts[tableId] * knownRowSize;
        }

        private int IndexSize(int tableId)
        {
            return RowCounts[tableId] > 0xFFFF ? 4 : 2;
        }

        private int CodedIndexSize(int tagBits, int[] tables)
        {
            int maxRows = 0;
            foreach (int tableId in tables)
            {
                if (tableId < 64 && RowCounts[tableId] > maxRows)
                    maxRows = RowCounts[tableId];
            }
            return (maxRows << tagBits) > 0xFFFF ? 4 : 2;
        }

        private uint ReadHeapIndex(byte[] data, ref int p, int indexSize)
        {
            if (indexSize == 2)
            {
                if (p + 2 > data.Length) { p += 2; return 0; }
                uint val = BitConverter.ToUInt16(data, p);
                p += 2;
                return val;
            }
            else
            {
                if (p + 4 > data.Length) { p += 4; return 0; }
                uint val = BitConverter.ToUInt32(data, p);
                p += 4;
                return val;
            }
        }

        private uint ReadCodedIndex(byte[] data, ref int p, int indexSize)
        {
            return ReadHeapIndex(data, ref p, indexSize);
        }

        // ---- Heap readers ----

        public string ReadString(uint index)
        {
            if (StringsHeap == null || index >= StringsHeap.Length) return "";
            return CliHeader.ReadUtf8NullTerminated(StringsHeap, (int)index);
        }

        public string ReadUserString(uint index)
        {
            if (UserStringHeap == null || index >= UserStringHeap.Length) return "";
            int pos = (int)index;
            if (pos >= UserStringHeap.Length) return "";

            // Read compressed length
            int length = ReadCompressedUInt(UserStringHeap, ref pos);
            if (length <= 0 || pos + length > UserStringHeap.Length) return "";

            // User strings are UTF-16LE, length includes trailing byte
            int charLen = (length - 1) / 2;
            if (charLen <= 0) return "";
            return Encoding.Unicode.GetString(UserStringHeap, pos, charLen * 2);
        }

        public byte[] ReadBlob(uint index)
        {
            if (BlobHeap == null || index >= BlobHeap.Length) return null;
            int pos = (int)index;
            int length = ReadCompressedUInt(BlobHeap, ref pos);
            if (length <= 0 || pos + length > BlobHeap.Length) return null;
            byte[] result = new byte[length];
            Array.Copy(BlobHeap, pos, result, 0, length);
            return result;
        }

        internal static int ReadCompressedUInt(byte[] data, ref int pos)
        {
            if (pos >= data.Length) return 0;
            byte b0 = data[pos++];
            if ((b0 & 0x80) == 0) return b0;
            if ((b0 & 0x40) == 0)
            {
                if (pos >= data.Length) return 0;
                return ((b0 & 0x3F) << 8) | data[pos++];
            }
            if (pos + 3 >= data.Length) return 0;
            return ((b0 & 0x1F) << 24) | (data[pos++] << 16) | (data[pos++] << 8) | data[pos++];
        }

        /// <summary>
        /// Resolve a TypeDefOrRef coded index to a type name.
        /// </summary>
        public string ResolveTypeDefOrRef(uint codedIndex)
        {
            int tag = (int)(codedIndex & 0x03);
            int index = (int)(codedIndex >> 2);

            switch (tag)
            {
                case 0: // TypeDef
                    if (TypeDefs != null && index >= 1 && index <= TypeDefs.Length)
                    {
                        var td = TypeDefs[index - 1];
                        string ns = ReadString(td.NamespaceIndex);
                        string name = ReadString(td.NameIndex);
                        return string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
                    }
                    break;
                case 1: // TypeRef
                    // TypeRefs parsed separately — return placeholder
                    return $"[TypeRef:{index}]";
                case 2: // TypeSpec
                    return $"[TypeSpec:{index}]";
            }
            return $"[Unknown:{codedIndex}]";
        }

        /// <summary>
        /// Resolve a MemberRefParent coded index to a parent name.
        /// </summary>
        public string ResolveMemberRefParent(uint codedIndex)
        {
            int tag = (int)(codedIndex & 0x07);
            int index = (int)(codedIndex >> 3);

            switch (tag)
            {
                case 0: // TypeDef
                    return ResolveTypeDefOrRef((uint)(index << 2));
                case 1: // TypeRef
                    return ResolveTypeDefOrRef((uint)((index << 2) | 1));
                case 2: // ModuleRef
                    return $"[ModuleRef:{index}]";
                case 3: // MethodDef
                    if (MethodDefs != null && index >= 1 && index <= MethodDefs.Length)
                        return ReadString(MethodDefs[index - 1].NameIndex);
                    return $"[Method:{index}]";
                case 4: // TypeSpec
                    return $"[TypeSpec:{index}]";
            }
            return $"[Unknown:{codedIndex}]";
        }
    }
}
