using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class Il2CppDumper
    {
        private const uint IL2CPP_METADATA_MAGIC = 0xFAB11BAF;

        // ---------- Public data types ----------

        public struct MetadataInfo
        {
            public uint Magic;
            public int Version;
            public int Size;
            public ulong VirtualAddress;
        }

        public class Il2CppMetadataHeader
        {
            public int StringLiteralOffset, StringLiteralSize;
            public int StringLiteralDataOffset, StringLiteralDataSize;
            public int StringOffset, StringSize;
            public int EventsOffset, EventsSize;
            public int PropertiesOffset, PropertiesSize;
            public int MethodsOffset, MethodsSize;
            public int ParameterDefaultValuesOffset, ParameterDefaultValuesSize;
            public int FieldDefaultValuesOffset, FieldDefaultValuesSize;
            public int FieldAndParameterDefaultValueDataOffset, FieldAndParameterDefaultValueDataSize;
            public int FieldMarshaledSizesOffset, FieldMarshaledSizesSize;
            public int ParametersOffset, ParametersSize;
            public int FieldsOffset, FieldsSize;
            public int GenericParametersOffset, GenericParametersSize;
            public int GenericParameterConstraintsOffset, GenericParameterConstraintsSize;
            public int GenericContainersOffset, GenericContainersSize;
            public int NestedTypesOffset, NestedTypesSize;
            public int InterfacesOffset, InterfacesSize;
            public int VTableMethodsOffset, VTableMethodsSize;
            public int InterfaceOffsetsOffset, InterfaceOffsetsSize;
            public int MetadataUsageListsOffset, MetadataUsageListsSize;
            public int MetadataUsagePairsOffset, MetadataUsagePairsSize;
            public int TypeDefinitionsOffset, TypeDefinitionsSize;
            public int ImagesOffset, ImagesSize;
            public int AssembliesOffset, AssembliesSize;
            public int FieldRefsOffset, FieldRefsSize;
            public int ReferencedAssembliesOffset, ReferencedAssembliesSize;
            public int AttributeDataOffset, AttributeDataSize;
            public int AttributeDataRangeOffset, AttributeDataRangeSize; // v31+
        }

        public struct Il2CppTypeDefinition
        {
            public int NameIndex;
            public int NamespaceIndex;
            public int CustomAttributeIndex;
            public int ByValTypeIndex;
            public int ByRefTypeIndex;
            public int DeclaringTypeIndex;
            public int ParentIndex;
            public int ElementTypeIndex;
            public int RgctxStartIndex;
            public int RgctxCount;
            public int GenericContainerIndex;
            public uint Flags;
            public int FieldStart;
            public int MethodStart;
            public int EventStart;
            public int PropertyStart;
            public int InterfacesStart;
            public int VTableStart;
            public int ReversePInvokeWrapperStart;
            public int InterfaceOffsetsStart;
            public ushort MethodCount;
            public ushort PropertyCount;
            public ushort FieldCount;
            public ushort EventCount;
            public ushort InterfaceCount;
            public ushort VTableCount;
            public ushort ReversePInvokeWrapperCount;
            public ushort InterfaceOffsetsCount;
            public uint Bitfield;
            public uint Token;
            public int ReversedPackedTerms; // v29+ only
        }

        public struct Il2CppMethodDefinition
        {
            public uint NameIndex;
            public int DeclaringType;
            public int ReturnType;
            public int ParameterStart;
            public int GenericContainerIndex;
            public int CustomAttributeIndex;
            public uint Token;
            public ushort Flags;
            public ushort IFlags;
            public ushort Slot;
            public ushort ParameterCount;
        }

        public struct Il2CppFieldDefinition
        {
            public uint NameIndex;
            public int TypeIndex;
            public uint Token;
        }

        public struct Il2CppParameterDefinition
        {
            public uint NameIndex;
            public uint Token;
            public int TypeIndex;
            public uint CustomAttributeIndex;
        }

        public struct Il2CppPropertyDefinition
        {
            public uint NameIndex;
            public int Get;
            public int Set;
            public uint Attrs;
            public uint CustomAttributeIndex;
            public uint Token;
        }

        public struct Il2CppEventDefinition
        {
            public uint NameIndex;
            public uint Token;
            public int TypeIndex;
        }

        public struct Il2CppGenericContainer
        {
            public int OwnerIndex;
            public int TypeArgCount;
            public int IsMethod;
            public int GenericParameterStart;
        }

        public struct Il2CppGenericParameter
        {
            public uint ContainerIndex;
            public uint NameIndex;
            public ushort Num;
            public ushort Flags;
        }

        public struct Il2CppImageDefinition
        {
            public int NameIndex;
            public int AssemblyIndex;
            public int TypeStart;
            public uint TypeCount;
            public int ExportedTypeStart;
            public uint ExportedTypeCount;
            public int EntryPointIndex;
            public uint Token;
        }

        public struct Il2CppAssemblyDefinition
        {
            public int ImageIndex;
            public uint Token;
            public int ReferencedAssemblyStart;
            public int ReferencedAssemblyCount;
            public int NameIndex;
            public int CultureIndex;
            public int HashValueIndex;
            public int PublicKeyIndex;
            public ushort Major, Minor, Build, Revision;
            public uint Flags;
        }

        public class Il2CppMetadataSnapshot
        {
            public int Version;
            public Il2CppMetadataHeader Header;
            public Il2CppTypeDefinition[] TypeDefinitions;
            public Il2CppMethodDefinition[] Methods;
            public Il2CppFieldDefinition[] Fields;
            public Il2CppParameterDefinition[] Parameters;
            public Il2CppPropertyDefinition[] Properties;
            public Il2CppEventDefinition[] Events;
            public Il2CppGenericContainer[] GenericContainers;
            public Il2CppGenericParameter[] GenericParameters;
            public int[] InterfaceIndices;
            public int[] NestedTypeIndices;
            public Il2CppImageDefinition[] Images;
            public Il2CppAssemblyDefinition[] Assemblies;
            public byte[] RawMetadata;
        }

        // ---------- Existing API ----------

        public static bool ValidateMagic(byte[] metadata)
        {
            if (metadata == null || metadata.Length < 8)
                return false;
            uint magic = BitConverter.ToUInt32(metadata, 0);
            return magic == IL2CPP_METADATA_MAGIC;
        }

        public static MetadataInfo ParseHeader(byte[] metadata, ulong virtualAddress)
        {
            var info = new MetadataInfo { VirtualAddress = virtualAddress };

            if (metadata != null && metadata.Length >= 8)
            {
                info.Magic = BitConverter.ToUInt32(metadata, 0);
                info.Version = BitConverter.ToInt32(metadata, 4);
                info.Size = metadata.Length;
            }

            return info;
        }

        public static void Save(string outputPath, byte[] metadata, MetadataInfo info)
        {
            if (metadata == null || metadata.Length == 0)
                return;

            File.WriteAllBytes(outputPath, metadata);

            string infoPath = Path.ChangeExtension(outputPath, ".info.txt");
            using (var writer = new StreamWriter(infoPath))
            {
                writer.WriteLine($"// KsDumper - Il2Cpp Metadata Info");
                writer.WriteLine($"// Magic: 0x{info.Magic:X8} ({(info.Magic == IL2CPP_METADATA_MAGIC ? "VALID" : "INVALID")})");
                writer.WriteLine($"// Version: {info.Version}");
                writer.WriteLine($"// Size: {info.Size} bytes ({info.Size / 1024.0:F1} KB)");
                writer.WriteLine($"// Virtual Address: 0x{info.VirtualAddress:X}");
                writer.WriteLine();
                writer.WriteLine($"// Usage: Feed this file to Il2CppDumper along with GameAssembly.dll");
                writer.WriteLine($"//   Il2CppDumper.exe GameAssembly_dump.dll global-metadata.dat");
            }
        }

        // ---------- Header parsing ----------

        public static Il2CppMetadataHeader ParseMetadataHeader(byte[] metadata, int version)
        {
            var h = new Il2CppMetadataHeader();
            int p = 8; // skip magic(4) + version(4)

            h.StringLiteralOffset = ReadI32(metadata, ref p);
            h.StringLiteralSize = ReadI32(metadata, ref p);
            h.StringLiteralDataOffset = ReadI32(metadata, ref p);
            h.StringLiteralDataSize = ReadI32(metadata, ref p);
            h.StringOffset = ReadI32(metadata, ref p);
            h.StringSize = ReadI32(metadata, ref p);
            h.EventsOffset = ReadI32(metadata, ref p);
            h.EventsSize = ReadI32(metadata, ref p);
            h.PropertiesOffset = ReadI32(metadata, ref p);
            h.PropertiesSize = ReadI32(metadata, ref p);
            h.MethodsOffset = ReadI32(metadata, ref p);
            h.MethodsSize = ReadI32(metadata, ref p);
            h.ParameterDefaultValuesOffset = ReadI32(metadata, ref p);
            h.ParameterDefaultValuesSize = ReadI32(metadata, ref p);
            h.FieldDefaultValuesOffset = ReadI32(metadata, ref p);
            h.FieldDefaultValuesSize = ReadI32(metadata, ref p);
            h.FieldAndParameterDefaultValueDataOffset = ReadI32(metadata, ref p);
            h.FieldAndParameterDefaultValueDataSize = ReadI32(metadata, ref p);
            h.FieldMarshaledSizesOffset = ReadI32(metadata, ref p);
            h.FieldMarshaledSizesSize = ReadI32(metadata, ref p);
            h.ParametersOffset = ReadI32(metadata, ref p);
            h.ParametersSize = ReadI32(metadata, ref p);
            h.FieldsOffset = ReadI32(metadata, ref p);
            h.FieldsSize = ReadI32(metadata, ref p);
            h.GenericParametersOffset = ReadI32(metadata, ref p);
            h.GenericParametersSize = ReadI32(metadata, ref p);
            h.GenericParameterConstraintsOffset = ReadI32(metadata, ref p);
            h.GenericParameterConstraintsSize = ReadI32(metadata, ref p);
            h.GenericContainersOffset = ReadI32(metadata, ref p);
            h.GenericContainersSize = ReadI32(metadata, ref p);
            h.NestedTypesOffset = ReadI32(metadata, ref p);
            h.NestedTypesSize = ReadI32(metadata, ref p);
            h.InterfacesOffset = ReadI32(metadata, ref p);
            h.InterfacesSize = ReadI32(metadata, ref p);
            h.VTableMethodsOffset = ReadI32(metadata, ref p);
            h.VTableMethodsSize = ReadI32(metadata, ref p);
            h.InterfaceOffsetsOffset = ReadI32(metadata, ref p);
            h.InterfaceOffsetsSize = ReadI32(metadata, ref p);
            h.MetadataUsageListsOffset = ReadI32(metadata, ref p);
            h.MetadataUsageListsSize = ReadI32(metadata, ref p);
            h.MetadataUsagePairsOffset = ReadI32(metadata, ref p);
            h.MetadataUsagePairsSize = ReadI32(metadata, ref p);
            h.TypeDefinitionsOffset = ReadI32(metadata, ref p);
            h.TypeDefinitionsSize = ReadI32(metadata, ref p);
            h.ImagesOffset = ReadI32(metadata, ref p);
            h.ImagesSize = ReadI32(metadata, ref p);
            h.AssembliesOffset = ReadI32(metadata, ref p);
            h.AssembliesSize = ReadI32(metadata, ref p);

            if (version >= 24)
            {
                h.FieldRefsOffset = ReadI32(metadata, ref p);
                h.FieldRefsSize = ReadI32(metadata, ref p);
                h.ReferencedAssembliesOffset = ReadI32(metadata, ref p);
                h.ReferencedAssembliesSize = ReadI32(metadata, ref p);
            }

            if (version >= 24 && p + 8 <= metadata.Length)
            {
                h.AttributeDataOffset = ReadI32(metadata, ref p);
                h.AttributeDataSize = ReadI32(metadata, ref p);
            }

            if (version >= 31 && p + 8 <= metadata.Length)
            {
                h.AttributeDataRangeOffset = ReadI32(metadata, ref p);
                h.AttributeDataRangeSize = ReadI32(metadata, ref p);
            }

            return h;
        }

        // ---------- Section parsers ----------

        public static string ReadStringFromTable(byte[] metadata, int stringOffset, int stringSize, int index)
        {
            if (index < 0 || stringOffset <= 0 || stringSize <= 0)
                return "";
            int pos = stringOffset + index;
            if (pos < 0 || pos >= metadata.Length)
                return "";
            int end = pos;
            while (end < metadata.Length && metadata[end] != 0)
                end++;
            if (end == pos)
                return "";
            return Encoding.UTF8.GetString(metadata, pos, end - pos);
        }

        private static int GetTypeDefSize(int version)
        {
            // v29+: 112 bytes (adds ReversedPackedTerms)
            // v27: 108 bytes, v25: 104 bytes, v24: 100 bytes
            // v21-23: 92 bytes, v16-20: 84 bytes
            if (version >= 29) return 112;
            if (version >= 27) return 108;
            if (version >= 25) return 104;
            if (version >= 24) return 100;
            if (version >= 21) return 92;
            return 84; // v16-20
        }

        public static Il2CppTypeDefinition[] ParseTypeDefinitions(byte[] metadata, Il2CppMetadataHeader header, int version)
        {
            if (header.TypeDefinitionsOffset <= 0 || header.TypeDefinitionsSize <= 0)
                return new Il2CppTypeDefinition[0];

            int structSize = GetTypeDefSize(version);
            int count = header.TypeDefinitionsSize / structSize;
            var result = new Il2CppTypeDefinition[count];
            int baseOff = header.TypeDefinitionsOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var td = new Il2CppTypeDefinition();
                td.NameIndex = ReadI32At(metadata, p); p += 4;
                td.NamespaceIndex = ReadI32At(metadata, p); p += 4;
                td.CustomAttributeIndex = ReadI32At(metadata, p); p += 4;
                td.ByValTypeIndex = ReadI32At(metadata, p); p += 4;
                td.ByRefTypeIndex = ReadI32At(metadata, p); p += 4;
                td.DeclaringTypeIndex = ReadI32At(metadata, p); p += 4;
                td.ParentIndex = ReadI32At(metadata, p); p += 4;
                td.ElementTypeIndex = ReadI32At(metadata, p); p += 4;
                td.RgctxStartIndex = ReadI32At(metadata, p); p += 4;
                td.RgctxCount = ReadI32At(metadata, p); p += 4;
                td.GenericContainerIndex = ReadI32At(metadata, p); p += 4;
                td.Flags = ReadU32At(metadata, p); p += 4;
                td.FieldStart = ReadI32At(metadata, p); p += 4;
                td.MethodStart = ReadI32At(metadata, p); p += 4;
                td.EventStart = ReadI32At(metadata, p); p += 4;
                td.PropertyStart = ReadI32At(metadata, p); p += 4;
                td.InterfacesStart = ReadI32At(metadata, p); p += 4;
                td.VTableStart = ReadI32At(metadata, p); p += 4;
                td.ReversePInvokeWrapperStart = ReadI32At(metadata, p); p += 4;
                td.InterfaceOffsetsStart = ReadI32At(metadata, p); p += 4;
                td.MethodCount = ReadU16At(metadata, p); p += 2;
                td.PropertyCount = ReadU16At(metadata, p); p += 2;
                td.FieldCount = ReadU16At(metadata, p); p += 2;
                td.EventCount = ReadU16At(metadata, p); p += 2;
                td.InterfaceCount = ReadU16At(metadata, p); p += 2;
                td.VTableCount = ReadU16At(metadata, p); p += 2;
                td.ReversePInvokeWrapperCount = ReadU16At(metadata, p); p += 2;
                td.InterfaceOffsetsCount = ReadU16At(metadata, p); p += 2;
                td.Bitfield = ReadU32At(metadata, p); p += 4;
                td.Token = ReadU32At(metadata, p);

                // v29+ adds ReversedPackedTerms field (4 bytes at end of struct)
                if (version >= 29 && baseOff + i * structSize + 108 + 4 <= metadata.Length)
                {
                    td.ReversedPackedTerms = ReadI32At(metadata, baseOff + i * structSize + 108);
                }

                result[i] = td;
            }
            return result;
        }

        public static Il2CppMethodDefinition[] ParseMethods(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.MethodsOffset <= 0 || header.MethodsSize <= 0)
                return new Il2CppMethodDefinition[0];

            const int structSize = 48;
            int count = header.MethodsSize / structSize;
            var result = new Il2CppMethodDefinition[count];
            int baseOff = header.MethodsOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var m = new Il2CppMethodDefinition();
                m.NameIndex = ReadU32At(metadata, p); p += 4;
                m.DeclaringType = ReadI32At(metadata, p); p += 4;
                m.ReturnType = ReadI32At(metadata, p); p += 4;
                m.ParameterStart = ReadI32At(metadata, p); p += 4;
                m.GenericContainerIndex = ReadI32At(metadata, p); p += 4;
                m.CustomAttributeIndex = ReadI32At(metadata, p); p += 4;
                m.Token = ReadU32At(metadata, p); p += 4;
                m.Flags = ReadU16At(metadata, p); p += 2;
                m.IFlags = ReadU16At(metadata, p); p += 2;
                m.Slot = ReadU16At(metadata, p); p += 2;
                m.ParameterCount = ReadU16At(metadata, p);

                result[i] = m;
            }
            return result;
        }

        public static Il2CppFieldDefinition[] ParseFields(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.FieldsOffset <= 0 || header.FieldsSize <= 0)
                return new Il2CppFieldDefinition[0];

            const int structSize = 12;
            int count = header.FieldsSize / structSize;
            var result = new Il2CppFieldDefinition[count];
            int baseOff = header.FieldsOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var f = new Il2CppFieldDefinition();
                f.NameIndex = ReadU32At(metadata, p); p += 4;
                f.TypeIndex = ReadI32At(metadata, p); p += 4;
                f.Token = ReadU32At(metadata, p);

                result[i] = f;
            }
            return result;
        }

        public static Il2CppParameterDefinition[] ParseParameters(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.ParametersOffset <= 0 || header.ParametersSize <= 0)
                return new Il2CppParameterDefinition[0];

            const int structSize = 16;
            int count = header.ParametersSize / structSize;
            var result = new Il2CppParameterDefinition[count];
            int baseOff = header.ParametersOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var param = new Il2CppParameterDefinition();
                param.NameIndex = ReadU32At(metadata, p); p += 4;
                param.Token = ReadU32At(metadata, p); p += 4;
                param.TypeIndex = ReadI32At(metadata, p); p += 4;
                param.CustomAttributeIndex = ReadU32At(metadata, p);

                result[i] = param;
            }
            return result;
        }

        public static Il2CppPropertyDefinition[] ParseProperties(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.PropertiesOffset <= 0 || header.PropertiesSize <= 0)
                return new Il2CppPropertyDefinition[0];

            const int structSize = 24;
            int count = header.PropertiesSize / structSize;
            var result = new Il2CppPropertyDefinition[count];
            int baseOff = header.PropertiesOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var prop = new Il2CppPropertyDefinition();
                prop.NameIndex = ReadU32At(metadata, p); p += 4;
                prop.Get = ReadI32At(metadata, p); p += 4;
                prop.Set = ReadI32At(metadata, p); p += 4;
                prop.Attrs = ReadU32At(metadata, p); p += 4;
                prop.CustomAttributeIndex = ReadU32At(metadata, p); p += 4;
                prop.Token = ReadU32At(metadata, p);

                result[i] = prop;
            }
            return result;
        }

        public static Il2CppEventDefinition[] ParseEvents(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.EventsOffset <= 0 || header.EventsSize <= 0)
                return new Il2CppEventDefinition[0];

            const int structSize = 12;
            int count = header.EventsSize / structSize;
            var result = new Il2CppEventDefinition[count];
            int baseOff = header.EventsOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var ev = new Il2CppEventDefinition();
                ev.NameIndex = ReadU32At(metadata, p); p += 4;
                ev.Token = ReadU32At(metadata, p); p += 4;
                ev.TypeIndex = ReadI32At(metadata, p);
                result[i] = ev;
            }
            return result;
        }

        public static Il2CppGenericContainer[] ParseGenericContainers(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.GenericContainersOffset <= 0 || header.GenericContainersSize <= 0)
                return new Il2CppGenericContainer[0];

            const int structSize = 16;
            int count = header.GenericContainersSize / structSize;
            var result = new Il2CppGenericContainer[count];
            int baseOff = header.GenericContainersOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var gc = new Il2CppGenericContainer();
                gc.OwnerIndex = ReadI32At(metadata, p); p += 4;
                gc.TypeArgCount = ReadI32At(metadata, p); p += 4;
                gc.IsMethod = ReadI32At(metadata, p); p += 4;
                gc.GenericParameterStart = ReadI32At(metadata, p);
                result[i] = gc;
            }
            return result;
        }

        public static Il2CppGenericParameter[] ParseGenericParameters(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.GenericParametersOffset <= 0 || header.GenericParametersSize <= 0)
                return new Il2CppGenericParameter[0];

            const int structSize = 12;
            int count = header.GenericParametersSize / structSize;
            var result = new Il2CppGenericParameter[count];
            int baseOff = header.GenericParametersOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var gp = new Il2CppGenericParameter();
                gp.ContainerIndex = ReadU32At(metadata, p); p += 4;
                gp.NameIndex = ReadU32At(metadata, p); p += 4;
                gp.Num = ReadU16At(metadata, p); p += 2;
                gp.Flags = ReadU16At(metadata, p);
                result[i] = gp;
            }
            return result;
        }

        public static int[] ParseInterfaceIndices(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.InterfacesOffset <= 0 || header.InterfacesSize <= 0)
                return new int[0];

            int count = header.InterfacesSize / 4;
            var result = new int[count];
            int baseOff = header.InterfacesOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * 4;
                if (p + 4 > metadata.Length) break;
                result[i] = ReadI32At(metadata, p);
            }
            return result;
        }

        public static int[] ParseNestedTypes(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.NestedTypesOffset <= 0 || header.NestedTypesSize <= 0)
                return new int[0];

            int count = header.NestedTypesSize / 4;
            var result = new int[count];
            int baseOff = header.NestedTypesOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * 4;
                if (p + 4 > metadata.Length) break;
                result[i] = ReadI32At(metadata, p);
            }
            return result;
        }

        public static Il2CppImageDefinition[] ParseImages(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.ImagesOffset <= 0 || header.ImagesSize <= 0)
                return new Il2CppImageDefinition[0];

            const int structSize = 40;
            int count = header.ImagesSize / structSize;
            var result = new Il2CppImageDefinition[count];
            int baseOff = header.ImagesOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var img = new Il2CppImageDefinition();
                img.NameIndex = ReadI32At(metadata, p); p += 4;
                img.AssemblyIndex = ReadI32At(metadata, p); p += 4;
                img.TypeStart = ReadI32At(metadata, p); p += 4;
                img.TypeCount = ReadU32At(metadata, p); p += 4;
                img.ExportedTypeStart = ReadI32At(metadata, p); p += 4;
                img.ExportedTypeCount = ReadU32At(metadata, p); p += 4;
                img.EntryPointIndex = ReadI32At(metadata, p); p += 4;
                img.Token = ReadU32At(metadata, p);
                result[i] = img;
            }
            return result;
        }

        public static Il2CppAssemblyDefinition[] ParseAssemblies(byte[] metadata, Il2CppMetadataHeader header)
        {
            if (header.AssembliesOffset <= 0 || header.AssembliesSize <= 0)
                return new Il2CppAssemblyDefinition[0];

            const int structSize = 68;
            int count = header.AssembliesSize / structSize;
            var result = new Il2CppAssemblyDefinition[count];
            int baseOff = header.AssembliesOffset;

            for (int i = 0; i < count; i++)
            {
                int p = baseOff + i * structSize;
                if (p + structSize > metadata.Length) break;

                var asm = new Il2CppAssemblyDefinition();
                asm.ImageIndex = ReadI32At(metadata, p); p += 4;
                asm.Token = ReadU32At(metadata, p); p += 4;
                asm.ReferencedAssemblyStart = ReadI32At(metadata, p); p += 4;
                asm.ReferencedAssemblyCount = ReadI32At(metadata, p); p += 4;
                // Il2CppAssemblyName inline: nameIdx(4), cultureIdx(4), hashIdx(4), pubkeyIdx(4), hashLen(4), hashAlg(4), revision(2), build(2), minor(2), major(2), flags(4)
                asm.NameIndex = ReadI32At(metadata, p); p += 4;
                asm.CultureIndex = ReadI32At(metadata, p); p += 4;
                asm.HashValueIndex = ReadI32At(metadata, p); p += 4;
                asm.PublicKeyIndex = ReadI32At(metadata, p); p += 4;
                p += 8; // hashLen + hashAlg
                asm.Revision = ReadU16At(metadata, p); p += 2;
                asm.Build = ReadU16At(metadata, p); p += 2;
                asm.Minor = ReadU16At(metadata, p); p += 2;
                asm.Major = ReadU16At(metadata, p); p += 2;
                asm.Flags = ReadU32At(metadata, p);
                result[i] = asm;
            }
            return result;
        }

        // ---------- Full metadata parse ----------

        public static Il2CppMetadataSnapshot ParseFullMetadata(byte[] metadata)
        {
            if (!ValidateMagic(metadata))
                return null;

            int version = BitConverter.ToInt32(metadata, 4);
            var header = ParseMetadataHeader(metadata, version);

            var snapshot = new Il2CppMetadataSnapshot
            {
                Version = version,
                Header = header,
                RawMetadata = metadata,
                TypeDefinitions = ParseTypeDefinitions(metadata, header, version),
                Methods = ParseMethods(metadata, header),
                Fields = ParseFields(metadata, header),
                Parameters = ParseParameters(metadata, header),
                Properties = ParseProperties(metadata, header),
                Events = ParseEvents(metadata, header),
                GenericContainers = ParseGenericContainers(metadata, header),
                GenericParameters = ParseGenericParameters(metadata, header),
                InterfaceIndices = ParseInterfaceIndices(metadata, header),
                NestedTypeIndices = ParseNestedTypes(metadata, header),
                Images = ParseImages(metadata, header),
                Assemblies = ParseAssemblies(metadata, header)
            };

            return snapshot;
        }

        // ---------- Encrypted / Obfuscated metadata recovery ----------

        public enum MetadataFindMethod
        {
            PlainMagic,
            XorDecrypted,
            GlobalMetadataPointer,
            DecoyDetected
        }

        public class MetadataFindResult
        {
            public byte[] Metadata;
            public ulong Address;
            public MetadataFindMethod Method;
            public byte XorKey;
            public string Details;
        }

        public static byte[] TryXorDecryptMagic(byte[] regionData, int offset, out byte xorKey)
        {
            xorKey = 0;
            byte[] magicBytes = { 0xAF, 0x1B, 0xB1, 0xFA };

            for (byte key = 1; key != 0; key++)
            {
                bool match = true;
                for (int j = 0; j < 4; j++)
                {
                    if ((byte)(regionData[offset + j] ^ key) != magicBytes[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    int versionByte0 = regionData[offset + 4] ^ key;
                    int versionByte1 = regionData[offset + 5] ^ key;
                    int version = versionByte0 | (versionByte1 << 8);
                    if (version >= 16 && version <= 40)
                    {
                        xorKey = key;
                        return XorDecryptRegion(regionData, offset, key);
                    }
                }
            }
            return null;
        }

        private static byte[] XorDecryptRegion(byte[] data, int offset, byte key)
        {
            int remaining = data.Length - offset;
            int size = Math.Min(remaining, 0x2000000);
            byte[] decrypted = new byte[size];
            for (int i = 0; i < size; i++)
                decrypted[i] = (byte)(data[offset + i] ^ key);
            return decrypted;
        }

        public static bool ValidateMetadataStructure(byte[] metadata)
        {
            if (metadata == null || metadata.Length < 280)
                return false;

            uint magic = BitConverter.ToUInt32(metadata, 0);
            if (magic != IL2CPP_METADATA_MAGIC)
                return false;

            int version = BitConverter.ToInt32(metadata, 4);
            if (version < 16 || version > 40)
                return false;

            int p = 8;
            int validSections = 0;
            int totalSections = version >= 24 ? 30 : 28;
            int lastEnd = 0;

            for (int i = 0; i < totalSections && p + 8 <= metadata.Length; i++)
            {
                int secOff = BitConverter.ToInt32(metadata, p);
                int secSize = BitConverter.ToInt32(metadata, p + 4);
                p += 8;

                if (secOff > 0 && secSize > 0 && secOff < metadata.Length)
                {
                    validSections++;
                    int end = secOff + secSize;
                    if (end > lastEnd) lastEnd = end;
                }
            }

            if (validSections < 8)
                return false;

            // The key struct size validation from the article:
            // TypeDefinitions / 0x5C (92), Methods / 0x20 (32), Images / 0x28 (40), Assemblies / 0x44 (68)
            var header = ParseMetadataHeader(metadata, version);
            if (header.TypeDefinitionsSize > 0 && header.TypeDefinitionsSize % GetTypeDefSize(version) != 0)
                return false;

            return true;
        }

        public static bool IsDecoyMetadata(byte[] fileData)
        {
            if (fileData == null || fileData.Length < 16)
                return true;

            uint magic = BitConverter.ToUInt32(fileData, 0);
            if (magic != IL2CPP_METADATA_MAGIC)
            {
                int printableCount = 0;
                int checkSize = Math.Min(fileData.Length, 256);
                for (int i = 0; i < checkSize; i++)
                {
                    byte b = fileData[i];
                    if ((b >= 0x20 && b <= 0x7E) || b == 0x0A || b == 0x0D || b == 0x09)
                        printableCount++;
                }
                if (printableCount > checkSize * 0.8)
                    return true;
            }
            else
            {
                if (!ValidateMetadataStructure(fileData))
                    return true;
            }

            return false;
        }

        public static int EstimateMetadataSizeFromHeader(byte[] metadata)
        {
            if (metadata == null || metadata.Length < 280)
                return 0;

            int version = BitConverter.ToInt32(metadata, 4);
            int p = 8;
            int maxEnd = 0;
            int sectionCount = version >= 31 ? 32 : version >= 24 ? 30 : 28;

            for (int i = 0; i < sectionCount && p + 8 <= metadata.Length; i++)
            {
                int secOff = BitConverter.ToInt32(metadata, p);
                int secSize = BitConverter.ToInt32(metadata, p + 4);
                p += 8;

                if (secOff > 0 && secSize > 0)
                {
                    int end = secOff + secSize;
                    if (end > maxEnd) maxEnd = end;
                }
            }

            return maxEnd > 0 ? maxEnd : 0;
        }

        // ---------- Helpers ----------

        private static int ReadI32(byte[] data, ref int pos)
        {
            if (pos + 4 > data.Length) { pos += 4; return 0; }
            int val = BitConverter.ToInt32(data, pos);
            pos += 4;
            return val;
        }

        private static int ReadI32At(byte[] data, int pos)
        {
            if (pos + 4 > data.Length) return 0;
            return BitConverter.ToInt32(data, pos);
        }

        private static uint ReadU32At(byte[] data, int pos)
        {
            if (pos + 4 > data.Length) return 0;
            return BitConverter.ToUInt32(data, pos);
        }

        private static ushort ReadU16At(byte[] data, int pos)
        {
            if (pos + 2 > data.Length) return 0;
            return BitConverter.ToUInt16(data, pos);
        }
    }
}
