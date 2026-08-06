using System;
using System.Collections.Generic;
using System.IO;
using System.Xml.Linq;

namespace KsDumperClient.ReClass
{
    /// <summary>
    /// Save/load ReClass structure definitions as XML.
    /// </summary>
    public static class StructureDefinition
    {
        public static void Save(MemoryNode root, string filePath)
        {
            var doc = new XDocument(
                new XDeclaration("1.0", "utf-8", null),
                new XElement("Structure",
                    new XAttribute("version", "1"),
                    SerializeNode(root)
                )
            );
            doc.Save(filePath);
        }

        public static MemoryNode Load(string filePath)
        {
            var doc = XDocument.Load(filePath);
            var rootElement = doc.Root?.Element("Node");
            if (rootElement == null) return null;
            return DeserializeNode(rootElement);
        }

        private static XElement SerializeNode(MemoryNode node)
        {
            var elem = new XElement("Node",
                new XAttribute("type", GetNodeTypeName(node)),
                new XAttribute("name", node.Name ?? ""),
                new XAttribute("offset", node.Offset)
            );

            // Type-specific attributes
            if (node is TextNode text)
            {
                elem.Add(new XAttribute("length", text.Length));
                elem.Add(new XAttribute("unicode", text.IsUnicode));
            }
            else if (node is ArrayNode arr)
            {
                elem.Add(new XAttribute("count", arr.Count));
                elem.Add(new XAttribute("elementType", GetNodeTypeName(arr.ElementPrototype)));
            }

            // Serialize children
            if (node.Children != null)
            {
                foreach (var child in node.Children)
                {
                    elem.Add(SerializeNode(child));
                }
            }

            return elem;
        }

        private static MemoryNode DeserializeNode(XElement elem)
        {
            string typeName = elem.Attribute("type")?.Value ?? "int32";
            string name = elem.Attribute("name")?.Value ?? "";
            int offset = int.Parse(elem.Attribute("offset")?.Value ?? "0");

            MemoryNode node = CreateNodeFromType(typeName);

            if (node is TextNode text)
            {
                text.Length = int.Parse(elem.Attribute("length")?.Value ?? "32");
                text.IsUnicode = bool.Parse(elem.Attribute("unicode")?.Value ?? "false");
            }
            else if (node is ArrayNode arr)
            {
                arr.Count = int.Parse(elem.Attribute("count")?.Value ?? "4");
                string elemType = elem.Attribute("elementType")?.Value ?? "int32";
                arr.ElementPrototype = CreateNodeFromType(elemType);
                arr.RebuildChildren();
            }

            node.Name = name;
            node.Offset = offset;

            // Deserialize children
            foreach (var childElem in elem.Elements("Node"))
            {
                var child = DeserializeNode(childElem);
                child.Parent = node;
                if (node.Children == null)
                    node.Children = new List<MemoryNode>();
                node.Children.Add(child);
            }

            return node;
        }

        public static string GetNodeTypeName(MemoryNode node)
        {
            if (node is Hex8Node) return "hex8";
            if (node is Hex16Node) return "hex16";
            if (node is Hex32Node) return "hex32";
            if (node is Hex64Node) return "hex64";
            if (node is Int8Node) return "int8";
            if (node is UInt8Node) return "uint8";
            if (node is Int16Node) return "int16";
            if (node is UInt16Node) return "uint16";
            if (node is Int32Node) return "int32";
            if (node is UInt32Node) return "uint32";
            if (node is Int64Node) return "int64";
            if (node is UInt64Node) return "uint64";
            if (node is FloatNode) return "float";
            if (node is DoubleNode) return "double";
            if (node is BoolNode) return "bool";
            if (node is PointerNode) return "ptr";
            if (node is TextNode) return "text";
            if (node is ArrayNode) return "array";
            if (node is ClassNode) return "class";
            return "int32";
        }

        public static MemoryNode CreateNodeFromType(string typeName)
        {
            switch (typeName)
            {
                case "hex8": return new Hex8Node();
                case "hex16": return new Hex16Node();
                case "hex32": return new Hex32Node();
                case "hex64": return new Hex64Node();
                case "int8": return new Int8Node();
                case "uint8": return new UInt8Node();
                case "int16": return new Int16Node();
                case "uint16": return new UInt16Node();
                case "int32": return new Int32Node();
                case "uint32": return new UInt32Node();
                case "int64": return new Int64Node();
                case "uint64": return new UInt64Node();
                case "float": return new FloatNode();
                case "double": return new DoubleNode();
                case "bool": return new BoolNode();
                case "ptr": return new PointerNode();
                case "text": return new TextNode();
                case "array": return new ArrayNode();
                case "class": return new ClassNode();
                default: return new Int32Node();
            }
        }

        /// <summary>
        /// All available node type names for menus.
        /// </summary>
        public static readonly string[] AllTypes = new[]
        {
            "hex8", "hex16", "hex32", "hex64",
            "int8", "uint8", "int16", "uint16",
            "int32", "uint32", "int64", "uint64",
            "float", "double", "bool",
            "ptr", "text", "array", "class"
        };
    }
}
