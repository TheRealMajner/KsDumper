using System.Text;

namespace KsDumperClient.DotNet
{
    /// <summary>
    /// Basic C# decompiler — pattern-matches common IL sequences to produce readable pseudocode.
    /// Falls back to IL listing for unrecognized patterns.
    /// </summary>
    public class Decompiler
    {
        private readonly MetadataTableParser metadata;
        private readonly ILDisassembler disassembler;

        public Decompiler(MetadataTableParser metadata, ILDisassembler disassembler)
        {
            this.metadata = metadata;
            this.disassembler = disassembler;
        }

        /// <summary>
        /// Decompile a method to C#-like pseudocode.
        /// </summary>
        public string DecompileMethod(int methodIndex)
        {
            if (metadata?.MethodDefs == null || methodIndex < 0 || methodIndex >= metadata.MethodDefs.Length)
                return "// Method not found";

            var method = metadata.MethodDefs[methodIndex];
            string methodName = metadata.ReadString(method.NameIndex);

            // Build method signature
            string accessMod = GetMethodAccess(method.Flags);
            string callingConv = (method.Flags & 0x0010) != 0 ? "static " : "";
            string isAbstract = (method.Flags & 0x0400) != 0 ? "abstract " : "";

            var sb = new StringBuilder();
            sb.AppendLine($"// Decompiled from IL — basic pseudocode");
            sb.AppendLine($"// IL disassembly follows for reference");
            sb.AppendLine();

            sb.AppendLine($"{accessMod}{callingConv}{isAbstract}void {EscapeName(methodName)}()");
            sb.AppendLine("{");

            // Get IL disassembly for analysis
            string il = disassembler.DisassembleMethod(methodIndex);
            string[] lines = il.Split('\n');

            int localCount = 0;
            bool inCode = false;

            foreach (string rawLine in lines)
            {
                string line = rawLine.Trim();
                if (line.StartsWith("// ") || line.StartsWith("IL_"))
                {
                    if (line.StartsWith("IL_") && !line.Contains(":"))
                    {
                        // Skip non-instruction lines
                        continue;
                    }

                    // Parse IL instruction
                    string instruction = ExtractInstruction(line);
                    if (string.IsNullOrEmpty(instruction))
                    {
                        sb.AppendLine($"    // {line}");
                        continue;
                    }

                    inCode = true;

                    // Pattern matching for common sequences
                    if (instruction.StartsWith("ldstr "))
                    {
                        string str = instruction.Substring(6);
                        sb.AppendLine($"    string s{localCount} = {str};");
                        localCount++;
                    }
                    else if (instruction.StartsWith("ldc.i4"))
                    {
                        string val = ExtractOperand(instruction);
                        sb.AppendLine($"    int i{localCount} = {val};");
                        localCount++;
                    }
                    else if (instruction.StartsWith("ldc.i8"))
                    {
                        string val = ExtractOperand(instruction);
                        sb.AppendLine($"    long l{localCount} = {val};");
                        localCount++;
                    }
                    else if (instruction.StartsWith("ldc.r4"))
                    {
                        string val = ExtractOperand(instruction);
                        sb.AppendLine($"    float f{localCount} = {val};");
                        localCount++;
                    }
                    else if (instruction.StartsWith("ldc.r8"))
                    {
                        string val = ExtractOperand(instruction);
                        sb.AppendLine($"    double d{localCount} = {val};");
                        localCount++;
                    }
                    else if (instruction == "add")
                    {
                        sb.AppendLine("    // ... + ...");
                    }
                    else if (instruction == "sub")
                    {
                        sb.AppendLine("    // ... - ...");
                    }
                    else if (instruction == "mul")
                    {
                        sb.AppendLine("    // ... * ...");
                    }
                    else if (instruction == "div")
                    {
                        sb.AppendLine("    // ... / ...");
                    }
                    else if (instruction == "ret")
                    {
                        sb.AppendLine("    return;");
                    }
                    else if (instruction.StartsWith("call ") || instruction.StartsWith("callvirt "))
                    {
                        string target = ExtractOperand(instruction);
                        string callType = instruction.StartsWith("callvirt") ? "virtual " : "";
                        sb.AppendLine($"    {callType}{target};");
                    }
                    else if (instruction.StartsWith("newobj "))
                    {
                        string target = ExtractOperand(instruction);
                        sb.AppendLine($"    new {target};");
                    }
                    else if (instruction.StartsWith("stloc"))
                    {
                        sb.AppendLine("    // store to local");
                    }
                    else if (instruction.StartsWith("ldloc") || instruction.StartsWith("ldarg"))
                    {
                        sb.AppendLine($"    // {instruction}");
                    }
                    else if (instruction.StartsWith("br") || instruction.StartsWith("beq") ||
                             instruction.StartsWith("bne") || instruction.StartsWith("bge") ||
                             instruction.StartsWith("bgt") || instruction.StartsWith("ble") ||
                             instruction.StartsWith("blt"))
                    {
                        string target = ExtractOperand(instruction);
                        sb.AppendLine($"    if (...) goto {target};");
                    }
                    else if (instruction.StartsWith("ldfld ") || instruction.StartsWith("ldsfld "))
                    {
                        string field = ExtractOperand(instruction);
                        sb.AppendLine($"    // load field: {field}");
                    }
                    else if (instruction.StartsWith("stfld ") || instruction.StartsWith("stsfld "))
                    {
                        string field = ExtractOperand(instruction);
                        sb.AppendLine($"    // store field: {field}");
                    }
                    else if (instruction == "nop")
                    {
                        // Skip
                    }
                    else if (instruction == "throw")
                    {
                        sb.AppendLine("    throw;");
                    }
                    else if (instruction == "pop")
                    {
                        sb.AppendLine("    // pop");
                    }
                    else if (instruction == "dup")
                    {
                        sb.AppendLine("    // dup");
                    }
                    else
                    {
                        sb.AppendLine($"    // {instruction}");
                    }
                }
                else if (inCode && !string.IsNullOrEmpty(line))
                {
                    sb.AppendLine($"    // {line}");
                }
            }

            sb.AppendLine("}");
            return sb.ToString();
        }

        private string ExtractInstruction(string line)
        {
            // Extract instruction from "IL_XXXX: instruction operand" format
            int colonIdx = line.IndexOf(':');
            if (colonIdx < 0) return line.Trim();

            string after = line.Substring(colonIdx + 1).Trim();
            return after;
        }

        private string ExtractOperand(string instruction)
        {
            int spaceIdx = instruction.IndexOf(' ');
            if (spaceIdx < 0) return "";
            return instruction.Substring(spaceIdx + 1).Trim();
        }

        private string GetMethodAccess(ushort flags)
        {
            uint access = (uint)(flags & 0x0007);
            switch (access)
            {
                case 0x01: return "private ";
                case 0x02: return "private ";
                case 0x03: return "internal ";
                case 0x04: return "protected ";
                case 0x05: return "protected internal ";
                case 0x06: return "public ";
                default: return "public ";
            }
        }

        private string EscapeName(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_unnamed";
            var sb = new StringBuilder(name.Length);
            foreach (char c in name)
            {
                if (char.IsLetterOrDigit(c) || c == '_')
                    sb.Append(c);
                else
                    sb.Append('_');
            }
            return sb.ToString();
        }
    }
}
