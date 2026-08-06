using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using ModelContextProtocol.Server;
using KsDumperClient;
using KsDumperClient.Driver;
using KsDumperClient.Utility;

namespace KsMcpServer.Tools
{
    [McpServerToolType]
    public class Il2CppTools
    {
        private readonly IMemoryReader _driver;

        public Il2CppTools(IMemoryReader driver)
        {
            _driver = driver;
        }

        [McpServerTool, Description("Reads IL2CPP metadata from a Unity IL2CPP process. Handles encrypted/obfuscated metadata automatically (XOR encryption, decoy files, s_GlobalMetadataHeader pointer scanning). Returns type definitions, methods, and fields.")]
        public string DumpIl2CppMetadata(int pid, int maxTypes = 200)
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null || metadata.Length == 0)
                    return $"Failed to read IL2CPP metadata from PID {pid}. The scanner tried:\n" +
                           $"  1. Plain magic scan (0xFAB11BAF in all committed regions)\n" +
                           $"  2. XOR decryption (common keys + brute-force all 255 keys)\n" +
                           $"  3. s_GlobalMetadataHeader pointer scan in GameAssembly.dll\n" +
                           $"Is this a Unity IL2CPP process? Check if GameAssembly.dll is loaded.";

                if (!Il2CppDumper.ValidateMetadataStructure(metadata))
                    return $"Found metadata-like data at 0x{address:X16} but structure validation failed. " +
                           $"This may use a non-standard obfuscation scheme (header field rearrangement, custom encryption).";

                uint magic = BitConverter.ToUInt32(metadata, 0);
                int version = BitConverter.ToInt32(metadata, 4);
                int stringTableSize = BitConverter.ToInt32(metadata, 8);
                int stringTableOffset = BitConverter.ToInt32(metadata, 12);

                var sb = new StringBuilder();
                sb.AppendLine($"IL2CPP Metadata found at 0x{address:X16}");
                sb.AppendLine($"  Magic: 0x{magic:X8}");
                sb.AppendLine($"  Version: {version}");
                sb.AppendLine($"  String table size: {stringTableSize:N0} bytes");
                sb.AppendLine($"  Metadata size: {metadata.Length:N0} bytes");
                sb.AppendLine();

                int typeDefOffset, typeDefSize;
                GetTypeDefTableInfo(metadata, version, out typeDefOffset, out typeDefSize);

                if (typeDefOffset <= 0 || typeDefSize <= 0 || typeDefOffset >= metadata.Length)
                {
                    sb.AppendLine("Could not locate TypeDefinition table.");
                    return sb.ToString();
                }

                int typeDefStructSize = GetTypeDefStructSize(version);
                if (typeDefStructSize <= 0)
                {
                    sb.AppendLine($"Unsupported IL2CPP version {version} for type parsing.");
                    return sb.ToString();
                }

                int typeCount = typeDefSize / typeDefStructSize;
                sb.AppendLine($"Type definitions: {typeCount}");
                sb.AppendLine();

                int shown = Math.Min(typeCount, maxTypes);
                sb.AppendLine($"{"Token",-12} {"Namespace",-30} {"Name",-35} {"Methods",-8} {"Fields"}");
                sb.AppendLine(new string('-', 100));

                for (int i = 0; i < shown; i++)
                {
                    int baseOff = typeDefOffset + i * typeDefStructSize;
                    if (baseOff + typeDefStructSize > metadata.Length) break;

                    int nameIdx = BitConverter.ToInt32(metadata, baseOff);
                    int nsIdx = BitConverter.ToInt32(metadata, baseOff + 4);
                    uint token = BitConverter.ToUInt32(metadata, baseOff + 24);
                    short methodCount = BitConverter.ToInt16(metadata, baseOff + 36);
                    short fieldCount = BitConverter.ToInt16(metadata, baseOff + 40);

                    string name = ReadString(metadata, stringTableOffset, stringTableSize, nameIdx);
                    string ns = ReadString(metadata, stringTableOffset, stringTableSize, nsIdx);

                    sb.AppendLine($"0x{token:X8}    {Truncate(ns, 29),-30} {Truncate(name, 34),-35} {methodCount,-8} {fieldCount}");
                }

                if (typeCount > shown)
                    sb.AppendLine($"... ({typeCount - shown} more types, use maxTypes parameter to see more)");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"IL2CPP metadata dump failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Saves IL2CPP metadata dump to a file. Includes all types, methods, and fields with their names.")]
        public string SaveIl2CppDump(int pid, string outputPath = "")
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null || metadata.Length == 0)
                    return $"Failed to read IL2CPP metadata from PID {pid}.";

                if (!_driver.GetProcessSummaryList(out ProcessSummary[] processes))
                    return "Failed to enumerate processes.";

                var proc = processes.FirstOrDefault(p => p.ProcessId == pid);
                string procName = proc?.ProcessName ?? $"pid_{pid}";

                if (string.IsNullOrEmpty(outputPath))
                    outputPath = Path.Combine(Path.GetTempPath(), $"{procName}_il2cpp_dump.txt");

                int sanity = BitConverter.ToInt32(metadata, 0);
                int version = BitConverter.ToInt32(metadata, 4);
                int stringTableSize = BitConverter.ToInt32(metadata, 8);
                int stringTableOffset = BitConverter.ToInt32(metadata, 12);

                int typeDefOffset, typeDefSize;
                GetTypeDefTableInfo(metadata, version, out typeDefOffset, out typeDefSize);

                int typeDefStructSize = GetTypeDefStructSize(version);
                if (typeDefOffset <= 0 || typeDefStructSize <= 0)
                    return "Could not parse type definitions from metadata.";

                int typeCount = typeDefSize / typeDefStructSize;

                int methodDefOffset, methodDefSize;
                GetMethodDefTableInfo(metadata, version, out methodDefOffset, out methodDefSize);
                int methodStructSize = GetMethodDefStructSize(version);

                int fieldDefOffset, fieldDefSize;
                GetFieldDefTableInfo(metadata, version, out fieldDefOffset, out fieldDefSize);
                int fieldStructSize = 8;

                var sb = new StringBuilder();
                sb.AppendLine($"// IL2CPP Metadata Dump");
                sb.AppendLine($"// Process: {procName} (PID {pid})");
                sb.AppendLine($"// Metadata address: 0x{address:X16}");
                sb.AppendLine($"// Version: {version}");
                sb.AppendLine($"// Types: {typeCount}");
                sb.AppendLine();

                for (int i = 0; i < typeCount; i++)
                {
                    int baseOff = typeDefOffset + i * typeDefStructSize;
                    if (baseOff + typeDefStructSize > metadata.Length) break;

                    int nameIdx = BitConverter.ToInt32(metadata, baseOff);
                    int nsIdx = BitConverter.ToInt32(metadata, baseOff + 4);
                    uint token = BitConverter.ToUInt32(metadata, baseOff + 24);
                    int methodStart = BitConverter.ToInt32(metadata, baseOff + 32);
                    short methodCount = BitConverter.ToInt16(metadata, baseOff + 36);
                    int fieldStart = BitConverter.ToInt32(metadata, baseOff + 38);
                    short fieldCount = BitConverter.ToInt16(metadata, baseOff + 40);

                    string name = ReadString(metadata, stringTableOffset, stringTableSize, nameIdx);
                    string ns = ReadString(metadata, stringTableOffset, stringTableSize, nsIdx);

                    string fullName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
                    sb.AppendLine($"// Token: 0x{token:X8}");
                    sb.AppendLine($"public class {fullName}");
                    sb.AppendLine("{");

                    if (fieldCount > 0 && fieldDefOffset > 0 && fieldStructSize > 0)
                    {
                        for (int f = 0; f < fieldCount; f++)
                        {
                            int fOff = fieldDefOffset + (fieldStart + f) * fieldStructSize;
                            if (fOff + fieldStructSize > metadata.Length) break;
                            int fNameIdx = BitConverter.ToInt32(metadata, fOff);
                            string fName = ReadString(metadata, stringTableOffset, stringTableSize, fNameIdx);
                            sb.AppendLine($"    public object {fName}; // field");
                        }
                    }

                    if (methodCount > 0 && methodDefOffset > 0 && methodStructSize > 0)
                    {
                        for (int m = 0; m < methodCount; m++)
                        {
                            int mOff = methodDefOffset + (methodStart + m) * methodStructSize;
                            if (mOff + methodStructSize > metadata.Length) break;
                            int mNameIdx = BitConverter.ToInt32(metadata, mOff);
                            uint mToken = BitConverter.ToUInt32(metadata, mOff + 4);
                            string mName = ReadString(metadata, stringTableOffset, stringTableSize, mNameIdx);
                            sb.AppendLine($"    public void {mName}(); // 0x{mToken:X8}");
                        }
                    }

                    sb.AppendLine("}");
                    sb.AppendLine();
                }

                File.WriteAllText(outputPath, sb.ToString(), Encoding.UTF8);
                return $"IL2CPP dump saved.\nFile: {outputPath}\nTypes: {typeCount}\nSize: {sb.Length:N0} chars";
            }
            catch (Exception ex)
            {
                return $"IL2CPP dump save failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Detects if a Unity IL2CPP game uses Beebyte obfuscation by checking for garbled type names in metadata.")]
        public string DetectBeebyte(int pid)
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null || metadata.Length == 0)
                    return $"Failed to read IL2CPP metadata from PID {pid}. Not a Unity IL2CPP process?";

                int version = BitConverter.ToInt32(metadata, 4);
                int stringTableSize = BitConverter.ToInt32(metadata, 8);
                int stringTableOffset = BitConverter.ToInt32(metadata, 12);

                int typeDefOffset, typeDefSize;
                GetTypeDefTableInfo(metadata, version, out typeDefOffset, out typeDefSize);
                int typeDefStructSize = GetTypeDefStructSize(version);

                if (typeDefOffset <= 0 || typeDefStructSize <= 0)
                    return "Could not parse metadata to check for obfuscation.";

                int typeCount = typeDefSize / typeDefStructSize;
                int sampleSize = Math.Min(typeCount, 300);
                int obfuscated = 0;

                for (int i = 0; i < sampleSize; i++)
                {
                    int baseOff = typeDefOffset + i * typeDefStructSize;
                    if (baseOff + typeDefStructSize > metadata.Length) break;

                    int nameIdx = BitConverter.ToInt32(metadata, baseOff);
                    string name = ReadString(metadata, stringTableOffset, stringTableSize, nameIdx);

                    if (IsObfuscatedName(name))
                        obfuscated++;
                }

                double ratio = (double)obfuscated / sampleSize;
                bool isBeebyte = ratio > 0.30;

                var sb = new StringBuilder();
                sb.AppendLine($"Beebyte Obfuscation Detection for PID {pid}:");
                sb.AppendLine($"  Sampled {sampleSize} of {typeCount} types");
                sb.AppendLine($"  Obfuscated names: {obfuscated} ({ratio:P1})");
                sb.AppendLine($"  Verdict: {(isBeebyte ? "BEEBYTE OBFUSCATION DETECTED" : "Not obfuscated")}");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"Beebyte detection failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Analyzes IL2CPP protection/obfuscation on a Unity process. Reports: encryption type, obfuscation level, metadata version, and whether common anti-dump techniques are used (XOR, decoy files, stripped exports, VMProtect).")]
        public string AnalyzeIl2CppProtection(int pid)
        {
            try
            {
                var sb = new StringBuilder();
                sb.AppendLine($"IL2CPP Protection Analysis for PID {pid}");
                sb.AppendLine(new string('=', 50));

                // Check if GameAssembly.dll is loaded
                bool hasGameAssembly = false;
                string gameAssemblyName = null;
                if (_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                {
                    foreach (var m in modules)
                    {
                        if (m.ModuleName != null && m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            hasGameAssembly = true;
                            gameAssemblyName = m.ModuleName;
                            sb.AppendLine($"\n[GameAssembly.dll] Found: {m.ModuleName}");
                            sb.AppendLine($"  Base: 0x{m.BaseAddress:X16}");
                            sb.AppendLine($"  Size: 0x{m.ImageSize:X}");

                            // Check exports for obfuscation (ROT-5, stripped names)
                            var exports = _driver.GetExportMap(pid);
                            if (exports != null && exports.Count > 0)
                            {
                                int il2cppExports = 0;
                                int obfuscatedExports = 0;
                                foreach (var kv in exports)
                                {
                                    string funcName = kv.Value.funcName ?? "";
                                    if (funcName.StartsWith("il2cpp_", StringComparison.Ordinal)) il2cppExports++;
                                    else if (IsObfuscatedName(funcName)) obfuscatedExports++;
                                }
                                sb.AppendLine($"  Exports: {exports.Count} total, {il2cppExports} il2cpp_*, {obfuscatedExports} obfuscated");
                                if (obfuscatedExports > il2cppExports && il2cppExports < 5)
                                    sb.AppendLine("  WARNING: Export names appear obfuscated (possible ROT-5 or stripped)");
                            }
                            else
                            {
                                sb.AppendLine("  Exports: none found (may be stripped or packed)");
                            }
                            break;
                        }
                    }
                }

                if (!hasGameAssembly)
                {
                    sb.AppendLine("\n[GameAssembly.dll] NOT FOUND — this may not be an IL2CPP game");
                    return sb.ToString();
                }

                // Try reading metadata
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                {
                    sb.AppendLine("\n[Metadata] NOT FOUND by any scanner");
                    sb.AppendLine("  Possible reasons:");
                    sb.AppendLine("  - Heavy custom encryption (not simple XOR)");
                    sb.AppendLine("  - Metadata not yet loaded (game still initializing)");
                    sb.AppendLine("  - Custom MetadataLoader that decrypts on-the-fly");
                    sb.AppendLine("  - VMProtect or similar code virtualization");
                    return sb.ToString();
                }

                sb.AppendLine($"\n[Metadata] Found at 0x{address:X16}");
                uint magic = BitConverter.ToUInt32(metadata, 0);
                int version = BitConverter.ToInt32(metadata, 4);
                sb.AppendLine($"  Magic: 0x{magic:X8} {(magic == 0xFAB11BAF ? "(valid)" : "(INVALID)")}");
                sb.AppendLine($"  Version: {version}");
                sb.AppendLine($"  Size: {metadata.Length:N0} bytes");
                sb.AppendLine($"  Structure valid: {Il2CppDumper.ValidateMetadataStructure(metadata)}");

                int estimatedSize = Il2CppDumper.EstimateMetadataSizeFromHeader(metadata);
                sb.AppendLine($"  Estimated size from header: {estimatedSize:N0} bytes");
                if (estimatedSize > 0 && Math.Abs(estimatedSize - metadata.Length) > 1024)
                    sb.AppendLine($"  WARNING: Size mismatch — may be truncated or padded");

                // Check for Beebyte obfuscation
                int typeDefOffset, typeDefSize;
                GetTypeDefTableInfo(metadata, version, out typeDefOffset, out typeDefSize);
                int typeDefStructSize = GetTypeDefStructSize(version);

                if (typeDefOffset > 0 && typeDefStructSize > 0)
                {
                    int stringTableSize = BitConverter.ToInt32(metadata, 8);
                    int stringTableOffset = BitConverter.ToInt32(metadata, 12);
                    int typeCount = typeDefSize / typeDefStructSize;
                    int sampleSize = Math.Min(typeCount, 300);
                    int obfuscated = 0;

                    for (int i = 0; i < sampleSize; i++)
                    {
                        int baseOff = typeDefOffset + i * typeDefStructSize;
                        if (baseOff + typeDefStructSize > metadata.Length) break;
                        int nameIdx = BitConverter.ToInt32(metadata, baseOff);
                        string name = ReadString(metadata, stringTableOffset, stringTableSize, nameIdx);
                        if (IsObfuscatedName(name)) obfuscated++;
                    }

                    double ratio = (double)obfuscated / sampleSize;
                    sb.AppendLine($"\n[Name Obfuscation]");
                    sb.AppendLine($"  Types: {typeCount}");
                    sb.AppendLine($"  Sampled: {sampleSize}");
                    sb.AppendLine($"  Obfuscated names: {obfuscated} ({ratio:P1})");
                    if (ratio > 0.30)
                        sb.AppendLine("  VERDICT: Beebyte/name obfuscation DETECTED");
                    else
                        sb.AppendLine("  VERDICT: Names appear clean");
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"Protection analysis failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Saves raw IL2CPP metadata binary to a file. Useful for offline analysis with tools like Il2CppDumper or Il2CppInspector.")]
        public string SaveRawMetadata(int pid, string outputPath = "")
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null || metadata.Length == 0)
                    return $"Failed to read IL2CPP metadata from PID {pid}.";

                if (string.IsNullOrEmpty(outputPath))
                {
                    if (!_driver.GetProcessSummaryList(out ProcessSummary[] processes))
                        return "Failed to enumerate processes.";
                    var proc = processes.FirstOrDefault(p => p.ProcessId == pid);
                    string procName = proc?.ProcessName ?? $"pid_{pid}";
                    outputPath = Path.Combine(Path.GetTempPath(), $"{procName}_global-metadata.dat");
                }

                File.WriteAllBytes(outputPath, metadata);
                int version = BitConverter.ToInt32(metadata, 4);
                return $"Raw metadata saved.\n  File: {outputPath}\n  Size: {metadata.Length:N0} bytes\n  Version: {version}\n  Address: 0x{address:X16}";
            }
            catch (Exception ex)
            {
                return $"SaveRawMetadata failed: {ex.Message}";
            }
        }

        private static bool IsObfuscatedName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length < 2) return true;
            if (name.StartsWith("<") || name.StartsWith("__")) return false;

            int consonants = 0;
            int nonAscii = 0;
            foreach (char c in name)
            {
                if (c > 127) nonAscii++;
                if ("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ".IndexOf(c) >= 0)
                    consonants++;
            }
            if (nonAscii > name.Length / 2) return true;
            if (name.Length <= 4 && consonants == name.Length) return true;
            if (name.Length > 3 && consonants > name.Length * 0.85) return true;
            return false;
        }

        private static string ReadString(byte[] metadata, int tableOffset, int tableSize, int index)
        {
            if (index < 0 || index >= tableSize) return "";
            int start = tableOffset + index;
            if (start >= metadata.Length) return "";
            int end = start;
            while (end < metadata.Length && end < tableOffset + tableSize && metadata[end] != 0) end++;
            if (end <= start) return "";
            return Encoding.UTF8.GetString(metadata, start, end - start);
        }

        private static void GetTypeDefTableInfo(byte[] metadata, int version, out int offset, out int size)
        {
            offset = 0; size = 0;
            if (version >= 27)
            {
                if (metadata.Length > 0xB0 + 8)
                {
                    offset = BitConverter.ToInt32(metadata, 0xA8);
                    size = BitConverter.ToInt32(metadata, 0xAC);
                }
            }
            else if (version >= 24)
            {
                if (metadata.Length > 0xA0 + 8)
                {
                    offset = BitConverter.ToInt32(metadata, 0x98);
                    size = BitConverter.ToInt32(metadata, 0x9C);
                }
            }
        }

        private static void GetMethodDefTableInfo(byte[] metadata, int version, out int offset, out int size)
        {
            offset = 0; size = 0;
            if (version >= 27)
            {
                if (metadata.Length > 0x90 + 8)
                {
                    offset = BitConverter.ToInt32(metadata, 0x88);
                    size = BitConverter.ToInt32(metadata, 0x8C);
                }
            }
            else if (version >= 24)
            {
                if (metadata.Length > 0x80 + 8)
                {
                    offset = BitConverter.ToInt32(metadata, 0x78);
                    size = BitConverter.ToInt32(metadata, 0x7C);
                }
            }
        }

        private static void GetFieldDefTableInfo(byte[] metadata, int version, out int offset, out int size)
        {
            offset = 0; size = 0;
            if (version >= 27)
            {
                if (metadata.Length > 0x98 + 8)
                {
                    offset = BitConverter.ToInt32(metadata, 0x90);
                    size = BitConverter.ToInt32(metadata, 0x94);
                }
            }
            else if (version >= 24)
            {
                if (metadata.Length > 0x88 + 8)
                {
                    offset = BitConverter.ToInt32(metadata, 0x80);
                    size = BitConverter.ToInt32(metadata, 0x84);
                }
            }
        }

        private static int GetTypeDefStructSize(int version)
        {
            if (version >= 27) return 92;
            if (version >= 24) return 88;
            return 0;
        }

        private static int GetMethodDefStructSize(int version)
        {
            if (version >= 27) return 28;
            if (version >= 24) return 24;
            return 0;
        }

        [McpServerTool, Description("Resolves runtime field offsets from live Il2CppClass instances in GameAssembly.dll. Returns actual memory offsets for struct/class fields usable in ReClass, IDA, or memory hacking. Much more useful than the metadata-only SDK which shows all offsets as -1.")]
        public string ResolveFieldOffsets(int pid, int maxResults = 200)
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return $"Failed to read IL2CPP metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to enumerate modules.";

                var ga = modules.FirstOrDefault(m => m.ModuleName != null &&
                    m.ModuleName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found.";

                var resolver = new Il2CppRuntimeResolver(_driver, pid);
                var log = new List<string>();
                var offsets = resolver.ResolveFieldOffsets(ga.BaseAddress, ga.ImageSize, snapshot,
                    msg => log.Add(msg));

                var sb = new StringBuilder();
                sb.AppendLine($"Field Offset Resolution for PID {pid}");
                sb.AppendLine(new string('=', 50));
                foreach (var l in log) sb.AppendLine($"  {l}");
                sb.AppendLine();

                int shown = 0;
                int stringOff = snapshot.Header.StringOffset;
                int stringSize = snapshot.Header.StringSize;

                foreach (var fo in offsets)
                {
                    if (shown >= maxResults) break;
                    if (fo.IsStatic) continue;

                    string typeName = "";
                    if (fo.TypeIndex >= 0 && fo.TypeIndex < snapshot.TypeDefinitions.Length)
                        typeName = Il2CppDumper.ReadStringFromTable(metadata, stringOff, stringSize,
                            snapshot.TypeDefinitions[fo.TypeIndex].NameIndex);

                    string fieldName = "";
                    if (fo.FieldIndex >= 0 && fo.FieldIndex < snapshot.Fields.Length)
                        fieldName = Il2CppDumper.ReadStringFromTable(metadata, stringOff, stringSize,
                            (int)snapshot.Fields[fo.FieldIndex].NameIndex);

                    sb.AppendLine($"  {typeName}.{fieldName} → 0x{fo.Offset:X}");
                    shown++;
                }

                if (offsets.Count > maxResults)
                    sb.AppendLine($"  ... ({offsets.Count - maxResults} more, increase maxResults)");

                sb.AppendLine();
                sb.AppendLine($"Total: {offsets.Count} field offsets resolved");
                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"ResolveFieldOffsets failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Resolves method pointers from CodeRegistration in GameAssembly.dll. Maps each IL2CPP method to its actual compiled address/RVA for labeling in IDA/Ghidra.")]
        public string ResolveMethodPointers(int pid, int maxResults = 200)
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return $"Failed to read IL2CPP metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to enumerate modules.";

                var ga = modules.FirstOrDefault(m => m.ModuleName != null &&
                    m.ModuleName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found.";

                var resolver = new Il2CppRuntimeResolver(_driver, pid);
                var log = new List<string>();
                var pointers = resolver.ResolveMethodPointers(ga.BaseAddress, ga.ImageSize, snapshot,
                    msg => log.Add(msg));

                var sb = new StringBuilder();
                sb.AppendLine($"Method Pointer Resolution for PID {pid}");
                sb.AppendLine(new string('=', 50));
                foreach (var l in log) sb.AppendLine($"  {l}");
                sb.AppendLine();

                int shown = 0;
                int stringOff = snapshot.Header.StringOffset;
                int stringSize = snapshot.Header.StringSize;

                foreach (var mp in pointers)
                {
                    if (shown >= maxResults) break;
                    string methodName = "";
                    if (mp.MethodIndex >= 0 && mp.MethodIndex < snapshot.Methods.Length)
                        methodName = Il2CppDumper.ReadStringFromTable(metadata, stringOff, stringSize,
                            (int)snapshot.Methods[mp.MethodIndex].NameIndex);

                    sb.AppendLine($"  [{mp.MethodIndex}] {methodName} → 0x{mp.Address:X} (RVA: 0x{mp.Rva:X})");
                    shown++;
                }

                if (pointers.Count > maxResults)
                    sb.AppendLine($"  ... ({pointers.Count - maxResults} more)");

                sb.AppendLine();
                sb.AppendLine($"Total: {pointers.Count} method pointers resolved");
                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"ResolveMethodPointers failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Extracts all string literals from IL2CPP metadata. These are the original C# string constants from the game code — searchable for game logic keywords, config keys, error messages, URLs, etc.")]
        public string DumpStringLiterals(int pid, string search = "", int maxResults = 500)
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return $"Failed to read IL2CPP metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var literals = Il2CppRuntimeResolver.ExtractStringLiterals(snapshot);

                var sb = new StringBuilder();
                sb.AppendLine($"IL2CPP String Literals for PID {pid}");
                sb.AppendLine($"Total: {literals.Count}");
                sb.AppendLine(new string('=', 50));
                sb.AppendLine();

                int shown = 0;
                foreach (var lit in literals)
                {
                    if (shown >= maxResults) break;

                    if (!string.IsNullOrEmpty(search) &&
                        lit.Value.IndexOf(search, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;

                    string display = lit.Value.Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t");
                    if (display.Length > 120) display = display.Substring(0, 120) + "...";

                    sb.AppendLine($"  [{lit.Index}] \"{display}\"");
                    shown++;
                }

                if (!string.IsNullOrEmpty(search))
                    sb.AppendLine($"\n(filtered by \"{search}\", showing {shown} results)");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"DumpStringLiterals failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Extracts enum values from IL2CPP metadata. Returns all enum types with their field names and integer values.")]
        public string DumpEnumValues(int pid, string search = "", int maxResults = 500)
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return $"Failed to read IL2CPP metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var enumValues = Il2CppRuntimeResolver.ExtractEnumValues(snapshot);

                int stringOff = snapshot.Header.StringOffset;
                int stringSize = snapshot.Header.StringSize;

                // Group by type
                var byType = new Dictionary<int, List<Il2CppRuntimeResolver.EnumValue>>();
                foreach (var ev in enumValues)
                {
                    if (!byType.TryGetValue(ev.TypeIndex, out var list))
                    {
                        list = new List<Il2CppRuntimeResolver.EnumValue>();
                        byType[ev.TypeIndex] = list;
                    }
                    list.Add(ev);
                }

                var sb = new StringBuilder();
                sb.AppendLine($"IL2CPP Enum Values for PID {pid}");
                sb.AppendLine($"Total enum types: {byType.Count}, Total values: {enumValues.Count}");
                sb.AppendLine(new string('=', 50));
                sb.AppendLine();

                int shown = 0;
                foreach (var kv in byType)
                {
                    if (shown >= maxResults) break;

                    string typeName = "";
                    if (kv.Key >= 0 && kv.Key < snapshot.TypeDefinitions.Length)
                    {
                        string name = Il2CppDumper.ReadStringFromTable(metadata, stringOff, stringSize,
                            snapshot.TypeDefinitions[kv.Key].NameIndex);
                        string ns = Il2CppDumper.ReadStringFromTable(metadata, stringOff, stringSize,
                            snapshot.TypeDefinitions[kv.Key].NamespaceIndex);
                        typeName = string.IsNullOrEmpty(ns) ? name : $"{ns}.{name}";
                    }

                    if (!string.IsNullOrEmpty(search) &&
                        typeName.IndexOf(search, StringComparison.OrdinalIgnoreCase) < 0)
                        continue;

                    sb.AppendLine($"  enum {typeName}");
                    sb.AppendLine("  {");
                    foreach (var ev in kv.Value)
                        sb.AppendLine($"      {ev.Name} = {ev.Value},");
                    sb.AppendLine("  }");
                    sb.AppendLine();
                    shown++;
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"DumpEnumValues failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Generates enhanced IL2CPP SDK with runtime-resolved field offsets, method RVAs, enum values, and string literals. Also generates Ghidra and IDA scripts. Saves all files to the specified output directory.")]
        public string GenerateEnhancedSdk(int pid, string outputDir = "")
        {
            try
            {
                var (metadata, address) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return $"Failed to read IL2CPP metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null || snapshot.TypeDefinitions.Length == 0)
                    return "Failed to parse metadata or no types found.";

                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to enumerate modules.";

                var ga = modules.FirstOrDefault(m => m.ModuleName != null &&
                    m.ModuleName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));

                if (string.IsNullOrEmpty(outputDir))
                {
                    if (!_driver.GetProcessSummaryList(out ProcessSummary[] procs))
                        return "Failed to enumerate processes.";
                    var proc = procs.FirstOrDefault(p => p.ProcessId == pid);
                    string procName = proc?.ProcessName ?? $"pid_{pid}";
                    outputDir = Path.Combine(Path.GetTempPath(), $"{procName}_il2cpp_sdk");
                }

                Directory.CreateDirectory(outputDir);
                var log = new List<string>();
                var classInfo = Il2CppSdkGenerator.BuildClassInfo(snapshot);

                // Resolve runtime data if GameAssembly available
                if (ga != null)
                {
                    var resolver = new Il2CppRuntimeResolver(_driver, pid);

                    var fieldOffsets = resolver.ResolveFieldOffsets(ga.BaseAddress, ga.ImageSize, snapshot,
                        msg => log.Add(msg));
                    var methodPtrs = resolver.ResolveMethodPointers(ga.BaseAddress, ga.ImageSize, snapshot,
                        msg => log.Add(msg));
                    var enumValues = Il2CppRuntimeResolver.ExtractEnumValues(snapshot);
                    var stringLiterals = Il2CppRuntimeResolver.ExtractStringLiterals(snapshot);

                    Il2CppRuntimeResolver.ApplyFieldOffsets(classInfo, fieldOffsets, snapshot);
                    Il2CppRuntimeResolver.ApplyMethodPointers(classInfo, methodPtrs, snapshot);
                    Il2CppRuntimeResolver.ApplyEnumValues(classInfo, enumValues, snapshot);

                    // Save string literals
                    if (stringLiterals.Count > 0)
                    {
                        string strDump = Il2CppSdkGenerator.GenerateStringLiteralDump(stringLiterals);
                        File.WriteAllText(Path.Combine(outputDir, "StringLiterals.txt"), strDump, Encoding.UTF8);
                        log.Add($"Saved {stringLiterals.Count} string literals");
                    }

                    // Generate scripts
                    var rvaDict = new Dictionary<int, ulong>();
                    foreach (var mp in methodPtrs)
                        rvaDict[mp.MethodIndex] = mp.Rva;

                    string ghidra = Il2CppGhidraScript.GenerateGhidraScript(classInfo, rvaDict, ga.BaseAddress);
                    File.WriteAllText(Path.Combine(outputDir, "Ghidra_Script.py"), ghidra, Encoding.UTF8);

                    string ida = Il2CppGhidraScript.GenerateIdaScript(classInfo, rvaDict, ga.BaseAddress);
                    File.WriteAllText(Path.Combine(outputDir, "IDA_Script.py"), ida, Encoding.UTF8);

                    log.Add($"Generated Ghidra + IDA scripts");
                }

                // Save SDK
                string sdkText = Il2CppSdkGenerator.GenerateSdk(classInfo);
                File.WriteAllText(Path.Combine(outputDir, "Il2CppSdk.cs"), sdkText, Encoding.UTF8);

                var sb = new StringBuilder();
                sb.AppendLine($"Enhanced IL2CPP SDK Generated for PID {pid}");
                sb.AppendLine($"Output: {outputDir}");
                sb.AppendLine(new string('=', 50));
                sb.AppendLine($"Classes: {classInfo.Count}");
                sb.AppendLine($"Methods: {classInfo.Sum(c => c.Methods.Count)}");
                sb.AppendLine($"Fields: {classInfo.Sum(c => c.Fields.Count)}");

                int withOffset = 0, withRva = 0;
                foreach (var c in classInfo)
                {
                    foreach (var f in c.Fields) if (f.FieldOffset >= 0) withOffset++;
                    foreach (var m in c.Methods) if (m.Rva > 0) withRva++;
                }
                sb.AppendLine($"Fields with offset: {withOffset}");
                sb.AppendLine($"Methods with RVA: {withRva}");
                sb.AppendLine();

                foreach (var l in log) sb.AppendLine($"  {l}");

                sb.AppendLine();
                sb.AppendLine("Files generated:");
                foreach (string f in Directory.GetFiles(outputDir))
                    sb.AppendLine($"  {Path.GetFileName(f)}");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"GenerateEnhancedSdk failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Builds an IL2CPP type cross-reference graph from metadata. Shows which types reference which others (via fields, methods, base types, interfaces). Use typeIndex to query specific types.")]
        public string BuildXrefGraph(int pid, int typeIndex = -1)
        {
            try
            {
                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null) return $"Failed to read metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null) return "Failed to parse metadata.";

                var xref = Il2CppXrefGraph.BuildXrefGraph(snapshot);

                if (typeIndex >= 0)
                {
                    var users = Il2CppXrefGraph.QueryUsersOf(xref, typeIndex, snapshot);
                    var used = Il2CppXrefGraph.QueryUsedBy(xref, typeIndex, snapshot);
                    return users + "\n" + used;
                }

                return Il2CppXrefGraph.GenerateFullGraph(xref, snapshot, 2000);
            }
            catch (Exception ex)
            {
                return $"BuildXrefGraph failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Reconstructs IL2CPP virtual method tables from metadata. Shows slot assignments and virtual/override methods for each type.")]
        public string ReconstructVTables(int pid, string search = "")
        {
            try
            {
                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null) return $"Failed to read metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null) return "Failed to parse metadata.";

                var vtables = Il2CppStubGenerator.ReconstructVTables(snapshot);

                if (!string.IsNullOrEmpty(search))
                {
                    var filtered = vtables
                        .Where(kv => kv.Value.TypeName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0)
                        .ToDictionary(kv => kv.Key, kv => kv.Value);
                    return Il2CppStubGenerator.GenerateVTableDump(filtered);
                }

                return Il2CppStubGenerator.GenerateVTableDump(vtables);
            }
            catch (Exception ex)
            {
                return $"ReconstructVTables failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Generates full C# stub source files from IL2CPP metadata + runtime data. Creates one .cs file per type organized by assembly/namespace.")]
        public string GenerateStubs(int pid, string outputDir = "")
        {
            try
            {
                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null) return $"Failed to read metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null) return "Failed to parse metadata.";

                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to enumerate modules.";

                var ga = modules.FirstOrDefault(m => m.ModuleName != null &&
                    m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0);

                var log = new List<string>();
                var classInfo = Il2CppSdkGenerator.BuildClassInfo(snapshot);
                var vtables = Il2CppStubGenerator.ReconstructVTables(snapshot);

                if (string.IsNullOrEmpty(outputDir))
                    outputDir = Path.Combine(Path.GetTempPath(), $"il2cpp_stubs_{pid}");

                Il2CppStubGenerator.GenerateStubFiles(classInfo, snapshot, vtables, outputDir);

                int fileCount = 0;
                try { fileCount = Directory.GetFiles(outputDir, "*.cs", SearchOption.AllDirectories).Length; } catch { }

                return $"Generated {fileCount} stub files in {outputDir}";
            }
            catch (Exception ex)
            {
                return $"GenerateStubs failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Detects and attempts to decrypt encrypted IL2CPP metadata. Tests XOR (single/multi/rolling), nibble swap, and header-only encryption. Reports entropy analysis.")]
        public string DecryptMetadata(int pid)
        {
            try
            {
                var (rawData, address) = _driver.ReadIl2CppMetadata(pid);
                if (rawData == null) return $"Failed to read metadata from PID {pid}.";

                var log = new List<string>();
                var result = Il2CppMetadataDecryptor.TryDecrypt(rawData, msg => log.Add(msg));

                var sb = new StringBuilder();
                sb.AppendLine($"IL2CPP Metadata Decryption Analysis (PID {pid})");
                sb.AppendLine($"  Address: 0x{address:X16}");
                sb.AppendLine($"  Size: {rawData.Length:N0} bytes");
                sb.AppendLine($"  Original entropy: {result.OriginalEntropy:F4}");

                if (result.WasEncrypted)
                {
                    sb.AppendLine($"  Encryption detected: {result.Method}");
                    sb.AppendLine($"  Decrypted entropy: {result.DecryptedEntropy:F4}");
                    sb.AppendLine($"  Details: {result.Details}");
                }
                else
                {
                    sb.AppendLine($"  Result: {result.Details}");
                }

                // Also check string table encryption
                bool stringEncrypted = Il2CppMetadataDecryptor.IsStringTableEncrypted(
                    result.DecryptedMetadata ?? rawData);
                if (stringEncrypted)
                    sb.AppendLine("  Warning: String table appears encrypted (high entropy)");

                sb.AppendLine();
                foreach (var l in log) sb.AppendLine($"  {l}");

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"DecryptMetadata failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Exports IL2CPP class layouts as a ReClass.NET project file (.rcnet XML). Useful for memory editing and runtime inspection with ReClass.NET.")]
        public string ExportReClass(int pid, string outputPath = "", string search = "")
        {
            try
            {
                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null) return $"Failed to read metadata from PID {pid}.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null) return "Failed to parse metadata.";

                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to enumerate modules.";

                var ga = modules.FirstOrDefault(m => m.ModuleName != null &&
                    m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0);

                var log = new List<string>();
                var classInfo = Il2CppSdkGenerator.BuildClassInfo(snapshot);

                if (!string.IsNullOrEmpty(search))
                {
                    classInfo = classInfo.Where(c =>
                    {
                        string fullName = string.IsNullOrEmpty(c.Namespace) ? c.Name : $"{c.Namespace}.{c.Name}";
                        return fullName.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0;
                    }).ToList();
                }

                if (string.IsNullOrEmpty(outputPath))
                    outputPath = Path.Combine(Path.GetTempPath(), $"il2cpp_reclass_{pid}.rcnet");

                ReClassExporter.SaveReClassProject(classInfo, outputPath);

                return $"ReClass.NET project exported: {outputPath}\nClasses: {classInfo.Count}\n\n" +
                       ReClassExporter.GenerateStructSummary(classInfo);
            }
            catch (Exception ex)
            {
                return $"ExportReClass failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Scans a memory region for Unity asset bundle headers (UnityFS/UnityWeb/UnityRaw). Returns bundle signatures, versions, compression info, and contained asset names.")]
        public string ScanAssetBundles(int pid, ulong address = 0, int size = 0x100000)
        {
            try
            {
                byte[] data;
                if (address == 0)
                {
                    // Scan all committed regions for asset bundle signatures
                    var regions = _driver.EnumRegions(pid);
                    if (regions == null || regions.Count == 0)
                        return "Failed to enumerate memory regions.";

                    var allBundles = new List<UnityAssetBundleParser.AssetBundleInfo>();
                    int scanned = 0;

                    foreach (var (baseAddr, regionSize, protect, state, type) in regions)
                    {
                        if (state != 0x1000 || regionSize > 0x1000000 || regionSize < 32) continue;
                        if ((protect & 0x04) == 0 && (protect & 0x02) == 0 && (protect & 0x20) == 0 && (protect & 0x40) == 0) continue;

                        int readSize = (int)Math.Min(regionSize, 0x100000);
                        byte[] regionData = new byte[readSize];
                        var handle = GCHandle.Alloc(regionData, GCHandleType.Pinned);
                        try
                        {
                            if (_driver.CopyVirtualMemory(pid, (IntPtr)(long)baseAddr, handle.AddrOfPinnedObject(), readSize))
                            {
                                var found = UnityAssetBundleParser.ScanForBundles(regionData, baseAddr);
                                allBundles.AddRange(found);
                            }
                        }
                        finally { handle.Free(); }

                        scanned++;
                        if (allBundles.Count >= 100) break;
                    }

                    if (allBundles.Count == 0)
                        return $"No asset bundles found after scanning {scanned} memory regions.";

                    return UnityAssetBundleParser.GenerateReport(allBundles);
                }
                else
                {
                    data = new byte[size];
                    var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
                    try
                    {
                        if (!_driver.CopyVirtualMemory(pid, (IntPtr)(long)address, handle.AddrOfPinnedObject(), size))
                            return $"Failed to read {size} bytes at 0x{address:X16}.";
                    }
                    finally { handle.Free(); }

                    var bundles = UnityAssetBundleParser.ScanForBundles(data, address);
                    if (bundles.Count == 0)
                        return $"No asset bundles found in {size:N0} bytes at 0x{address:X16}.";

                    return UnityAssetBundleParser.GenerateReport(bundles);
                }
            }
            catch (Exception ex)
            {
                return $"ScanAssetBundles failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Scans GameAssembly.dll for CodeRegistration and MetadataRegistration runtime structs. Finds method pointer arrays, generic method pointers, type definition pointers, and field offset tables at their actual runtime addresses.")]
        public string FindCodeRegistration(int pid)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var ga = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found. Is this an IL2CPP process?";

                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                if (!Il2CppDumper.ValidateMetadataStructure(metadata))
                    return "Metadata validation failed.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var codeReg = Il2CppCodeRegistration.FindCodeRegistration(
                    _driver, pid, ga.BaseAddress, ga.ImageSize, snapshot);
                var metaReg = Il2CppCodeRegistration.FindMetadataRegistration(
                    _driver, pid, ga.BaseAddress, ga.ImageSize, snapshot);

                return Il2CppCodeRegistration.GenerateReport(codeReg, metaReg, ga.BaseAddress);
            }
            catch (Exception ex)
            {
                return $"FindCodeRegistration failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Generates Frida JS hook scripts and/or GameGuardian Lua scripts from IL2CPP metadata. Creates ready-to-use scripts with method hooks, string readers, field accessors, and patching helpers.")]
        public string GenerateFridaScript(int pid, string outputDir = "", string format = "both")
        {
            try
            {
                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                if (!Il2CppDumper.ValidateMetadataStructure(metadata))
                    return "Metadata validation failed.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var classInfos = Il2CppSdkGenerator.BuildClassInfo(snapshot);
                var sb = new StringBuilder();
                string dir = string.IsNullOrEmpty(outputDir) ? Path.Combine(Path.GetTempPath(), $"KsDump_Scripts_{pid}") : outputDir;
                Directory.CreateDirectory(dir);

                if (format == "frida" || format == "both")
                {
                    var methodRvas = new Dictionary<int, ulong>();
                    string frida = FridaScriptGenerator.GenerateFridaScript(classInfos, methodRvas);
                    string fridaPath = Path.Combine(dir, "hooks.js");
                    File.WriteAllText(fridaPath, frida);
                    sb.AppendLine($"Frida script: {fridaPath} ({frida.Length:N0} chars)");
                }

                if (format == "gg" || format == "both")
                {
                    string gg = FridaScriptGenerator.GenerateGameGuardianLua(classInfos);
                    string ggPath = Path.Combine(dir, "gameguardian.lua");
                    File.WriteAllText(ggPath, gg);
                    sb.AppendLine($"GameGuardian script: {ggPath} ({gg.Length:N0} chars)");
                }

                return sb.ToString();
            }
            catch (Exception ex)
            {
                return $"GenerateFridaScript failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Exports IL2CPP string literals as JSON with byte offsets, data indices, and lengths. Richer output than DumpStringLiterals. Saves to file if outputPath specified.")]
        public string ExportStringLiterals(int pid, string outputPath = "", string search = "")
        {
            try
            {
                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                if (!Il2CppDumper.ValidateMetadataStructure(metadata))
                    return "Metadata validation failed.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var dump = Il2CppStringLiteralDumper.ExtractAll(snapshot);

                if (!string.IsNullOrEmpty(outputPath))
                {
                    string json = Il2CppStringLiteralDumper.GenerateJsonExport(dump);
                    File.WriteAllText(outputPath, json);
                    return $"Exported {dump.TotalStrings} string literals ({dump.TotalBytes:N0} bytes) to {outputPath}";
                }

                return Il2CppStringLiteralDumper.GenerateReport(dump,
                    string.IsNullOrEmpty(search) ? null : search, 500);
            }
            catch (Exception ex)
            {
                return $"ExportStringLiterals failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Walks the Unity scene hierarchy by scanning for GameObject and Transform instances in process memory. Returns a tree of GameObjects with names, layers, and active state.")]
        public string WalkUnityScene(int pid, string search = "", int maxObjects = 500)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var up = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("UnityPlayer.dll", StringComparison.OrdinalIgnoreCase));
                if (up == null)
                    return "UnityPlayer.dll not found. Is this a Unity process?";

                var scene = UnitySceneWalker.WalkScene(_driver, pid, up.BaseAddress, up.ImageSize, maxObjects);

                if (!string.IsNullOrEmpty(search))
                    return UnitySceneWalker.SearchObjects(scene, search);

                return UnitySceneWalker.GenerateSceneTree(scene);
            }
            catch (Exception ex)
            {
                return $"WalkUnityScene failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Resolves concrete generic type instantiations from IL2CPP runtime data. Finds actual List<PlayerData>, Dictionary<string,int> etc. that exist at runtime.")]
        public string ResolveGenerics(int pid)
        {
            try
            {
                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                if (!Il2CppDumper.ValidateMetadataStructure(metadata))
                    return "Metadata validation failed.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to enumerate modules.";

                var ga = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found.";

                var result = Il2CppGenericResolver.ResolveFromRuntime(
                    _driver, pid, ga.BaseAddress, ga.ImageSize, snapshot);

                return Il2CppGenericResolver.GenerateReport(result);
            }
            catch (Exception ex)
            {
                return $"ResolveGenerics failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Detects anti-cheat solutions in a process. Scans loaded modules, kernel callbacks, and drivers for EAC, BattlEye, Vanguard, GameGuard, mhyprot, ACE, XIGNCODE3, PunkBuster, and 10+ other solutions.")]
        public string DetectAntiCheat(int pid)
        {
            try
            {
                var result = AntiCheatDetector.Detect(_driver, pid);
                return result.Summary;
            }
            catch (Exception ex)
            {
                return $"DetectAntiCheat failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Disassembles native x86-64 code at a method address in an IL2CPP process. Shows instructions, call targets, and jump targets. Use with method RVAs from the SDK dump.")]
        public string DisassembleNative(int pid, ulong address, int maxBytes = 256)
        {
            try
            {
                var result = Il2CppNativeDisassembler.DisassembleMethod(_driver, pid, address, maxBytes);
                return Il2CppNativeDisassembler.FormatDisassembly(result);
            }
            catch (Exception ex)
            {
                return $"DisassembleNative failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Resolves Mono runtime class and method addresses by walking MonoDomain -> MonoAssembly -> MonoImage -> MonoClass. Returns live pointers for all classes, methods, and fields.")]
        public string ResolveMonoRuntime(int pid, string search = "")
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var mono = modules.FirstOrDefault(m =>
                {
                    string name = (m.ModuleName ?? "").ToLowerInvariant();
                    return name.StartsWith("mono") && name.EndsWith(".dll");
                });
                if (mono == null)
                    return "No Mono runtime DLL found. Is this a Mono-based Unity process?";

                var result = MonoRuntimeResolver.ResolveFromMonoModule(
                    _driver, pid, mono.BaseAddress, mono.ImageSize);

                return MonoRuntimeResolver.GenerateReport(result,
                    string.IsNullOrEmpty(search) ? null : search);
            }
            catch (Exception ex)
            {
                return $"ResolveMonoRuntime failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Dump IL2CPP runtime TypeInfo (instance sizes, static field data, field layouts) from live Il2CppClass structs")]
        public string DumpTypeInfo(int pid, string filter = null, int maxTypes = 2000)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var ga = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found. Is this an IL2CPP process?";

                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var dump = Il2CppTypeInfoDumper.DumpTypeInfo(
                    _driver, pid, ga.BaseAddress, ga.ImageSize, snapshot, filter, maxTypes);

                return Il2CppTypeInfoDumper.GenerateReport(dump);
            }
            catch (Exception ex)
            {
                return $"DumpTypeInfo failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Extract Mono JIT info table mapping every JIT-compiled method to its native code address and size")]
        public string ExtractMonoJitTable(int pid, string search = null, int maxMethods = 5000)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var mono = modules.FirstOrDefault(m =>
                {
                    string name = (m.ModuleName ?? "").ToLowerInvariant();
                    return name.StartsWith("mono") && name.EndsWith(".dll");
                });
                if (mono == null)
                    return "No Mono runtime DLL found. Is this a Mono-based Unity process?";

                var dump = MonoJitTableExtractor.ExtractJitTable(
                    _driver, pid, mono.BaseAddress, mono.ImageSize, maxMethods);

                return MonoJitTableExtractor.GenerateReport(dump, search);
            }
            catch (Exception ex)
            {
                return $"ExtractMonoJitTable failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Parse IL2CPP MetadataUsage table (type/method/field/string usage sites and runtime addresses)")]
        public string ParseMetadataUsage(int pid, string usageType = null, string search = null)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var ga = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found. Is this an IL2CPP process?";

                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var result = Il2CppMetadataUsageParser.ParseFromMetadata(
                    snapshot, _driver, pid, ga.BaseAddress, ga.ImageSize);

                Il2CppMetadataUsageParser.UsageType? filterType = null;
                if (!string.IsNullOrEmpty(usageType))
                {
                    if (Enum.TryParse<Il2CppMetadataUsageParser.UsageType>(usageType, true, out var ut))
                        filterType = ut;
                }

                return Il2CppMetadataUsageParser.GenerateReport(result, filterType, search);
            }
            catch (Exception ex)
            {
                return $"ParseMetadataUsage failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Reconstruct PE imports for a dumped module by resolving IAT entries and scanning CALL targets against loaded DLL exports")]
        public string ReconstructImports(int pid, string moduleName = "GameAssembly.dll")
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var target = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals(moduleName, StringComparison.OrdinalIgnoreCase));
                if (target == null)
                    return $"Module '{moduleName}' not found.";

                var result = PEImportReconstructor.ReconstructImports(
                    _driver, pid, target.BaseAddress, target.ImageSize);

                return PEImportReconstructor.GenerateReport(result);
            }
            catch (Exception ex)
            {
                return $"ReconstructImports failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Scan heap for live instances of a specific IL2CPP class, reading field values for each found object")]
        public string ScanInstances(int pid, string className, int maxInstances = 200)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var ga = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found. Is this an IL2CPP process?";

                var result = Il2CppInstanceScanner.ScanByClassName(
                    _driver, pid, ga.BaseAddress, ga.ImageSize, className, maxInstances);

                return Il2CppInstanceScanner.GenerateReport(result);
            }
            catch (Exception ex)
            {
                return $"ScanInstances failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Build a method call graph by disassembling IL2CPP methods and tracing CALL targets")]
        public string BuildCallGraph(int pid, string focusClass = null, string search = null, int maxMethods = 1000)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var ga = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found. Is this an IL2CPP process?";

                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var result = UnityMethodTracer.BuildCallGraph(
                    _driver, pid, ga.BaseAddress, ga.ImageSize, snapshot, focusClass, maxMethods);

                return UnityMethodTracer.GenerateReport(result, search);
            }
            catch (Exception ex)
            {
                return $"BuildCallGraph failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Resolve IL2CPP delegate and multicast delegate instances to find registered event handlers and callback methods")]
        public string ResolveDelegates(int pid, string filter = null, int maxDelegates = 500)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var ga = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found. Is this an IL2CPP process?";

                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                Il2CppDumper.Il2CppMetadataSnapshot snapshot = null;
                if (metadata != null)
                    snapshot = Il2CppDumper.ParseFullMetadata(metadata);

                var result = Il2CppDelegateResolver.ScanDelegates(
                    _driver, pid, ga.BaseAddress, ga.ImageSize, snapshot, filter, maxDelegates);

                return Il2CppDelegateResolver.GenerateReport(result);
            }
            catch (Exception ex)
            {
                return $"ResolveDelegates failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Manage dump profiles: save/load/list/delete preset configurations per game for one-click re-dumps")]
        public string ManageDumpProfile(string action, string name = null, string engineType = null)
        {
            try
            {
                switch ((action ?? "").ToLowerInvariant())
                {
                    case "list":
                    {
                        var profiles = DumpProfile.ListProfiles();
                        if (profiles.Count == 0)
                            return "No dump profiles found.";

                        var sb = new System.Text.StringBuilder();
                        sb.AppendLine($"Dump Profiles ({profiles.Count}):");
                        foreach (var p in profiles)
                        {
                            sb.AppendLine($"  {p.Name} [{p.EngineType}] - used {p.DumpCount}x, last: {p.LastUsed:yyyy-MM-dd}");
                        }
                        return sb.ToString();
                    }

                    case "load":
                    {
                        if (string.IsNullOrEmpty(name))
                            return "Profile name required for 'load' action.";
                        var profile = DumpProfile.Load(name);
                        if (profile == null)
                            return $"Profile '{name}' not found.";
                        return profile.GenerateSummary();
                    }

                    case "create":
                    {
                        if (string.IsNullOrEmpty(name))
                            return "Profile name required for 'create' action.";
                        var profile = DumpProfile.CreateDefault(name, engineType ?? "il2cpp");
                        profile.Save();
                        return $"Profile '{name}' created and saved.\n{profile.GenerateSummary()}";
                    }

                    case "delete":
                    {
                        if (string.IsNullOrEmpty(name))
                            return "Profile name required for 'delete' action.";
                        bool deleted = DumpProfile.DeleteProfile(name);
                        return deleted ? $"Profile '{name}' deleted." : $"Profile '{name}' not found.";
                    }

                    default:
                        return "Usage: action = 'list' | 'load' | 'create' | 'delete'. Provide name for load/create/delete.";
                }
            }
            catch (Exception ex)
            {
                return $"ManageDumpProfile failed: {ex.Message}";
            }
        }

        // ---- 5th batch MCP tools ----

        private static readonly Dictionary<string, MemorySnapshotDiff.MemorySnapshot> _snapshots =
            new Dictionary<string, MemorySnapshotDiff.MemorySnapshot>();

        [McpServerTool, Description("Take a memory snapshot and optionally diff against a previous snapshot. Actions: 'take' (save snapshot with a name), 'diff' (compare two named snapshots), 'scan' (search for a value in a snapshot), 'list' (show saved snapshots)")]
        public string ManageMemorySnapshot(int pid, string action = "take", string name = null, string name2 = null,
            string valueType = null, string value = null, string compareType = null)
        {
            try
            {
                switch ((action ?? "").ToLowerInvariant())
                {
                    case "take":
                    {
                        string snapName = name ?? $"snap_{DateTime.Now:HHmmss}";
                        var snap = MemorySnapshotDiff.TakeSnapshot(_driver, pid);
                        _snapshots[snapName] = snap;
                        return $"Snapshot '{snapName}' taken: {snap.Regions.Count} regions, {snap.TotalBytes:N0} bytes at {snap.Timestamp:HH:mm:ss.fff}";
                    }

                    case "diff":
                    {
                        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(name2))
                            return "Provide name and name2 for the two snapshots to compare.";
                        if (!_snapshots.ContainsKey(name) || !_snapshots.ContainsKey(name2))
                            return $"Snapshot not found. Available: {string.Join(", ", _snapshots.Keys)}";

                        if (!string.IsNullOrEmpty(compareType))
                        {
                            var vDiff = MemorySnapshotDiff.CompareForValue(_snapshots[name], _snapshots[name2], compareType);
                            return MemorySnapshotDiff.GenerateDiffReport(vDiff);
                        }
                        else
                        {
                            var diff = MemorySnapshotDiff.CompareSnapshots(_snapshots[name], _snapshots[name2]);
                            return MemorySnapshotDiff.GenerateDiffReport(diff);
                        }
                    }

                    case "scan":
                    {
                        if (string.IsNullOrEmpty(name) || string.IsNullOrEmpty(valueType) || string.IsNullOrEmpty(value))
                            return "Provide name (snapshot), valueType (int32/float/int64/double), and value.";
                        if (!_snapshots.ContainsKey(name))
                            return $"Snapshot '{name}' not found. Available: {string.Join(", ", _snapshots.Keys)}";

                        var scanResult = MemorySnapshotDiff.ScanForValue(_snapshots[name], valueType, value);
                        return MemorySnapshotDiff.GenerateValueScanReport(scanResult);
                    }

                    case "list":
                    {
                        if (_snapshots.Count == 0) return "No snapshots stored.";
                        var sb = new System.Text.StringBuilder();
                        foreach (var kvp in _snapshots)
                            sb.AppendLine($"  {kvp.Key}: {kvp.Value.Regions.Count} regions, {kvp.Value.TotalBytes:N0} bytes @ {kvp.Value.Timestamp:HH:mm:ss.fff}");
                        return sb.ToString();
                    }

                    default:
                        return "Actions: take, diff, scan, list";
                }
            }
            catch (Exception ex)
            {
                return $"MemorySnapshot failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Generate unique byte pattern signatures for method addresses, with auto-wildcard for relocations. Output in IDA/x64dbg/CE/YARA/C++ formats")]
        public string GenerateSignature(int pid, string address, string moduleName = null, int sigLength = 32)
        {
            try
            {
                if (!ulong.TryParse(address.Replace("0x", "").Replace("0X", ""), System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                    return "Invalid address. Provide hex address like 0x7FF...";

                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                string modName = moduleName ?? "GameAssembly.dll";
                var mod = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals(modName, StringComparison.OrdinalIgnoreCase));
                if (mod == null)
                    return $"Module '{modName}' not found.";

                var sig = AutoSignatureGenerator.GenerateSignature(
                    _driver, pid, addr, mod.BaseAddress, mod.ImageSize, sigLength);

                if (sig == null) return "Failed to read memory at address.";

                return AutoSignatureGenerator.GenerateReport(sig);
            }
            catch (Exception ex)
            {
                return $"GenerateSignature failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Dump IL2CPP interface offset tables showing which interfaces each class implements and their vtable slot offsets")]
        public string DumpInterfaceOffsets(int pid, string filter = null, string interfaceFilter = null, int maxTypes = 3000)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return $"Failed to enumerate modules for PID {pid}.";

                var ga = modules.FirstOrDefault(m =>
                    (m.ModuleName ?? "").Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase));
                if (ga == null)
                    return "GameAssembly.dll not found. Is this an IL2CPP process?";

                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                Il2CppDumper.Il2CppMetadataSnapshot snapshot = null;
                if (metadata != null)
                    snapshot = Il2CppDumper.ParseFullMetadata(metadata);

                var result = Il2CppInterfaceOffsetDumper.DumpInterfaceOffsets(
                    _driver, pid, ga.BaseAddress, ga.ImageSize, snapshot, filter, maxTypes);

                return Il2CppInterfaceOffsetDumper.GenerateReport(result, interfaceFilter);
            }
            catch (Exception ex)
            {
                return $"DumpInterfaceOffsets failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Detect serialization formats (Protobuf, FlatBuffers, MessagePack, JSON, XML) in process memory and infer protobuf message schemas")]
        public string DetectSerializationFormats(int pid, string moduleName = null)
        {
            try
            {
                ProtobufDetector.DetectionResult result;

                if (!string.IsNullOrEmpty(moduleName))
                {
                    if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                        return $"Failed to enumerate modules for PID {pid}.";

                    var mod = modules.FirstOrDefault(m =>
                        (m.ModuleName ?? "").Equals(moduleName, StringComparison.OrdinalIgnoreCase));
                    if (mod == null)
                        return $"Module '{moduleName}' not found.";

                    result = ProtobufDetector.DetectInModule(_driver, pid, mod.BaseAddress, mod.ImageSize);
                }
                else
                {
                    result = ProtobufDetector.Detect(_driver, pid);
                }

                return ProtobufDetector.GenerateReport(result);
            }
            catch (Exception ex)
            {
                return $"DetectSerializationFormats failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Generate ready-to-use patch templates for a method: NOP, return true/false/float, skip jumps, redirect. Outputs CE scripts and Frida snippets")]
        public string GeneratePatchTemplates(int pid, string address, string methodName = null, string moduleName = null)
        {
            try
            {
                if (!ulong.TryParse(address.Replace("0x", "").Replace("0X", ""), System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                    return "Invalid address. Provide hex address like 0x7FF...";

                var result = MethodPatchGenerator.GeneratePatches(
                    _driver, pid, addr, methodName, moduleName ?? "GameAssembly.dll");

                return MethodPatchGenerator.GenerateReport(result);
            }
            catch (Exception ex)
            {
                return $"GeneratePatchTemplates failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Scan process memory for pointer chains leading to a target address. Finds static base pointers in modules for stable access paths")]
        public string PointerScan(int pid, string targetAddress, int maxDepth = 4, int maxOffset = 0x1000, int maxResults = 200)
        {
            try
            {
                if (!ulong.TryParse(targetAddress.Replace("0x", "").Replace("0X", ""), System.Globalization.NumberStyles.HexNumber, null, out ulong addr))
                    return "Invalid targetAddress. Provide hex address like 0x7FF...";

                var result = PointerScanEngine.Scan(_driver, pid, addr, maxDepth, maxOffset, maxResults);

                return PointerScanEngine.GenerateReport(result);
            }
            catch (Exception ex)
            {
                return $"PointerScan failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Extract custom attributes from IL2CPP metadata for types, methods, and fields. Finds [Serializable], [Obsolete], [HideInInspector], game-specific attributes")]
        public string ExtractAttributes(int pid, string filter = null, string attributeFilter = null, int maxEntries = 5000)
        {
            try
            {
                var (metadata, _) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse metadata.";

                var result = Il2CppAttributeExtractor.ExtractAttributes(snapshot, filter, maxEntries);

                return Il2CppAttributeExtractor.GenerateReport(result, attributeFilter);
            }
            catch (Exception ex)
            {
                return $"ExtractAttributes failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Dump Unity PlayerPrefs from Windows registry and find save files in persistent data paths. Works without attaching to the game process")]
        public string DumpPlayerPrefs(string companyName = null, string productName = null, bool searchSaveFiles = true)
        {
            try
            {
                UnityPlayerPrefsDumper.PlayerPrefsDumpResult result;

                if (string.IsNullOrEmpty(companyName) && string.IsNullOrEmpty(productName))
                {
                    result = UnityPlayerPrefsDumper.ListAllUnityGames();
                }
                else
                {
                    result = UnityPlayerPrefsDumper.DumpPlayerPrefs(companyName, productName, searchSaveFiles);
                }

                return UnityPlayerPrefsDumper.GenerateReport(result);
            }
            catch (Exception ex)
            {
                return $"DumpPlayerPrefs failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Detect vtable hooks in IL2CPP classes by checking if method pointers point outside GameAssembly.dll")]
        public string DetectVtableHooks(int pid, string filter = null, int maxClasses = 2000)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to get module list.";

                ModuleSummary ga = Array.Find(modules, m => m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0);
                if (ga.ModuleName == null)
                    return "GameAssembly.dll not found.";

                var result = Il2CppVtableHookDetector.DetectHooks(_driver, pid, ga.BaseAddress, (uint)ga.ImageSize, filter, maxClasses);
                return Truncate(Il2CppVtableHookDetector.GenerateReport(result), 60000);
            }
            catch (Exception ex)
            {
                return $"DetectVtableHooks failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Dump Unity GameObject hierarchy by walking Transform parent/child pointers in live memory")]
        public string DumpObjectHierarchy(int pid, string filter = null, int maxObjects = 2000, int maxDepth = 10)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to get module list.";

                ModuleSummary ga = Array.Find(modules, m => m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0);
                if (ga.ModuleName == null)
                    return "GameAssembly.dll not found.";

                var result = UnityObjectHierarchyDumper.DumpHierarchy(_driver, pid, ga.BaseAddress, (uint)ga.ImageSize, filter, maxObjects, maxDepth);
                return Truncate(UnityObjectHierarchyDumper.GenerateReport(result), 60000);
            }
            catch (Exception ex)
            {
                return $"DumpObjectHierarchy failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Resolve all enum types and their values from IL2CPP runtime memory")]
        public string ResolveEnums(int pid, string filter = null, string search = null, int maxEnums = 5000)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to get module list.";

                ModuleSummary ga = Array.Find(modules, m => m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0);
                if (ga.ModuleName == null)
                    return "GameAssembly.dll not found.";

                var (metadata, metaAddr) = _driver.ReadIl2CppMetadata(pid);
                if (metadata == null)
                    return "Failed to read IL2CPP metadata.";

                var snapshot = Il2CppDumper.ParseFullMetadata(metadata);
                if (snapshot == null)
                    return "Failed to parse IL2CPP metadata.";

                var result = Il2CppEnumResolver.DumpEnums(_driver, pid, ga.BaseAddress, (uint)ga.ImageSize, snapshot, filter, maxEnums);
                return Truncate(Il2CppEnumResolver.GenerateReport(result, search), 60000);
            }
            catch (Exception ex)
            {
                return $"ResolveEnums failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Watch a memory address for value changes over time. Polls at a configurable interval and reports all changes.")]
        public string WatchMemoryValue(int pid, string address, string valueType = "int32", int durationMs = 5000, int intervalMs = 50)
        {
            try
            {
                ulong addr;
                if (address.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
                    addr = Convert.ToUInt64(address, 16);
                else
                    addr = ulong.Parse(address);

                var result = MemoryWatchpointEngine.WatchValue(_driver, pid, addr, valueType, durationMs, intervalMs);
                return Truncate(MemoryWatchpointEngine.GenerateReport(result), 60000);
            }
            catch (Exception ex)
            {
                return $"WatchMemoryValue failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Dump all concrete generic type instantiations from IL2CPP runtime (e.g. List<PlayerData>, Dictionary<int,string>)")]
        public string DumpGenericInstantiations(int pid, string filter = null, string search = null, int maxClasses = 5000)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to get module list.";

                ModuleSummary ga = Array.Find(modules, m => m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0);
                if (ga.ModuleName == null)
                    return "GameAssembly.dll not found.";

                var result = Il2CppGenericInstDumper.DumpGenericInstantiations(_driver, pid, ga.BaseAddress, (uint)ga.ImageSize, filter, maxClasses);
                return Truncate(Il2CppGenericInstDumper.GenerateReport(result, search), 60000);
            }
            catch (Exception ex)
            {
                return $"DumpGenericInstantiations failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Compare two GameAssembly.dll files and generate migration maps (old RVA -> new RVA) for updating cheat tables across game patches")]
        public string CompareGameVersions(string oldDllPath, string newDllPath, string format = "ce")
        {
            try
            {
                var diff = BinaryDiffPatcher.CompareGameAssemblies(oldDllPath, newDllPath);
                string report = BinaryDiffPatcher.GenerateMigrationMap(diff, format);
                string ceScript = BinaryDiffPatcher.GenerateCheatTablePatch(diff);
                return Truncate(report + "\n\n" + ceScript, 60000);
            }
            catch (Exception ex)
            {
                return $"CompareGameVersions failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Read actual runtime values from IL2CPP static fields by resolving Il2CppClass->static_fields pointer + field offsets")]
        public string ReadStaticFields(int pid, string filter = null, string fieldFilter = null, int maxClasses = 2000)
        {
            try
            {
                if (!_driver.GetModuleSummaryList(pid, out ModuleSummary[] modules))
                    return "Failed to get module list.";

                ModuleSummary ga = Array.Find(modules, m => m.ModuleName.IndexOf("GameAssembly", StringComparison.OrdinalIgnoreCase) >= 0);
                if (ga.ModuleName == null)
                    return "GameAssembly.dll not found.";

                var result = Il2CppStaticFieldReader.ReadStaticFields(_driver, pid, ga.BaseAddress, (uint)ga.ImageSize, filter, fieldFilter, maxClasses);
                return Truncate(Il2CppStaticFieldReader.GenerateReport(result), 60000);
            }
            catch (Exception ex)
            {
                return $"ReadStaticFields failed: {ex.Message}";
            }
        }

        [McpServerTool, Description("Map Unity asset references by scanning .prefab/.unity/.asset files for script-to-asset GUID cross-references")]
        public string MapAssetReferences(string projectPath, string filter = null, string search = null, int maxAssets = 10000)
        {
            try
            {
                var result = UnityAssetReferenceMapper.MapAssetReferences(projectPath, filter, maxAssets);
                return Truncate(UnityAssetReferenceMapper.GenerateReport(result, search), 60000);
            }
            catch (Exception ex)
            {
                return $"MapAssetReferences failed: {ex.Message}";
            }
        }

        private static string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value) || value.Length <= maxLength)
                return value ?? "";
            return value.Substring(0, maxLength - 1) + "…";
        }
    }
}
