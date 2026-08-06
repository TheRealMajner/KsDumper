using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class BinaryDiffPatcher
    {
        public class FunctionMapping
        {
            public string Name;
            public uint OldRVA;
            public uint NewRVA;
            public int OldSize;
            public int NewSize;
            public float Similarity;
            public bool IsExact;
        }

        public class DiffResult
        {
            public string OldFileName;
            public string NewFileName;
            public int OldExportCount;
            public int NewExportCount;
            public List<FunctionMapping> Mappings = new List<FunctionMapping>();
            public List<string> AddedExports = new List<string>();
            public List<string> RemovedExports = new List<string>();
            public int ExactMatches;
            public int FuzzyMatches;
            public int UnmatchedOld;
            public int UnmatchedNew;
        }

        public static DiffResult CompareGameAssemblies(string oldPath, string newPath, int contextBytes = 32)
        {
            var result = new DiffResult
            {
                OldFileName = Path.GetFileName(oldPath),
                NewFileName = Path.GetFileName(newPath)
            };

            if (!File.Exists(oldPath) || !File.Exists(newPath))
                return result;

            byte[] oldDll = File.ReadAllBytes(oldPath);
            byte[] newDll = File.ReadAllBytes(newPath);

            var oldExports = ParseExports(oldDll);
            var newExports = ParseExports(newDll);

            result.OldExportCount = oldExports.Count;
            result.NewExportCount = newExports.Count;

            var newByName = new Dictionary<string, (uint rva, int ordinal)>();
            foreach (var exp in newExports)
                newByName[exp.name] = (exp.rva, exp.ordinal);

            var oldByName = new Dictionary<string, (uint rva, int ordinal)>();
            foreach (var exp in oldExports)
                oldByName[exp.name] = (exp.rva, exp.ordinal);

            // Phase 1: Match by export name
            foreach (var oldExp in oldExports)
            {
                if (newByName.TryGetValue(oldExp.name, out var newInfo))
                {
                    float similarity = CompareBytes(oldDll, oldExp.rva, newDll, newInfo.rva, contextBytes);

                    result.Mappings.Add(new FunctionMapping
                    {
                        Name = oldExp.name,
                        OldRVA = oldExp.rva,
                        NewRVA = newInfo.rva,
                        Similarity = similarity,
                        IsExact = oldExp.rva == newInfo.rva && similarity >= 1.0f
                    });

                    if (oldExp.rva == newInfo.rva && similarity >= 1.0f)
                        result.ExactMatches++;
                    else
                        result.FuzzyMatches++;
                }
                else
                {
                    result.RemovedExports.Add(oldExp.name);
                    result.UnmatchedOld++;
                }
            }

            foreach (var newExp in newExports)
            {
                if (!oldByName.ContainsKey(newExp.name))
                {
                    result.AddedExports.Add(newExp.name);
                    result.UnmatchedNew++;
                }
            }

            return result;
        }

        public static string GenerateMigrationMap(DiffResult diff, string format = "ce")
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Binary Diff Migration Map");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Old: {diff.OldFileName} ({diff.OldExportCount} exports)");
            sb.AppendLine($"// New: {diff.NewFileName} ({diff.NewExportCount} exports)");
            sb.AppendLine($"// Exact matches: {diff.ExactMatches}");
            sb.AppendLine($"// Moved/changed: {diff.FuzzyMatches}");
            sb.AppendLine($"// Added: {diff.UnmatchedNew}");
            sb.AppendLine($"// Removed: {diff.UnmatchedOld}");
            sb.AppendLine();

            var movedMappings = diff.Mappings
                .Where(m => !m.IsExact && m.OldRVA != m.NewRVA)
                .OrderBy(m => m.Name)
                .ToList();

            switch ((format ?? "").ToLowerInvariant())
            {
                case "ce":
                    sb.AppendLine("// Cheat Engine migration (old -> new RVA):");
                    foreach (var m in movedMappings)
                    {
                        sb.AppendLine($"// {m.Name}");
                        sb.AppendLine($"//   GameAssembly.dll+{m.OldRVA:X}  ->  GameAssembly.dll+{m.NewRVA:X}  ({m.Similarity:P0} similar)");
                    }
                    break;

                case "ida":
                    sb.AppendLine("# IDA Python migration script");
                    sb.AppendLine("migration_map = {");
                    foreach (var m in movedMappings)
                    {
                        sb.AppendLine($"    0x{m.OldRVA:X}: (0x{m.NewRVA:X}, \"{m.Name}\"),");
                    }
                    sb.AppendLine("}");
                    sb.AppendLine();
                    sb.AppendLine("for old_rva, (new_rva, name) in migration_map.items():");
                    sb.AppendLine("    print(f'  {name}: 0x{old_rva:X} -> 0x{new_rva:X}')");
                    break;

                case "json":
                    sb.AppendLine("{");
                    sb.AppendLine("  \"mappings\": [");
                    for (int i = 0; i < movedMappings.Count; i++)
                    {
                        var m = movedMappings[i];
                        string comma = i < movedMappings.Count - 1 ? "," : "";
                        sb.AppendLine($"    {{\"name\": \"{m.Name}\", \"old_rva\": \"0x{m.OldRVA:X}\", \"new_rva\": \"0x{m.NewRVA:X}\", \"similarity\": {m.Similarity:F2}}}{comma}");
                    }
                    sb.AppendLine("  ]");
                    sb.AppendLine("}");
                    break;

                default:
                    sb.AppendLine("// Migration map (old RVA -> new RVA):");
                    foreach (var m in movedMappings)
                    {
                        sb.AppendLine($"{m.Name}: 0x{m.OldRVA:X} -> 0x{m.NewRVA:X} ({m.Similarity:P0})");
                    }
                    break;
            }

            if (diff.RemovedExports.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine($"// Removed exports ({diff.RemovedExports.Count}):");
                foreach (var name in diff.RemovedExports.Take(100))
                    sb.AppendLine($"//   - {name}");
            }

            if (diff.AddedExports.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine($"// Added exports ({diff.AddedExports.Count}):");
                foreach (var name in diff.AddedExports.Take(100))
                    sb.AppendLine($"//   + {name}");
            }

            return sb.ToString();
        }

        public static string GenerateCheatTablePatch(DiffResult diff)
        {
            var sb = new StringBuilder();
            sb.AppendLine("-- Lua script to patch CE table addresses from old -> new version");
            sb.AppendLine($"-- Old: {diff.OldFileName}");
            sb.AppendLine($"-- New: {diff.NewFileName}");
            sb.AppendLine($"-- Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine();
            sb.AppendLine("local migration = {");

            foreach (var m in diff.Mappings.Where(m => m.OldRVA != m.NewRVA).OrderBy(m => m.OldRVA))
            {
                sb.AppendLine($"  [0x{m.OldRVA:X}] = 0x{m.NewRVA:X}, -- {m.Name}");
            }

            sb.AppendLine("}");
            sb.AppendLine();
            sb.AppendLine("local base = getAddress('GameAssembly.dll')");
            sb.AppendLine("local list = getAddressList()");
            sb.AppendLine("local patched = 0");
            sb.AppendLine();
            sb.AppendLine("for i = 0, list.Count - 1 do");
            sb.AppendLine("  local rec = list[i]");
            sb.AppendLine("  local addr = rec.Address");
            sb.AppendLine("  if addr:find('GameAssembly.dll') then");
            sb.AppendLine("    local offset = getAddress(addr) - base");
            sb.AppendLine("    if migration[offset] then");
            sb.AppendLine("      rec.Address = string.format('GameAssembly.dll+%X', migration[offset])");
            sb.AppendLine("      patched = patched + 1");
            sb.AppendLine("    end");
            sb.AppendLine("  end");
            sb.AppendLine("end");
            sb.AppendLine();
            sb.AppendLine("print(string.format('Patched %d addresses', patched))");

            return sb.ToString();
        }

        private static List<(string name, uint rva, int ordinal)> ParseExports(byte[] pe)
        {
            var exports = new List<(string, uint, int)>();
            if (pe.Length < 0x100) return exports;

            int peOff = BitConverter.ToInt32(pe, 0x3C);
            if (peOff <= 0 || peOff + 0x78 + 8 > pe.Length) return exports;

            // Export table RVA and size from optional header
            bool is64 = BitConverter.ToUInt16(pe, peOff + 0x18) == 0x20b;
            int exportDirOff = is64 ? peOff + 0x88 : peOff + 0x78;
            if (exportDirOff + 8 > pe.Length) return exports;

            uint exportRVA = BitConverter.ToUInt32(pe, exportDirOff);
            uint exportSize = BitConverter.ToUInt32(pe, exportDirOff + 4);
            if (exportRVA == 0) return exports;

            int exportFileOff = RvaToOffset(pe, exportRVA, peOff);
            if (exportFileOff < 0 || exportFileOff + 40 > pe.Length) return exports;

            uint numFunctions = BitConverter.ToUInt32(pe, exportFileOff + 20);
            uint numNames = BitConverter.ToUInt32(pe, exportFileOff + 24);
            uint addrTableRVA = BitConverter.ToUInt32(pe, exportFileOff + 28);
            uint nameTableRVA = BitConverter.ToUInt32(pe, exportFileOff + 32);
            uint ordTableRVA = BitConverter.ToUInt32(pe, exportFileOff + 36);

            int addrTableOff = RvaToOffset(pe, addrTableRVA, peOff);
            int nameTableOff = RvaToOffset(pe, nameTableRVA, peOff);
            int ordTableOff = RvaToOffset(pe, ordTableRVA, peOff);

            if (addrTableOff < 0 || nameTableOff < 0 || ordTableOff < 0) return exports;

            for (int i = 0; i < numNames && i < 50000; i++)
            {
                if (nameTableOff + i * 4 + 4 > pe.Length) break;
                if (ordTableOff + i * 2 + 2 > pe.Length) break;

                uint nameRVA = BitConverter.ToUInt32(pe, nameTableOff + i * 4);
                ushort ordinal = BitConverter.ToUInt16(pe, ordTableOff + i * 2);

                int nameFileOff = RvaToOffset(pe, nameRVA, peOff);
                if (nameFileOff < 0 || nameFileOff >= pe.Length) continue;

                int end = nameFileOff;
                while (end < pe.Length && pe[end] != 0) end++;
                string name = Encoding.ASCII.GetString(pe, nameFileOff, end - nameFileOff);

                if (addrTableOff + ordinal * 4 + 4 > pe.Length) continue;
                uint funcRVA = BitConverter.ToUInt32(pe, addrTableOff + ordinal * 4);

                exports.Add((name, funcRVA, ordinal));
            }

            return exports;
        }

        private static int RvaToOffset(byte[] pe, uint rva, int peOff)
        {
            ushort sectionCount = BitConverter.ToUInt16(pe, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(pe, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > pe.Length) break;

                uint vSize = BitConverter.ToUInt32(pe, off + 8);
                uint vAddr = BitConverter.ToUInt32(pe, off + 12);
                uint rawSize = BitConverter.ToUInt32(pe, off + 16);
                uint rawAddr = BitConverter.ToUInt32(pe, off + 20);

                if (rva >= vAddr && rva < vAddr + vSize)
                    return (int)(rva - vAddr + rawAddr);
            }

            return -1;
        }

        private static float CompareBytes(byte[] oldData, uint oldRVA, byte[] newData, uint newRVA, int count)
        {
            int oldOff = RvaToOffset(oldData, oldRVA, BitConverter.ToInt32(oldData, 0x3C));
            int newOff = RvaToOffset(newData, newRVA, BitConverter.ToInt32(newData, 0x3C));

            if (oldOff < 0 || newOff < 0) return 0;
            if (oldOff + count > oldData.Length || newOff + count > newData.Length) return 0;

            int matching = 0;
            for (int i = 0; i < count; i++)
            {
                if (oldData[oldOff + i] == newData[newOff + i])
                    matching++;
            }

            return (float)matching / count;
        }
    }
}
