using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class UnityAssetReferenceMapper
    {
        public class AssetReference
        {
            public string ScriptClass;
            public string FieldName;
            public string FieldType;
            public string AssetPath;
            public string AssetGUID;
            public string AssetType;
        }

        public class ScriptToAssetMapping
        {
            public string ScriptClass;
            public string ScriptGUID;
            public string ScriptPath;
            public List<AssetReference> References = new List<AssetReference>();
        }

        public class AssetMapResult
        {
            public List<ScriptToAssetMapping> ScriptMappings = new List<ScriptToAssetMapping>();
            public Dictionary<string, List<string>> AssetUsageMap = new Dictionary<string, List<string>>();
            public int TotalScripts;
            public int TotalReferences;
            public int TotalAssets;
            public string ProjectPath;
        }

        public static AssetMapResult MapAssetReferences(
            string projectPath,
            string filter = null,
            int maxAssets = 10000)
        {
            var result = new AssetMapResult { ProjectPath = projectPath };

            if (!Directory.Exists(projectPath)) return result;

            string assetsPath = Path.Combine(projectPath, "Assets");
            if (!Directory.Exists(assetsPath))
            {
                // Maybe projectPath IS the Assets folder
                if (Directory.GetFiles(projectPath, "*.meta", SearchOption.TopDirectoryOnly).Length > 0)
                    assetsPath = projectPath;
                else
                    return result;
            }

            // Build GUID -> path map from .meta files
            var guidToPath = new Dictionary<string, string>();
            var pathToGuid = new Dictionary<string, string>();

            foreach (var metaFile in SafeEnumFiles(assetsPath, "*.meta"))
            {
                if (guidToPath.Count >= maxAssets) break;

                string guid = ExtractGuidFromMeta(metaFile);
                if (guid == null) continue;

                string assetPath = metaFile.Substring(0, metaFile.Length - 5); // Remove .meta
                string relativePath = GetRelativePath(projectPath, assetPath);

                guidToPath[guid] = relativePath;
                pathToGuid[relativePath] = guid;
            }

            // Find all .cs scripts and their .meta GUIDs
            var scriptMappings = new Dictionary<string, ScriptToAssetMapping>();

            foreach (var csFile in SafeEnumFiles(assetsPath, "*.cs"))
            {
                string relativePath = GetRelativePath(projectPath, csFile);
                string className = Path.GetFileNameWithoutExtension(csFile);

                if (!string.IsNullOrEmpty(filter) &&
                    className.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0 &&
                    relativePath.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;

                string metaPath = csFile + ".meta";
                string scriptGuid = File.Exists(metaPath) ? ExtractGuidFromMeta(metaPath) : null;

                var mapping = new ScriptToAssetMapping
                {
                    ScriptClass = className,
                    ScriptGUID = scriptGuid,
                    ScriptPath = relativePath
                };

                scriptMappings[className] = mapping;
                result.TotalScripts++;
            }

            // Scan .prefab, .unity (scene), .asset files for script references
            var yamlExtensions = new[] { "*.prefab", "*.unity", "*.asset", "*.controller", "*.overrideController" };

            foreach (var ext in yamlExtensions)
            {
                foreach (var yamlFile in SafeEnumFiles(assetsPath, ext))
                {
                    ScanYamlForReferences(yamlFile, projectPath, guidToPath, scriptMappings, result);
                }
            }

            // Build asset usage map (which assets are used by which scripts)
            foreach (var mapping in scriptMappings.Values)
            {
                foreach (var reference in mapping.References)
                {
                    string assetKey = reference.AssetPath ?? reference.AssetGUID ?? "unknown";

                    if (!result.AssetUsageMap.ContainsKey(assetKey))
                        result.AssetUsageMap[assetKey] = new List<string>();

                    string user = $"{mapping.ScriptClass}.{reference.FieldName}";
                    if (!result.AssetUsageMap[assetKey].Contains(user))
                        result.AssetUsageMap[assetKey].Add(user);
                }
            }

            result.ScriptMappings = scriptMappings.Values.Where(m => m.References.Count > 0).ToList();
            result.TotalReferences = result.ScriptMappings.Sum(m => m.References.Count);
            result.TotalAssets = result.AssetUsageMap.Count;

            return result;
        }

        private static void ScanYamlForReferences(
            string filePath, string projectPath,
            Dictionary<string, string> guidToPath,
            Dictionary<string, ScriptToAssetMapping> scriptMappings,
            AssetMapResult result)
        {
            string[] lines;
            try { lines = File.ReadAllLines(filePath); }
            catch { return; }

            string currentScriptGuid = null;
            string currentFieldName = null;

            for (int i = 0; i < lines.Length; i++)
            {
                string line = lines[i].TrimStart();

                // Detect MonoBehaviour script reference
                if (line.StartsWith("m_Script:"))
                {
                    string guid = ExtractGuidFromYamlRef(line);
                    if (guid != null)
                        currentScriptGuid = guid;
                    continue;
                }

                // Look for GUID references in field values
                if (line.Contains("guid:") && currentScriptGuid != null)
                {
                    string refGuid = ExtractGuidFromYamlRef(line);
                    if (refGuid == null || refGuid == currentScriptGuid) continue;

                    // Extract field name (the key before the colon on this line or a parent line)
                    string fieldName = "?";
                    int colonIdx = line.IndexOf(':');
                    if (colonIdx > 0)
                        fieldName = line.Substring(0, colonIdx).Trim().TrimStart('-').Trim();

                    if (fieldName.StartsWith("m_"))
                        fieldName = fieldName.Substring(2);

                    // Find which script this belongs to
                    string scriptClass = null;
                    foreach (var kv in scriptMappings)
                    {
                        if (kv.Value.ScriptGUID == currentScriptGuid)
                        {
                            scriptClass = kv.Key;
                            break;
                        }
                    }

                    if (scriptClass == null) continue;

                    guidToPath.TryGetValue(refGuid, out string assetPath);
                    string assetType = assetPath != null ? GetAssetType(assetPath) : "unknown";

                    scriptMappings[scriptClass].References.Add(new AssetReference
                    {
                        ScriptClass = scriptClass,
                        FieldName = fieldName,
                        FieldType = assetType,
                        AssetPath = assetPath,
                        AssetGUID = refGuid,
                        AssetType = assetType
                    });

                    result.TotalReferences++;
                }

                // Reset on new component
                if (line.StartsWith("--- !u!"))
                    currentScriptGuid = null;
            }
        }

        private static string ExtractGuidFromMeta(string metaPath)
        {
            try
            {
                foreach (var line in File.ReadLines(metaPath))
                {
                    if (line.StartsWith("guid:"))
                    {
                        return line.Substring(5).Trim();
                    }
                }
            }
            catch { }
            return null;
        }

        private static string ExtractGuidFromYamlRef(string line)
        {
            int guidIdx = line.IndexOf("guid:");
            if (guidIdx < 0) return null;

            int start = guidIdx + 5;
            while (start < line.Length && line[start] == ' ') start++;

            int end = start;
            while (end < line.Length && ((line[end] >= '0' && line[end] <= '9') ||
                   (line[end] >= 'a' && line[end] <= 'f') ||
                   (line[end] >= 'A' && line[end] <= 'F')))
                end++;

            if (end - start >= 32)
                return line.Substring(start, end - start);

            return null;
        }

        private static string GetAssetType(string path)
        {
            string ext = Path.GetExtension(path).ToLowerInvariant();
            switch (ext)
            {
                case ".png": case ".jpg": case ".jpeg": case ".tga": case ".bmp": case ".psd":
                    return "Texture";
                case ".mat": return "Material";
                case ".shader": return "Shader";
                case ".prefab": return "Prefab";
                case ".fbx": case ".obj": case ".blend": return "Model";
                case ".anim": return "Animation";
                case ".controller": return "AnimatorController";
                case ".mp3": case ".wav": case ".ogg": return "AudioClip";
                case ".cs": return "Script";
                case ".asset": return "ScriptableObject";
                case ".unity": return "Scene";
                case ".ttf": case ".otf": return "Font";
                case ".json": case ".xml": case ".txt": return "TextAsset";
                case ".compute": return "ComputeShader";
                case ".renderTexture": return "RenderTexture";
                default: return ext.TrimStart('.');
            }
        }

        private static string GetRelativePath(string basePath, string fullPath)
        {
            if (fullPath.StartsWith(basePath, StringComparison.OrdinalIgnoreCase))
            {
                string rel = fullPath.Substring(basePath.Length).TrimStart('\\', '/');
                return rel.Replace('\\', '/');
            }
            return fullPath.Replace('\\', '/');
        }

        private static IEnumerable<string> SafeEnumFiles(string path, string pattern)
        {
            try
            {
                return Directory.EnumerateFiles(path, pattern, SearchOption.AllDirectories);
            }
            catch
            {
                return Enumerable.Empty<string>();
            }
        }

        public static string GenerateReport(AssetMapResult result, string search = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Unity Asset Reference Mapper");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Project: {result.ProjectPath}");
            sb.AppendLine($"// Scripts analyzed: {result.TotalScripts}");
            sb.AppendLine($"// Total references: {result.TotalReferences}");
            sb.AppendLine($"// Unique assets referenced: {result.TotalAssets}");
            sb.AppendLine();

            var mappings = result.ScriptMappings.AsEnumerable();
            if (!string.IsNullOrEmpty(search))
                mappings = mappings.Where(m =>
                    m.ScriptClass.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    m.References.Any(r => (r.AssetPath ?? "").IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0));

            sb.AppendLine("// === Script -> Asset References ===");
            sb.AppendLine();

            foreach (var mapping in mappings.OrderBy(m => m.ScriptClass))
            {
                sb.AppendLine($"{mapping.ScriptClass} ({mapping.ScriptPath})");
                foreach (var reference in mapping.References.OrderBy(r => r.FieldName))
                {
                    string path = reference.AssetPath ?? reference.AssetGUID;
                    sb.AppendLine($"  .{reference.FieldName} [{reference.AssetType}] -> {path}");
                }
                sb.AppendLine();
            }

            if (result.AssetUsageMap.Count > 0)
            {
                sb.AppendLine("// === Most Referenced Assets ===");
                sb.AppendLine();

                foreach (var kv in result.AssetUsageMap.OrderByDescending(x => x.Value.Count).Take(50))
                {
                    sb.AppendLine($"{kv.Key} (used by {kv.Value.Count} fields)");
                    foreach (var user in kv.Value.Take(10))
                        sb.AppendLine($"  <- {user}");
                    sb.AppendLine();
                }
            }

            return sb.ToString();
        }
    }
}
