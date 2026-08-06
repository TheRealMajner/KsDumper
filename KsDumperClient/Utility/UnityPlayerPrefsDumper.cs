using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using Microsoft.Win32;

namespace KsDumperClient.Utility
{
    public static class UnityPlayerPrefsDumper
    {
        public class PlayerPrefEntry
        {
            public string Key;
            public string Value;
            public string Type; // "int", "float", "string"
            public string RawRegistryType;
        }

        public class SaveFileInfo
        {
            public string Path;
            public string FileName;
            public long FileSize;
            public DateTime LastModified;
            public string DetectedFormat; // "json", "xml", "binary", "sqlite", "ini", "unknown"
            public string Preview;
        }

        public class PlayerPrefsDumpResult
        {
            public string CompanyName;
            public string ProductName;
            public string RegistryPath;
            public List<PlayerPrefEntry> Prefs = new List<PlayerPrefEntry>();
            public List<SaveFileInfo> SaveFiles = new List<SaveFileInfo>();
            public List<string> PersistentDataPaths = new List<string>();
        }

        public static PlayerPrefsDumpResult DumpPlayerPrefs(
            string companyName = null, string productName = null,
            bool searchSaveFiles = true)
        {
            var result = new PlayerPrefsDumpResult
            {
                CompanyName = companyName,
                ProductName = productName
            };

            // Read PlayerPrefs from registry
            if (!string.IsNullOrEmpty(companyName) && !string.IsNullOrEmpty(productName))
            {
                ReadSpecificPlayerPrefs(result, companyName, productName);
            }
            else
            {
                // Enumerate all Unity PlayerPrefs in registry
                EnumerateAllPlayerPrefs(result);
            }

            // Find persistent data paths
            if (!string.IsNullOrEmpty(companyName) && !string.IsNullOrEmpty(productName))
            {
                FindPersistentDataPaths(result, companyName, productName);
            }
            else
            {
                FindAllUnityDataPaths(result);
            }

            // Search for save files
            if (searchSaveFiles)
            {
                foreach (var path in result.PersistentDataPaths)
                {
                    ScanForSaveFiles(result, path);
                }
            }

            return result;
        }

        public static PlayerPrefsDumpResult ListAllUnityGames()
        {
            var result = new PlayerPrefsDumpResult();
            EnumerateAllPlayerPrefs(result);
            FindAllUnityDataPaths(result);
            return result;
        }

        private static void ReadSpecificPlayerPrefs(PlayerPrefsDumpResult result, string company, string product)
        {
            string regPath = $"Software\\Unity\\UnityPlayer\\{company}\\{product}";
            result.RegistryPath = $"HKCU\\{regPath}";

            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(regPath))
                {
                    if (key == null) return;
                    ReadPrefsFromKey(result, key);
                }
            }
            catch { }

            // Also try the alternate path format
            string altPath = $"Software\\{company}\\{product}";
            try
            {
                using (var key = Registry.CurrentUser.OpenSubKey(altPath))
                {
                    if (key == null) return;
                    ReadPrefsFromKey(result, key);
                }
            }
            catch { }
        }

        private static void EnumerateAllPlayerPrefs(PlayerPrefsDumpResult result)
        {
            // Check Software\Unity\UnityPlayer\*\*
            try
            {
                using (var unityKey = Registry.CurrentUser.OpenSubKey("Software\\Unity\\UnityPlayer"))
                {
                    if (unityKey != null)
                    {
                        foreach (string companyName in unityKey.GetSubKeyNames())
                        {
                            using (var companyKey = unityKey.OpenSubKey(companyName))
                            {
                                if (companyKey == null) continue;
                                foreach (string productName in companyKey.GetSubKeyNames())
                                {
                                    using (var productKey = companyKey.OpenSubKey(productName))
                                    {
                                        if (productKey == null) continue;
                                        result.CompanyName = companyName;
                                        result.ProductName = productName;
                                        result.RegistryPath = $"HKCU\\Software\\Unity\\UnityPlayer\\{companyName}\\{productName}";
                                        ReadPrefsFromKey(result, productKey);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch { }
        }

        private static void ReadPrefsFromKey(PlayerPrefsDumpResult result, RegistryKey key)
        {
            foreach (string valueName in key.GetValueNames())
            {
                try
                {
                    var kind = key.GetValueKind(valueName);
                    object rawValue = key.GetValue(valueName);

                    var entry = new PlayerPrefEntry { Key = CleanKeyName(valueName) };

                    switch (kind)
                    {
                        case RegistryValueKind.DWord:
                            entry.Type = "int";
                            entry.Value = rawValue?.ToString() ?? "0";
                            entry.RawRegistryType = "REG_DWORD";
                            break;

                        case RegistryValueKind.QWord:
                            entry.Type = "int64";
                            entry.Value = rawValue?.ToString() ?? "0";
                            entry.RawRegistryType = "REG_QWORD";
                            break;

                        case RegistryValueKind.Binary:
                            byte[] binVal = rawValue as byte[];
                            if (binVal != null && binVal.Length == 8)
                            {
                                double dVal = BitConverter.ToDouble(binVal, 0);
                                float fVal = (float)dVal;
                                entry.Type = "float";
                                entry.Value = fVal.ToString("G6");
                            }
                            else
                            {
                                entry.Type = "binary";
                                entry.Value = binVal != null ? BitConverter.ToString(binVal).Replace("-", " ") : "";
                            }
                            entry.RawRegistryType = "REG_BINARY";
                            break;

                        case RegistryValueKind.String:
                        case RegistryValueKind.ExpandString:
                            entry.Type = "string";
                            entry.Value = rawValue?.ToString() ?? "";
                            entry.RawRegistryType = "REG_SZ";
                            break;

                        default:
                            entry.Type = "unknown";
                            entry.Value = rawValue?.ToString() ?? "";
                            entry.RawRegistryType = kind.ToString();
                            break;
                    }

                    result.Prefs.Add(entry);
                }
                catch { }
            }
        }

        private static string CleanKeyName(string regValueName)
        {
            // Unity appends "_hXXXXXXXX" hash suffix to registry value names
            int hashIdx = regValueName.LastIndexOf("_h");
            if (hashIdx > 0 && regValueName.Length - hashIdx > 5)
            {
                string suffix = regValueName.Substring(hashIdx + 2);
                bool allHex = suffix.All(c => "0123456789abcdefABCDEF".Contains(c));
                if (allHex)
                    return regValueName.Substring(0, hashIdx);
            }
            return regValueName;
        }

        private static void FindPersistentDataPaths(PlayerPrefsDumpResult result, string company, string product)
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            string localLow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow");

            string[] candidates = new string[]
            {
                Path.Combine(localLow, company, product),
                Path.Combine(appData, company, product),
                Path.Combine(appData, "..", "LocalLow", company, product),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), company, product)
            };

            foreach (var path in candidates)
            {
                try
                {
                    string fullPath = Path.GetFullPath(path);
                    if (Directory.Exists(fullPath) && !result.PersistentDataPaths.Contains(fullPath))
                        result.PersistentDataPaths.Add(fullPath);
                }
                catch { }
            }
        }

        private static void FindAllUnityDataPaths(PlayerPrefsDumpResult result)
        {
            string localLow = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "LocalLow");

            try
            {
                if (!Directory.Exists(localLow)) return;

                foreach (string companyDir in Directory.GetDirectories(localLow))
                {
                    foreach (string productDir in Directory.GetDirectories(companyDir))
                    {
                        // Check if this looks like a Unity game data folder
                        bool hasUnityMarkers =
                            File.Exists(Path.Combine(productDir, "Player.log")) ||
                            File.Exists(Path.Combine(productDir, "output_log.txt")) ||
                            Directory.Exists(Path.Combine(productDir, "Unity")) ||
                            Directory.GetFiles(productDir, "*.save").Length > 0 ||
                            Directory.GetFiles(productDir, "*.sav").Length > 0 ||
                            Directory.GetFiles(productDir, "*.dat").Length > 0 ||
                            Directory.GetFiles(productDir, "*.json").Length > 0;

                        if (hasUnityMarkers && !result.PersistentDataPaths.Contains(productDir))
                            result.PersistentDataPaths.Add(productDir);
                    }
                }
            }
            catch { }
        }

        private static void ScanForSaveFiles(PlayerPrefsDumpResult result, string basePath)
        {
            if (!Directory.Exists(basePath)) return;

            string[] saveExtensions = { "*.save", "*.sav", "*.dat", "*.json", "*.xml",
                                        "*.bin", "*.db", "*.sqlite", "*.sqlite3",
                                        "*.ini", "*.cfg", "*.config", "*.prefs",
                                        "*.playerprefs", "*.progress", "*.profile" };

            try
            {
                foreach (var ext in saveExtensions)
                {
                    foreach (var file in Directory.GetFiles(basePath, ext, SearchOption.AllDirectories))
                    {
                        try
                        {
                            var fi = new FileInfo(file);
                            if (fi.Length > 100 * 1024 * 1024) continue; // Skip > 100MB

                            var saveInfo = new SaveFileInfo
                            {
                                Path = file,
                                FileName = fi.Name,
                                FileSize = fi.Length,
                                LastModified = fi.LastWriteTime
                            };

                            // Detect format and preview
                            if (fi.Length > 0 && fi.Length < 10 * 1024 * 1024)
                            {
                                DetectFileFormat(saveInfo);
                            }
                            else
                            {
                                saveInfo.DetectedFormat = "unknown";
                            }

                            result.SaveFiles.Add(saveInfo);
                        }
                        catch { }
                    }
                }

                // Also check for Player.log
                string playerLog = Path.Combine(basePath, "Player.log");
                if (File.Exists(playerLog))
                {
                    var fi = new FileInfo(playerLog);
                    result.SaveFiles.Add(new SaveFileInfo
                    {
                        Path = playerLog,
                        FileName = "Player.log",
                        FileSize = fi.Length,
                        LastModified = fi.LastWriteTime,
                        DetectedFormat = "log"
                    });
                }
            }
            catch { }
        }

        private static void DetectFileFormat(SaveFileInfo info)
        {
            try
            {
                byte[] header = new byte[Math.Min(256, (int)info.FileSize)];
                using (var fs = File.OpenRead(info.Path))
                    fs.Read(header, 0, header.Length);

                // SQLite magic
                if (header.Length >= 16 && Encoding.ASCII.GetString(header, 0, 15) == "SQLite format 3")
                {
                    info.DetectedFormat = "sqlite";
                    return;
                }

                string text = Encoding.UTF8.GetString(header).TrimStart();

                if (text.StartsWith("{") || text.StartsWith("["))
                {
                    info.DetectedFormat = "json";
                    info.Preview = text.Length > 200 ? text.Substring(0, 200) + "..." : text;
                    return;
                }

                if (text.StartsWith("<?xml") || text.StartsWith("<"))
                {
                    info.DetectedFormat = "xml";
                    info.Preview = text.Length > 200 ? text.Substring(0, 200) + "..." : text;
                    return;
                }

                if (text.Contains("=") && (text.Contains("[") || text.Contains("\n")))
                {
                    info.DetectedFormat = "ini";
                    info.Preview = text.Length > 200 ? text.Substring(0, 200) + "..." : text;
                    return;
                }

                // Check if mostly printable text
                int printable = header.Count(b => b >= 0x20 && b < 0x7F);
                if ((float)printable / header.Length > 0.8f)
                {
                    info.DetectedFormat = "text";
                    info.Preview = text.Length > 200 ? text.Substring(0, 200) + "..." : text;
                    return;
                }

                info.DetectedFormat = "binary";
            }
            catch
            {
                info.DetectedFormat = "unknown";
            }
        }

        public static string GenerateReport(PlayerPrefsDumpResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Unity PlayerPrefs & Save Data Dumper");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            if (!string.IsNullOrEmpty(result.CompanyName))
                sb.AppendLine($"// Company: {result.CompanyName}");
            if (!string.IsNullOrEmpty(result.ProductName))
                sb.AppendLine($"// Product: {result.ProductName}");
            if (!string.IsNullOrEmpty(result.RegistryPath))
                sb.AppendLine($"// Registry: {result.RegistryPath}");
            sb.AppendLine($"// PlayerPrefs entries: {result.Prefs.Count}");
            sb.AppendLine($"// Data paths found: {result.PersistentDataPaths.Count}");
            sb.AppendLine($"// Save files found: {result.SaveFiles.Count}");
            sb.AppendLine();

            // PlayerPrefs
            if (result.Prefs.Count > 0)
            {
                sb.AppendLine("=== PlayerPrefs ===");
                foreach (var pref in result.Prefs.OrderBy(p => p.Key))
                {
                    string valPreview = pref.Value;
                    if (valPreview.Length > 100)
                        valPreview = valPreview.Substring(0, 100) + "...";
                    sb.AppendLine($"  [{pref.Type}] {pref.Key} = {valPreview}");
                }
                sb.AppendLine();
            }

            // Data paths
            if (result.PersistentDataPaths.Count > 0)
            {
                sb.AppendLine("=== Persistent Data Paths ===");
                foreach (var path in result.PersistentDataPaths)
                    sb.AppendLine($"  {path}");
                sb.AppendLine();
            }

            // Save files
            if (result.SaveFiles.Count > 0)
            {
                sb.AppendLine("=== Save Files ===");
                foreach (var file in result.SaveFiles.OrderBy(f => f.Path))
                {
                    sb.AppendLine($"  [{file.DetectedFormat}] {file.FileName} ({FormatSize(file.FileSize)}) modified: {file.LastModified:yyyy-MM-dd HH:mm}");
                    sb.AppendLine($"    Path: {file.Path}");
                    if (!string.IsNullOrEmpty(file.Preview))
                        sb.AppendLine($"    Preview: {file.Preview.Substring(0, Math.Min(file.Preview.Length, 120))}");
                }
            }

            return sb.ToString();
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        }
    }
}
