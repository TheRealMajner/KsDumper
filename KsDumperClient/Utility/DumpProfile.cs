using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace KsDumperClient.Utility
{
    public class DumpProfile
    {
        public string Name;
        public string GameExecutable;
        public string EngineType; // "il2cpp", "mono", "unreal", "unknown"
        public DateTime Created;
        public DateTime LastUsed;
        public int DumpCount;

        // Module configuration
        public List<string> ModulesToDump = new List<string>();
        public List<string> ModulesToSkip = new List<string>();

        // Feature flags
        public bool DumpMetadata = true;
        public bool GenerateSDK = true;
        public bool GenerateScripts = true;
        public bool ExtractStrings = true;
        public bool ResolveRuntime = true;
        public bool DetectAntiCheat = true;
        public bool ReconstructImports = false;
        public bool ScanInstances = false;
        public bool BuildCallGraph = false;
        public bool ExportReClass = false;
        public bool FridaScripts = false;

        // Anti-cheat workarounds
        public string AntiCheatType;
        public bool DelayedDump;
        public int DelayMs;
        public bool UseStealthRead;

        // Known offsets (survive game updates until changed)
        public Dictionary<string, ulong> KnownOffsets = new Dictionary<string, ulong>();
        public Dictionary<string, string> KnownModuleHashes = new Dictionary<string, string>();

        // Instance scan targets
        public List<string> InstanceScanClasses = new List<string>();

        // Output settings
        public string OutputDirectory;
        public bool OverwriteExisting = true;
        public string NamingPattern = "{game}_{date}";

        public static string ProfilesDirectory
        {
            get
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "KsDumper", "Profiles");
                if (!Directory.Exists(dir))
                    Directory.CreateDirectory(dir);
                return dir;
            }
        }

        public static DumpProfile CreateDefault(string gameName, string engineType)
        {
            return new DumpProfile
            {
                Name = gameName,
                GameExecutable = gameName,
                EngineType = engineType,
                Created = DateTime.Now,
                LastUsed = DateTime.Now,
                DumpCount = 0,
                OutputDirectory = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    "KsDumper", gameName)
            };
        }

        public void Save()
        {
            string path = Path.Combine(ProfilesDirectory, SanitizeFileName(Name) + ".ksdump");
            var sb = new StringBuilder();

            sb.AppendLine("[Profile]");
            sb.AppendLine($"Name={Name}");
            sb.AppendLine($"GameExecutable={GameExecutable}");
            sb.AppendLine($"EngineType={EngineType}");
            sb.AppendLine($"Created={Created:o}");
            sb.AppendLine($"LastUsed={LastUsed:o}");
            sb.AppendLine($"DumpCount={DumpCount}");
            sb.AppendLine();

            sb.AppendLine("[Modules]");
            sb.AppendLine($"Dump={string.Join(",", ModulesToDump)}");
            sb.AppendLine($"Skip={string.Join(",", ModulesToSkip)}");
            sb.AppendLine();

            sb.AppendLine("[Features]");
            sb.AppendLine($"DumpMetadata={DumpMetadata}");
            sb.AppendLine($"GenerateSDK={GenerateSDK}");
            sb.AppendLine($"GenerateScripts={GenerateScripts}");
            sb.AppendLine($"ExtractStrings={ExtractStrings}");
            sb.AppendLine($"ResolveRuntime={ResolveRuntime}");
            sb.AppendLine($"DetectAntiCheat={DetectAntiCheat}");
            sb.AppendLine($"ReconstructImports={ReconstructImports}");
            sb.AppendLine($"ScanInstances={ScanInstances}");
            sb.AppendLine($"BuildCallGraph={BuildCallGraph}");
            sb.AppendLine($"ExportReClass={ExportReClass}");
            sb.AppendLine($"FridaScripts={FridaScripts}");
            sb.AppendLine();

            sb.AppendLine("[AntiCheat]");
            sb.AppendLine($"Type={AntiCheatType ?? "none"}");
            sb.AppendLine($"DelayedDump={DelayedDump}");
            sb.AppendLine($"DelayMs={DelayMs}");
            sb.AppendLine($"UseStealthRead={UseStealthRead}");
            sb.AppendLine();

            sb.AppendLine("[Offsets]");
            foreach (var kvp in KnownOffsets)
                sb.AppendLine($"{kvp.Key}=0x{kvp.Value:X}");
            sb.AppendLine();

            sb.AppendLine("[Hashes]");
            foreach (var kvp in KnownModuleHashes)
                sb.AppendLine($"{kvp.Key}={kvp.Value}");
            sb.AppendLine();

            sb.AppendLine("[InstanceScan]");
            sb.AppendLine($"Classes={string.Join(",", InstanceScanClasses)}");
            sb.AppendLine();

            sb.AppendLine("[Output]");
            sb.AppendLine($"Directory={OutputDirectory}");
            sb.AppendLine($"OverwriteExisting={OverwriteExisting}");
            sb.AppendLine($"NamingPattern={NamingPattern}");

            File.WriteAllText(path, sb.ToString());
        }

        public static DumpProfile Load(string name)
        {
            string path = Path.Combine(ProfilesDirectory, SanitizeFileName(name) + ".ksdump");
            if (!File.Exists(path)) return null;
            return LoadFromFile(path);
        }

        public static DumpProfile LoadFromFile(string path)
        {
            if (!File.Exists(path)) return null;

            var profile = new DumpProfile();
            string currentSection = "";

            foreach (string rawLine in File.ReadAllLines(path))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith("#")) continue;

                if (line.StartsWith("[") && line.EndsWith("]"))
                {
                    currentSection = line.Substring(1, line.Length - 2);
                    continue;
                }

                int eq = line.IndexOf('=');
                if (eq < 0) continue;
                string key = line.Substring(0, eq).Trim();
                string val = line.Substring(eq + 1).Trim();

                switch (currentSection)
                {
                    case "Profile":
                        switch (key)
                        {
                            case "Name": profile.Name = val; break;
                            case "GameExecutable": profile.GameExecutable = val; break;
                            case "EngineType": profile.EngineType = val; break;
                            case "Created": DateTime.TryParse(val, out profile.Created); break;
                            case "LastUsed": DateTime.TryParse(val, out profile.LastUsed); break;
                            case "DumpCount": int.TryParse(val, out profile.DumpCount); break;
                        }
                        break;

                    case "Modules":
                        if (key == "Dump" && !string.IsNullOrEmpty(val))
                            profile.ModulesToDump = val.Split(',').Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
                        if (key == "Skip" && !string.IsNullOrEmpty(val))
                            profile.ModulesToSkip = val.Split(',').Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
                        break;

                    case "Features":
                        switch (key)
                        {
                            case "DumpMetadata": bool.TryParse(val, out profile.DumpMetadata); break;
                            case "GenerateSDK": bool.TryParse(val, out profile.GenerateSDK); break;
                            case "GenerateScripts": bool.TryParse(val, out profile.GenerateScripts); break;
                            case "ExtractStrings": bool.TryParse(val, out profile.ExtractStrings); break;
                            case "ResolveRuntime": bool.TryParse(val, out profile.ResolveRuntime); break;
                            case "DetectAntiCheat": bool.TryParse(val, out profile.DetectAntiCheat); break;
                            case "ReconstructImports": bool.TryParse(val, out profile.ReconstructImports); break;
                            case "ScanInstances": bool.TryParse(val, out profile.ScanInstances); break;
                            case "BuildCallGraph": bool.TryParse(val, out profile.BuildCallGraph); break;
                            case "ExportReClass": bool.TryParse(val, out profile.ExportReClass); break;
                            case "FridaScripts": bool.TryParse(val, out profile.FridaScripts); break;
                        }
                        break;

                    case "AntiCheat":
                        switch (key)
                        {
                            case "Type": profile.AntiCheatType = val == "none" ? null : val; break;
                            case "DelayedDump": bool.TryParse(val, out profile.DelayedDump); break;
                            case "DelayMs": int.TryParse(val, out profile.DelayMs); break;
                            case "UseStealthRead": bool.TryParse(val, out profile.UseStealthRead); break;
                        }
                        break;

                    case "Offsets":
                        if (val.StartsWith("0x") && ulong.TryParse(val.Substring(2), System.Globalization.NumberStyles.HexNumber, null, out ulong offsetVal))
                            profile.KnownOffsets[key] = offsetVal;
                        break;

                    case "Hashes":
                        profile.KnownModuleHashes[key] = val;
                        break;

                    case "InstanceScan":
                        if (key == "Classes" && !string.IsNullOrEmpty(val))
                            profile.InstanceScanClasses = val.Split(',').Where(s => !string.IsNullOrWhiteSpace(s)).ToList();
                        break;

                    case "Output":
                        switch (key)
                        {
                            case "Directory": profile.OutputDirectory = val; break;
                            case "OverwriteExisting": bool.TryParse(val, out profile.OverwriteExisting); break;
                            case "NamingPattern": profile.NamingPattern = val; break;
                        }
                        break;
                }
            }

            return profile;
        }

        public static List<DumpProfile> ListProfiles()
        {
            var profiles = new List<DumpProfile>();
            string dir = ProfilesDirectory;

            foreach (string file in Directory.GetFiles(dir, "*.ksdump"))
            {
                var p = LoadFromFile(file);
                if (p != null) profiles.Add(p);
            }

            return profiles.OrderByDescending(p => p.LastUsed).ToList();
        }

        public static bool DeleteProfile(string name)
        {
            string path = Path.Combine(ProfilesDirectory, SanitizeFileName(name) + ".ksdump");
            if (!File.Exists(path)) return false;
            File.Delete(path);
            return true;
        }

        public string GetOutputPath()
        {
            string dir = OutputDirectory;
            if (string.IsNullOrEmpty(dir))
                dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), "KsDumper", Name);

            string folderName = NamingPattern
                .Replace("{game}", SanitizeFileName(Name))
                .Replace("{date}", DateTime.Now.ToString("yyyyMMdd_HHmmss"));

            return Path.Combine(dir, folderName);
        }

        public void MarkUsed()
        {
            LastUsed = DateTime.Now;
            DumpCount++;
        }

        public string GenerateSummary()
        {
            var sb = new StringBuilder();
            sb.AppendLine($"Profile: {Name}");
            sb.AppendLine($"  Game: {GameExecutable}");
            sb.AppendLine($"  Engine: {EngineType}");
            sb.AppendLine($"  Created: {Created:yyyy-MM-dd}");
            sb.AppendLine($"  Last used: {LastUsed:yyyy-MM-dd HH:mm}");
            sb.AppendLine($"  Dump count: {DumpCount}");

            var features = new List<string>();
            if (DumpMetadata) features.Add("metadata");
            if (GenerateSDK) features.Add("SDK");
            if (GenerateScripts) features.Add("scripts");
            if (ExtractStrings) features.Add("strings");
            if (ResolveRuntime) features.Add("runtime");
            if (DetectAntiCheat) features.Add("anti-cheat");
            if (ReconstructImports) features.Add("imports");
            if (ScanInstances) features.Add("instances");
            if (BuildCallGraph) features.Add("callgraph");
            if (ExportReClass) features.Add("ReClass");
            if (FridaScripts) features.Add("Frida");
            sb.AppendLine($"  Features: {string.Join(", ", features)}");

            if (!string.IsNullOrEmpty(AntiCheatType))
                sb.AppendLine($"  Anti-cheat: {AntiCheatType} (delay: {DelayMs}ms, stealth: {UseStealthRead})");

            if (KnownOffsets.Count > 0)
            {
                sb.AppendLine($"  Known offsets: {KnownOffsets.Count}");
                foreach (var kvp in KnownOffsets.Take(5))
                    sb.AppendLine($"    {kvp.Key} = 0x{kvp.Value:X}");
            }

            if (InstanceScanClasses.Count > 0)
                sb.AppendLine($"  Instance targets: {string.Join(", ", InstanceScanClasses)}");

            return sb.ToString();
        }

        private static string SanitizeFileName(string name)
        {
            char[] invalid = Path.GetInvalidFileNameChars();
            var sb = new StringBuilder();
            foreach (char c in name)
            {
                if (Array.IndexOf(invalid, c) >= 0)
                    sb.Append('_');
                else
                    sb.Append(c);
            }
            return sb.ToString();
        }
    }
}
