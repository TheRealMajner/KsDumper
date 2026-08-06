using System;
using System.Collections.Generic;
using System.IO;

namespace KsDumperClient.Utility
{
    public static class EngineDetector
    {
        public enum GameEngine
        {
            Unknown,
            UnityIl2Cpp,
            UnityMono,
            Unreal,
            SourceEngine,
            Frostbite,
            CryEngine
        }

        public struct DetectionResult
        {
            public GameEngine Engine;
            public List<string> IndicatorModules;
            public string Details;
        }

        // Known module signatures for each engine
        private static readonly Dictionary<GameEngine, string[]> EngineSignatures = new Dictionary<GameEngine, string[]>
        {
            { GameEngine.UnityIl2Cpp, new[] { "gameassembly.dll", "unityplayer.dll", "il2cpp.dll" } },
            { GameEngine.UnityMono,   new[] { "mono.dll", "mono-2.0-bdwgc.dll", "unityplayer.dll" } },
            { GameEngine.Unreal,      new[] { "unrealengine", "ue4", "ue5", "engine.dll" } },
            { GameEngine.SourceEngine,new[] { "engine.dll", "tier0.dll", "vstdlib.dll", "materialsystem.dll" } },
            { GameEngine.Frostbite,   new[] { "frostbite", "ea_desktop", "eadp.dll" } },
            { GameEngine.CryEngine,   new[] { "cryengine", "crysystem.dll", "cryrender.dll" } },
        };

        public static DetectionResult Detect(ModuleSummary[] modules)
        {
            var indicators = new Dictionary<GameEngine, List<string>>();

            foreach (var mod in modules)
            {
                string name = (mod.ModuleName ?? "").ToLowerInvariant();

                foreach (var kvp in EngineSignatures)
                {
                    foreach (var sig in kvp.Value)
                    {
                        if (name.Contains(sig))
                        {
                            if (!indicators.ContainsKey(kvp.Key))
                                indicators[kvp.Key] = new List<string>();
                            indicators[kvp.Key].Add(mod.ModuleName);
                        }
                    }
                }
            }

            // Determine best match (most indicators wins)
            GameEngine bestEngine = GameEngine.Unknown;
            int bestCount = 0;
            List<string> bestModules = new List<string>();

            foreach (var kvp in indicators)
            {
                if (kvp.Value.Count > bestCount)
                {
                    bestCount = kvp.Value.Count;
                    bestEngine = kvp.Key;
                    bestModules = kvp.Value;
                }
            }

            string details = bestEngine == GameEngine.Unknown
                ? "No known game engine detected"
                : $"{bestEngine} detected via {bestCount} indicator module(s)";

            return new DetectionResult
            {
                Engine = bestEngine,
                IndicatorModules = bestModules,
                Details = details
            };
        }

        public static bool IsUnityIl2Cpp(DetectionResult result)
        {
            return result.Engine == GameEngine.UnityIl2Cpp;
        }

        public static bool IsUnityMono(DetectionResult result)
        {
            return result.Engine == GameEngine.UnityMono;
        }

        private static readonly HashSet<string> KnownManagedAssemblyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Assembly-CSharp.dll", "Assembly-CSharp-firstpass.dll",
            "UnityEngine.dll", "UnityEngine.CoreModule.dll",
            "UnityEngine.UI.dll", "UnityEngine.Networking.dll",
            "UnityEngine.AnimationModule.dll", "UnityEngine.PhysicsModule.dll",
            "UnityEngine.InputLegacyModule.dll", "UnityEngine.IMGUIModule.dll",
            "UnityEngine.AudioModule.dll", "UnityEngine.RenderingModule.dll",
            "UnityEngine.TextRenderingModule.dll", "UnityEngine.UnityWebRequestModule.dll",
            "UnityEngine.AssetBundleModule.dll", "UnityEngine.JSONSerializeModule.dll",
            "mscorlib.dll", "System.dll", "System.Core.dll",
            "Mono.Security.dll", "netstandard.dll",
            "Unity.TextMeshPro.dll", "Cinemachine.dll",
            "DOTween.dll", "Newtonsoft.Json.dll",
            "Unity.Addressables.dll", "Unity.ResourceManager.dll"
        };

        public static List<ModuleSummary> FindManagedAssemblies(ModuleSummary[] modules)
        {
            var result = new List<ModuleSummary>();
            foreach (var mod in modules)
            {
                if (KnownManagedAssemblyNames.Contains(mod.ModuleName) ||
                    (mod.FileName != null && mod.FileName.IndexOf("_Data\\Managed\\", StringComparison.OrdinalIgnoreCase) >= 0) ||
                    (mod.FileName != null && mod.FileName.IndexOf("_Data/Managed/", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    result.Add(mod);
                }
            }
            return result;
        }
    }
}
