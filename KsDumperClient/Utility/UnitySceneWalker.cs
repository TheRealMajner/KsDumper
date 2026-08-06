using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class UnitySceneWalker
    {
        public class GameObjectInfo
        {
            public ulong Address;
            public string Name;
            public int Layer;
            public bool Active;
            public string Tag;
            public ulong TransformAddress;
            public List<ComponentInfo> Components = new List<ComponentInfo>();
            public List<GameObjectInfo> Children = new List<GameObjectInfo>();
        }

        public class ComponentInfo
        {
            public ulong Address;
            public string TypeName;
            public bool Enabled;
        }

        public class SceneInfo
        {
            public string SceneName;
            public int RootObjectCount;
            public int TotalObjectCount;
            public int TotalComponentCount;
            public List<GameObjectInfo> RootObjects = new List<GameObjectInfo>();
        }

        // Unity runtime offsets (x64, varies by version)
        // These are common offsets for Unity 2019-2022
        private const int kGameObject_Name = 0x60;        // +0x60: char* name (pointer to string)
        private const int kGameObject_Layer = 0x50;        // +0x50: int layer
        private const int kGameObject_Active = 0x56;       // +0x56: byte active
        private const int kGameObject_Tag = 0x54;          // +0x54: ushort tag
        private const int kGameObject_ComponentCount = 0x40; // +0x40 or nearby
        private const int kGameObject_Components = 0x30;    // +0x30: Component** array

        private const int kTransform_Children = 0x70;      // +0x70: TransformData
        private const int kTransform_Parent = 0x48;         // +0x48: Transform* parent
        private const int kTransform_ChildCount = 0x80;     // +0x80: int childCount
        private const int kTransform_ChildArray = 0x70;     // Children stored as pointer array

        // Il2CppClass* at obj+0x00, then klass->name at klass+0x10
        private const int kObject_Klass = 0x00;
        private const int kClass_Name = 0x10;
        private const int kClass_Namespace = 0x18;

        public static SceneInfo WalkScene(
            IMemoryReader driver, int pid,
            ulong unityPlayerBase, uint unityPlayerSize,
            int maxObjects = 2000)
        {
            var scene = new SceneInfo();

            // Strategy: Find the GameObject linked list via pattern scanning
            // Unity stores all GameObjects in a global GObjectManager
            // We scan UnityPlayer.dll for the manager pointer

            // Alternative approach: scan for "GameObject" Il2CppClass instances
            // and walk the transform hierarchy
            var gameObjects = FindGameObjects(driver, pid, unityPlayerBase, unityPlayerSize, maxObjects);

            // Build parent-child relationships from transform hierarchy
            var byAddress = new Dictionary<ulong, GameObjectInfo>();
            foreach (var go in gameObjects)
            {
                byAddress[go.Address] = go;
            }

            // Find root objects (no parent transform)
            var roots = new List<GameObjectInfo>();
            var childSet = new HashSet<ulong>();

            foreach (var go in gameObjects)
            {
                if (go.TransformAddress == 0) continue;

                ulong parentTransform = ReadPtr(driver, pid, go.TransformAddress + kTransform_Parent);
                if (parentTransform == 0 || parentTransform == go.TransformAddress)
                {
                    roots.Add(go);
                }
                else
                {
                    // Find parent GO by scanning who owns this parent transform
                    foreach (var candidate in gameObjects)
                    {
                        if (candidate.TransformAddress == parentTransform && candidate.Address != go.Address)
                        {
                            candidate.Children.Add(go);
                            childSet.Add(go.Address);
                            break;
                        }
                    }
                }
            }

            // Objects not linked as children are also roots
            foreach (var go in gameObjects)
            {
                if (!childSet.Contains(go.Address) && !roots.Contains(go))
                    roots.Add(go);
            }

            scene.RootObjects = roots;
            scene.RootObjectCount = roots.Count;
            scene.TotalObjectCount = gameObjects.Count;
            scene.TotalComponentCount = gameObjects.Sum(g => g.Components.Count);

            return scene;
        }

        private static List<GameObjectInfo> FindGameObjects(
            IMemoryReader driver, int pid,
            ulong moduleBase, uint moduleSize,
            int maxObjects)
        {
            var result = new List<GameObjectInfo>();

            // Scan memory regions for GameObject-like structures
            var regions = driver.EnumRegions(pid);
            if (regions == null) return result;

            // Filter to heap-like committed private regions
            var heapRegions = regions
                .Where(r => r.state == 0x1000 && r.regionSize >= 0x1000 && r.regionSize <= 0x1000000)
                .Where(r => (r.protect & 0x04) != 0 || (r.protect & 0x40) != 0) // PAGE_READWRITE or PAGE_EXECUTE_READWRITE
                .OrderByDescending(r => r.regionSize)
                .Take(200)
                .ToList();

            foreach (var (baseAddr, regionSize, protect, state, type) in heapRegions)
            {
                if (result.Count >= maxObjects) break;

                int readSize = (int)Math.Min(regionSize, 0x200000);
                byte[] data = ReadMemory(driver, pid, baseAddr, readSize);
                if (data == null) continue;

                // Scan for potential GameObject pointers
                // A GameObject has: klass pointer (valid), then specific structure
                for (int i = 0; i <= data.Length - 0x68; i += 8)
                {
                    if (result.Count >= maxObjects) break;

                    ulong klassPtr = BitConverter.ToUInt64(data, i);
                    if (klassPtr < 0x10000 || klassPtr > 0x7FFFFFFFFFFF) continue;

                    // Read klass->name to check if this is a "GameObject"
                    ulong namePtr = ReadPtr(driver, pid, klassPtr + kClass_Name);
                    if (namePtr == 0) continue;

                    string className = ReadCString(driver, pid, namePtr, 32);
                    if (className != "GameObject" && className != "Transform") continue;

                    ulong objAddr = baseAddr + (ulong)i;

                    if (className == "GameObject")
                    {
                        var go = ReadGameObject(driver, pid, objAddr);
                        if (go != null && !string.IsNullOrEmpty(go.Name))
                        {
                            result.Add(go);
                        }
                    }
                }
            }

            return result;
        }

        private static GameObjectInfo ReadGameObject(IMemoryReader driver, int pid, ulong address)
        {
            var go = new GameObjectInfo { Address = address };

            // Read name
            ulong namePtr = ReadPtr(driver, pid, address + kGameObject_Name);
            if (namePtr != 0)
                go.Name = ReadCString(driver, pid, namePtr, 128);

            if (string.IsNullOrEmpty(go.Name)) return null;

            // Read layer and active state
            byte[] headerData = ReadMemory(driver, pid, address + (ulong)kGameObject_Layer, 8);
            if (headerData != null)
            {
                go.Layer = BitConverter.ToInt32(headerData, 0);
                go.Active = headerData[6] != 0;
            }

            // Read transform
            // The transform is typically the first component
            ulong componentArray = ReadPtr(driver, pid, address + kGameObject_Components);
            if (componentArray != 0)
            {
                // First component pointer → usually Transform
                ulong firstComp = ReadPtr(driver, pid, componentArray);
                if (firstComp != 0)
                {
                    ulong compKlass = ReadPtr(driver, pid, firstComp + kObject_Klass);
                    if (compKlass != 0)
                    {
                        ulong compNamePtr = ReadPtr(driver, pid, compKlass + kClass_Name);
                        string compName = compNamePtr != 0 ? ReadCString(driver, pid, compNamePtr, 32) : "";
                        if (compName == "Transform" || compName == "RectTransform")
                            go.TransformAddress = firstComp;
                    }
                }
            }

            return go;
        }

        public static string GenerateSceneTree(SceneInfo scene, int maxDepth = 10)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Unity Scene Hierarchy");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Root objects: {scene.RootObjectCount}");
            sb.AppendLine($"// Total objects: {scene.TotalObjectCount}");
            sb.AppendLine($"// Total components: {scene.TotalComponentCount}");
            sb.AppendLine();

            foreach (var root in scene.RootObjects.OrderBy(r => r.Name))
            {
                PrintGameObject(sb, root, 0, maxDepth);
            }

            return sb.ToString();
        }

        private static void PrintGameObject(StringBuilder sb, GameObjectInfo go, int depth, int maxDepth)
        {
            if (depth > maxDepth) return;

            string indent = new string(' ', depth * 2);
            string active = go.Active ? "" : " [inactive]";
            string layer = go.Layer != 0 ? $" (layer:{go.Layer})" : "";

            sb.AppendLine($"{indent}- {go.Name}{active}{layer} @ 0x{go.Address:X}");

            foreach (var comp in go.Components)
            {
                string enabled = comp.Enabled ? "" : " [disabled]";
                sb.AppendLine($"{indent}  [{comp.TypeName}{enabled}]");
            }

            foreach (var child in go.Children.OrderBy(c => c.Name))
            {
                PrintGameObject(sb, child, depth + 1, maxDepth);
            }
        }

        public static string SearchObjects(SceneInfo scene, string search)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"// Search results for: \"{search}\"");
            sb.AppendLine();

            var matches = FlattenTree(scene.RootObjects)
                .Where(go => go.Name != null && go.Name.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0)
                .ToList();

            sb.AppendLine($"// Found {matches.Count} matching objects");
            sb.AppendLine();

            foreach (var go in matches)
            {
                string active = go.Active ? "" : " [inactive]";
                sb.AppendLine($"  {go.Name}{active} @ 0x{go.Address:X} (layer:{go.Layer})");
                foreach (var comp in go.Components)
                    sb.AppendLine($"    [{comp.TypeName}]");
            }

            return sb.ToString();
        }

        private static IEnumerable<GameObjectInfo> FlattenTree(List<GameObjectInfo> roots)
        {
            foreach (var root in roots)
            {
                yield return root;
                foreach (var child in FlattenTree(root.Children))
                    yield return child;
            }
        }

        private static byte[] ReadMemory(IMemoryReader driver, int pid, ulong address, int size)
        {
            byte[] buf = new byte[size];
            GCHandle handle = GCHandle.Alloc(buf, GCHandleType.Pinned);
            try
            {
                if (!driver.CopyVirtualMemory(pid, (IntPtr)(long)address, handle.AddrOfPinnedObject(), size))
                    return null;
                return buf;
            }
            finally { handle.Free(); }
        }

        private static ulong ReadPtr(IMemoryReader driver, int pid, ulong address)
        {
            byte[] buf = ReadMemory(driver, pid, address, 8);
            if (buf == null) return 0;
            return BitConverter.ToUInt64(buf, 0);
        }

        private static string ReadCString(IMemoryReader driver, int pid, ulong address, int maxLen)
        {
            byte[] buf = ReadMemory(driver, pid, address, maxLen);
            if (buf == null) return null;
            int len = Array.IndexOf(buf, (byte)0);
            if (len < 0) len = maxLen;
            if (len == 0) return "";
            try { return Encoding.UTF8.GetString(buf, 0, len); }
            catch { return null; }
        }
    }
}
