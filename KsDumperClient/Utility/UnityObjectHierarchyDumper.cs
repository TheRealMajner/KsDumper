using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class UnityObjectHierarchyDumper
    {
        public class UnityGameObject
        {
            public ulong Address;
            public string Name;
            public int InstanceID;
            public bool IsActive;
            public string Tag;
            public int Layer;
            public List<ComponentInfo> Components = new List<ComponentInfo>();
            public List<UnityGameObject> Children = new List<UnityGameObject>();
            public int Depth;
        }

        public class ComponentInfo
        {
            public ulong Address;
            public string TypeName;
            public ulong KlassPointer;
        }

        public class HierarchyResult
        {
            public List<UnityGameObject> RootObjects = new List<UnityGameObject>();
            public int TotalObjects;
            public int TotalComponents;
            public int MaxDepth;
            public Dictionary<string, int> ComponentCounts = new Dictionary<string, int>();
        }

        // Unity Transform offsets (IL2CPP x64, approximate - varies by version)
        private const int kTransform_GameObject = 0x30;
        private const int kTransform_Parent = 0x38;
        private const int kTransform_Children = 0x40;
        private const int kTransform_ChildCount = 0x50;
        // Alternative offsets for newer Unity versions
        private static readonly int[] kTransform_ChildCountOffsets = { 0x50, 0x48, 0x58, 0x80 };
        private static readonly int[] kTransform_ChildrenOffsets = { 0x40, 0x38, 0x48, 0x70 };
        private static readonly int[] kTransform_ParentOffsets = { 0x38, 0x30, 0x40, 0x68 };

        // GameObject offsets
        private const int kGameObject_Components = 0x30;
        private const int kGameObject_ComponentCount = 0x40;
        private const int kGameObject_Layer = 0x44;
        private const int kGameObject_Name = 0x60;
        private const int kGameObject_IsActive = 0x56;

        public static HierarchyResult DumpHierarchy(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            string filter = null,
            int maxObjects = 2000,
            int maxDepth = 10)
        {
            var result = new HierarchyResult();
            var visited = new HashSet<ulong>();

            // Find Transform class pointers by scanning for known patterns
            var transformPtrs = FindTransformInstances(driver, pid, gaBase, gaSize);

            foreach (var transformAddr in transformPtrs)
            {
                if (result.TotalObjects >= maxObjects) break;
                if (visited.Contains(transformAddr)) continue;

                // Walk up to find root transform
                ulong rootTransform = FindRootTransform(driver, pid, transformAddr, visited);
                if (rootTransform == 0 || visited.Contains(rootTransform)) continue;

                var rootObj = BuildHierarchy(driver, pid, rootTransform, visited, filter, 0, maxDepth, result);
                if (rootObj != null)
                {
                    result.RootObjects.Add(rootObj);
                }
            }

            return result;
        }

        private static List<ulong> FindTransformInstances(IMemoryReader driver, int pid, ulong gaBase, uint gaSize)
        {
            var transforms = new List<ulong>();

            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return transforms;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                if (sName != ".data") continue;

                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                ulong secStart = gaBase + vAddr;
                int readSize = (int)Math.Min(vSize, 0x2000000);

                byte[] data = ReadMemory(driver, pid, secStart, readSize);
                if (data == null) continue;

                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    if (transforms.Count >= 500) break;

                    ulong candidate = BitConverter.ToUInt64(data, i);
                    if (candidate < 0x10000 || candidate > 0x7FFFFFFFFFFF) continue;

                    if (IsLikelyTransform(driver, pid, candidate))
                        transforms.Add(candidate);
                }
            }

            return transforms;
        }

        private static bool IsLikelyTransform(IMemoryReader driver, int pid, ulong addr)
        {
            byte[] data = ReadMemory(driver, pid, addr, 0x90);
            if (data == null) return false;

            // Check klass pointer (offset 0)
            ulong klass = BitConverter.ToUInt64(data, 0);
            if (klass < 0x10000 || klass > 0x7FFFFFFFFFFF) return false;

            // Try to read class name
            ulong namePtr = ReadPtr(driver, pid, klass + 0x10);
            if (namePtr == 0) return false;
            string name = ReadCString(driver, pid, namePtr, 64);
            if (name != "Transform" && name != "RectTransform") return false;

            return true;
        }

        private static ulong FindRootTransform(IMemoryReader driver, int pid, ulong transformAddr, HashSet<ulong> visited)
        {
            ulong current = transformAddr;
            int maxWalk = 50;

            while (maxWalk-- > 0)
            {
                byte[] data = ReadMemory(driver, pid, current, 0x60);
                if (data == null) return current;

                ulong parent = 0;
                foreach (int parentOff in kTransform_ParentOffsets)
                {
                    if (parentOff + 8 <= data.Length)
                    {
                        ulong candidate = BitConverter.ToUInt64(data, parentOff);
                        if (candidate >= 0x10000 && candidate < 0x7FFFFFFFFFFF && candidate != current)
                        {
                            parent = candidate;
                            break;
                        }
                    }
                }

                if (parent == 0 || parent == current) return current;
                current = parent;
            }

            return current;
        }

        private static UnityGameObject BuildHierarchy(
            IMemoryReader driver, int pid, ulong transformAddr,
            HashSet<ulong> visited, string filter,
            int depth, int maxDepth, HierarchyResult result)
        {
            if (visited.Contains(transformAddr)) return null;
            if (depth > maxDepth) return null;
            visited.Add(transformAddr);

            byte[] tData = ReadMemory(driver, pid, transformAddr, 0x90);
            if (tData == null) return null;

            // Read the GameObject pointer
            ulong goPtr = 0;
            if (kTransform_GameObject + 8 <= tData.Length)
                goPtr = BitConverter.ToUInt64(tData, kTransform_GameObject);

            string objName = "?";
            bool isActive = true;
            int layer = 0;

            if (goPtr != 0 && goPtr >= 0x10000 && goPtr < 0x7FFFFFFFFFFF)
            {
                byte[] goData = ReadMemory(driver, pid, goPtr, 0x70);
                if (goData != null)
                {
                    ulong namePtr = BitConverter.ToUInt64(goData, kGameObject_Name);
                    if (namePtr != 0 && namePtr >= 0x10000)
                    {
                        // Unity managed string: length at +0x10, chars at +0x14
                        byte[] strHeader = ReadMemory(driver, pid, namePtr, 0x40);
                        if (strHeader != null)
                        {
                            int strLen = BitConverter.ToInt32(strHeader, 0x10);
                            if (strLen > 0 && strLen < 200)
                            {
                                byte[] chars = new byte[strLen * 2];
                                if (strLen * 2 + 0x14 <= strHeader.Length)
                                    Buffer.BlockCopy(strHeader, 0x14, chars, 0, strLen * 2);
                                else
                                {
                                    byte[] full = ReadMemory(driver, pid, namePtr + 0x14, strLen * 2);
                                    if (full != null) chars = full;
                                }
                                objName = Encoding.Unicode.GetString(chars, 0, Math.Min(chars.Length, strLen * 2));
                            }
                        }
                    }

                    if (kGameObject_IsActive < goData.Length)
                        isActive = goData[kGameObject_IsActive] != 0;
                    if (kGameObject_Layer + 4 <= goData.Length)
                        layer = BitConverter.ToInt32(goData, kGameObject_Layer);
                }
            }

            if (!string.IsNullOrEmpty(filter) &&
                objName.IndexOf(filter, StringComparison.OrdinalIgnoreCase) < 0 && depth == 0)
                return null;

            var gameObj = new UnityGameObject
            {
                Address = transformAddr,
                Name = objName,
                IsActive = isActive,
                Layer = layer,
                Depth = depth
            };

            result.TotalObjects++;
            if (depth > result.MaxDepth) result.MaxDepth = depth;

            // Try to find children
            foreach (int childCountOff in kTransform_ChildCountOffsets)
            {
                if (childCountOff + 4 > tData.Length) continue;
                int childCount = BitConverter.ToInt32(tData, childCountOff);
                if (childCount < 0 || childCount > 500) continue;

                int childrenOff = kTransform_ChildrenOffsets[Array.IndexOf(kTransform_ChildCountOffsets, childCountOff)];
                if (childrenOff + 8 > tData.Length) continue;

                ulong childrenPtr = BitConverter.ToUInt64(tData, childrenOff);
                if (childrenPtr == 0 || childrenPtr < 0x10000) continue;

                byte[] childPtrs = ReadMemory(driver, pid, childrenPtr, childCount * 8);
                if (childPtrs == null) continue;

                bool validChildren = false;
                for (int c = 0; c < childCount; c++)
                {
                    ulong childTransform = BitConverter.ToUInt64(childPtrs, c * 8);
                    if (childTransform == 0 || childTransform < 0x10000) continue;

                    var child = BuildHierarchy(driver, pid, childTransform, visited, null, depth + 1, maxDepth, result);
                    if (child != null)
                    {
                        gameObj.Children.Add(child);
                        validChildren = true;
                    }
                }
                if (validChildren) break;
            }

            return gameObj;
        }

        public static string GenerateReport(HierarchyResult result)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Unity Object Hierarchy Dump");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Root objects: {result.RootObjects.Count}");
            sb.AppendLine($"// Total objects: {result.TotalObjects}");
            sb.AppendLine($"// Max depth: {result.MaxDepth}");
            sb.AppendLine();

            foreach (var root in result.RootObjects.OrderBy(r => r.Name))
            {
                PrintObject(sb, root, 0);
            }

            return sb.ToString();
        }

        private static void PrintObject(StringBuilder sb, UnityGameObject obj, int indent)
        {
            string prefix = new string(' ', indent * 2);
            string active = obj.IsActive ? "" : " [INACTIVE]";
            sb.AppendLine($"{prefix}{obj.Name} (0x{obj.Address:X}) layer:{obj.Layer}{active}");

            foreach (var child in obj.Children.OrderBy(c => c.Name))
            {
                PrintObject(sb, child, indent + 1);
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
