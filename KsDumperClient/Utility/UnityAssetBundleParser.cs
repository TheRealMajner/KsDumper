using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace KsDumperClient.Utility
{
    public static class UnityAssetBundleParser
    {
        public class AssetBundleHeader
        {
            public string Signature; // UnityFS, UnityWeb, UnityRaw, UnityArchive
            public int FormatVersion;
            public string UnityVersion;
            public string GeneratorVersion;
            public long FileSize;
            public int CompressedBlocksInfoSize;
            public int UncompressedBlocksInfoSize;
            public uint Flags;
        }

        public class AssetInfo
        {
            public string Name;
            public long Offset;
            public long Size;
            public int TypeId;
            public string TypeName;
        }

        public class AssetBundleInfo
        {
            public AssetBundleHeader Header;
            public List<AssetInfo> Assets = new List<AssetInfo>();
            public bool IsValid;
            public string Error;
        }

        private static readonly Dictionary<int, string> KnownTypeIds = new Dictionary<int, string>
        {
            { 1, "GameObject" }, { 2, "Component" }, { 3, "LevelGameManager" },
            { 4, "Transform" }, { 5, "TimeManager" }, { 6, "GlobalGameManager" },
            { 20, "Camera" }, { 21, "Material" }, { 23, "MeshRenderer" },
            { 25, "Renderer" }, { 27, "Texture" }, { 28, "Texture2D" },
            { 29, "OcclusionCullingSettings" }, { 33, "MeshFilter" },
            { 43, "Mesh" }, { 48, "Shader" }, { 49, "TextAsset" },
            { 54, "Rigidbody2D" }, { 56, "Collider2D" }, { 58, "CircleCollider2D" },
            { 61, "BoxCollider2D" }, { 65, "PhysicsMaterial2D" },
            { 72, "ComputeShader" }, { 74, "AnimationClip" },
            { 82, "AudioSource" }, { 83, "AudioClip" }, { 84, "RenderTexture" },
            { 86, "CustomRenderTexture" }, { 89, "Cubemap" },
            { 90, "Avatar" }, { 91, "AnimatorController" }, { 95, "Animator" },
            { 96, "TrailRenderer" }, { 102, "SortingGroup" },
            { 104, "CanvasRenderer" }, { 108, "Canvas" },
            { 111, "Animation" }, { 114, "MonoBehaviour" },
            { 115, "MonoScript" }, { 120, "LineRenderer" },
            { 128, "Font" }, { 131, "GUIText" }, { 134, "PhysicMaterial" },
            { 135, "SphereCollider" }, { 136, "CapsuleCollider" },
            { 137, "SkinnedMeshRenderer" }, { 141, "BuildSettings" },
            { 142, "AssetBundle" }, { 143, "NavMeshAgent" },
            { 144, "NavMeshSettings" }, { 150, "PreloadData" },
            { 152, "MovieTexture" }, { 153, "ParticleSystem" },
            { 154, "ParticleSystemRenderer" }, { 156, "Terrain" },
            { 157, "TerrainCollider" }, { 158, "TerrainData" },
            { 183, "BoxCollider" }, { 184, "MeshCollider" },
            { 187, "CharacterController" }, { 188, "CharacterJoint" },
            { 192, "Light" }, { 194, "LightmapSettings" },
            { 196, "NavMeshObstacle" }, { 198, "Flare" },
            { 199, "FlareLayer" }, { 200, "HaloLayer" },
            { 210, "RenderSettings" }, { 213, "Sprite" },
            { 218, "Terrain" }, { 220, "LightProbeGroup" },
            { 221, "AnimatorOverrideController" }, { 224, "RectTransform" },
            { 225, "SpriteRenderer" }, { 226, "WheelCollider" },
            { 228, "WindZone" }, { 229, "HingeJoint2D" },
            { 241, "ReflectionProbe" }, { 258, "LightProbeProxyVolume" },
            { 271, "VideoPlayer" }, { 290, "VisualEffect" },
            { 319, "SpriteMask" }, { 328, "TilemapRenderer" },
            { 329, "Tilemap" }, { 331, "SpriteAtlas" },
        };

        public static AssetBundleInfo ParseFromMemory(byte[] data, ulong baseAddress = 0)
        {
            var info = new AssetBundleInfo();

            if (data == null || data.Length < 32)
            {
                info.Error = "Data too small";
                return info;
            }

            try
            {
                int p = 0;
                info.Header = new AssetBundleHeader();

                // Read null-terminated signature
                info.Header.Signature = ReadNullTerminatedString(data, ref p);
                if (info.Header.Signature != "UnityFS" && info.Header.Signature != "UnityWeb" &&
                    info.Header.Signature != "UnityRaw" && info.Header.Signature != "UnityArchive")
                {
                    info.Error = $"Unknown signature: {info.Header.Signature}";
                    return info;
                }

                // Format version (big-endian int32)
                info.Header.FormatVersion = ReadBigEndianInt32(data, ref p);
                info.Header.UnityVersion = ReadNullTerminatedString(data, ref p);
                info.Header.GeneratorVersion = ReadNullTerminatedString(data, ref p);

                if (info.Header.Signature == "UnityFS")
                {
                    // UnityFS header
                    if (p + 24 > data.Length)
                    {
                        info.Error = "Header truncated";
                        info.IsValid = true; // partial parse OK
                        return info;
                    }

                    info.Header.FileSize = ReadBigEndianInt64(data, ref p);
                    info.Header.CompressedBlocksInfoSize = ReadBigEndianInt32(data, ref p);
                    info.Header.UncompressedBlocksInfoSize = ReadBigEndianInt32(data, ref p);
                    info.Header.Flags = (uint)ReadBigEndianInt32(data, ref p);

                    uint compressionType = info.Header.Flags & 0x3F;

                    // If blocks info is at end of file (flag bit 7), we can't easily read it from memory
                    // If uncompressed (type 0), try to parse the directory info
                    if (compressionType == 0 && (info.Header.Flags & 0x80) == 0)
                    {
                        // Blocks info follows header immediately
                        if (p + info.Header.UncompressedBlocksInfoSize <= data.Length)
                        {
                            ParseBlocksInfo(data, p, info);
                        }
                    }
                }

                info.IsValid = true;
            }
            catch (Exception ex)
            {
                info.Error = ex.Message;
            }

            return info;
        }

        public static List<AssetBundleInfo> ScanForBundles(byte[] regionData, ulong regionBase)
        {
            var results = new List<AssetBundleInfo>();

            byte[] unityFS = Encoding.ASCII.GetBytes("UnityFS\0");
            byte[] unityWeb = Encoding.ASCII.GetBytes("UnityWeb\0");
            byte[] unityRaw = Encoding.ASCII.GetBytes("UnityRaw\0");

            for (int i = 0; i <= regionData.Length - 8; i++)
            {
                bool match = false;
                if (MatchBytes(regionData, i, unityFS)) match = true;
                else if (MatchBytes(regionData, i, unityWeb)) match = true;
                else if (MatchBytes(regionData, i, unityRaw)) match = true;

                if (!match) continue;

                int remaining = regionData.Length - i;
                byte[] bundleSlice = new byte[Math.Min(remaining, 0x10000)]; // 64KB slice
                Array.Copy(regionData, i, bundleSlice, 0, bundleSlice.Length);

                var info = ParseFromMemory(bundleSlice, regionBase + (ulong)i);
                if (info.IsValid)
                    results.Add(info);
            }

            return results;
        }

        public static string GenerateReport(List<AssetBundleInfo> bundles)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Unity Asset Bundle Report");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Bundles found: {bundles.Count}");
            sb.AppendLine();

            int idx = 0;
            foreach (var bundle in bundles)
            {
                sb.AppendLine($"=== Bundle #{idx++} ===");
                sb.AppendLine($"  Signature: {bundle.Header.Signature}");
                sb.AppendLine($"  Format Version: {bundle.Header.FormatVersion}");
                sb.AppendLine($"  Unity Version: {bundle.Header.UnityVersion}");
                sb.AppendLine($"  Generator: {bundle.Header.GeneratorVersion}");
                if (bundle.Header.FileSize > 0)
                    sb.AppendLine($"  File Size: {bundle.Header.FileSize:N0} bytes");

                uint comp = bundle.Header.Flags & 0x3F;
                string compName = comp == 0 ? "None" : comp == 1 ? "LZMA" : comp == 2 || comp == 3 ? "LZ4" : $"Unknown ({comp})";
                sb.AppendLine($"  Compression: {compName}");

                if (bundle.Assets.Count > 0)
                {
                    sb.AppendLine($"  Assets: {bundle.Assets.Count}");
                    foreach (var asset in bundle.Assets)
                    {
                        string typeName = asset.TypeName ?? (KnownTypeIds.TryGetValue(asset.TypeId, out var tn) ? tn : $"Type_{asset.TypeId}");
                        sb.AppendLine($"    [{typeName}] {asset.Name} (offset: 0x{asset.Offset:X}, size: {asset.Size:N0})");
                    }
                }

                if (!string.IsNullOrEmpty(bundle.Error))
                    sb.AppendLine($"  Parse note: {bundle.Error}");

                sb.AppendLine();
            }

            return sb.ToString();
        }

        // ===== Internal parsing =====

        private static void ParseBlocksInfo(byte[] data, int offset, AssetBundleInfo info)
        {
            int p = offset;

            // Read uncompressed data hash (16 bytes)
            if (p + 16 > data.Length) return;
            p += 16;

            // Block count
            if (p + 4 > data.Length) return;
            int blockCount = ReadBigEndianInt32(data, ref p);
            if (blockCount < 0 || blockCount > 10000) return;

            // Skip block entries (each: 4 uncompressed + 4 compressed + 2 flags = 10 bytes)
            for (int i = 0; i < blockCount; i++)
            {
                if (p + 10 > data.Length) return;
                p += 10;
            }

            // Node/directory count
            if (p + 4 > data.Length) return;
            int nodeCount = ReadBigEndianInt32(data, ref p);
            if (nodeCount < 0 || nodeCount > 10000) return;

            for (int i = 0; i < nodeCount; i++)
            {
                if (p + 20 > data.Length) return;

                long nodeOffset = ReadBigEndianInt64(data, ref p);
                long nodeSize = ReadBigEndianInt64(data, ref p);
                int nodeFlags = ReadBigEndianInt32(data, ref p);
                string nodeName = ReadNullTerminatedString(data, ref p);

                info.Assets.Add(new AssetInfo
                {
                    Name = nodeName,
                    Offset = nodeOffset,
                    Size = nodeSize,
                    TypeId = nodeFlags & 0xFF
                });
            }
        }

        private static string ReadNullTerminatedString(byte[] data, ref int p)
        {
            int start = p;
            while (p < data.Length && data[p] != 0) p++;
            string result = Encoding.ASCII.GetString(data, start, p - start);
            if (p < data.Length) p++; // skip null
            return result;
        }

        private static int ReadBigEndianInt32(byte[] data, ref int p)
        {
            if (p + 4 > data.Length) { p += 4; return 0; }
            int val = (data[p] << 24) | (data[p + 1] << 16) | (data[p + 2] << 8) | data[p + 3];
            p += 4;
            return val;
        }

        private static long ReadBigEndianInt64(byte[] data, ref int p)
        {
            if (p + 8 > data.Length) { p += 8; return 0; }
            long val = ((long)data[p] << 56) | ((long)data[p + 1] << 48) | ((long)data[p + 2] << 40) | ((long)data[p + 3] << 32) |
                       ((long)data[p + 4] << 24) | ((long)data[p + 5] << 16) | ((long)data[p + 6] << 8) | data[p + 7];
            p += 8;
            return val;
        }

        private static bool MatchBytes(byte[] data, int offset, byte[] pattern)
        {
            if (offset + pattern.Length > data.Length) return false;
            for (int i = 0; i < pattern.Length; i++)
                if (data[offset + i] != pattern[i]) return false;
            return true;
        }
    }
}
