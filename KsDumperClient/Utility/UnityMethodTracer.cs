using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;
using static KsDumperClient.Utility.Il2CppDumper;

namespace KsDumperClient.Utility
{
    public static class UnityMethodTracer
    {
        public class MethodCallEntry
        {
            public ulong CallerAddress;
            public ulong TargetAddress;
            public string CallerName;
            public string TargetName;
            public ulong ReturnAddress;
            public int CallType; // 0=direct, 1=indirect, 2=vtable
        }

        public class CallGraphNode
        {
            public string Name;
            public ulong Address;
            public int IncomingCalls;
            public int OutgoingCalls;
            public List<string> Callers = new List<string>();
            public List<string> Callees = new List<string>();
        }

        public class TraceResult
        {
            public List<MethodCallEntry> Calls = new List<MethodCallEntry>();
            public Dictionary<string, CallGraphNode> Graph = new Dictionary<string, CallGraphNode>();
            public int TotalMethods;
            public int TotalEdges;
            public List<string> HotMethods = new List<string>();
        }

        public static TraceResult BuildCallGraph(
            IMemoryReader driver, int pid,
            ulong gaBase, uint gaSize,
            Il2CppMetadataSnapshot snapshot,
            string focusClass = null,
            int maxMethods = 2000)
        {
            var result = new TraceResult();
            if (snapshot == null) return result;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            // Build method name lookup
            var methodNames = BuildMethodNameMap(snapshot);

            // Build address-to-name map for resolved methods
            var addressToName = new Dictionary<ulong, string>();
            var methodAddresses = new List<(ulong address, string name)>();

            // Get known method RVAs from the Il2CppRuntimeResolver if available
            // Otherwise, scan CodeRegistration for method pointers
            byte[] peHeader = ReadMemory(driver, pid, gaBase, 0x1000);
            if (peHeader == null) return result;

            int peOff = BitConverter.ToInt32(peHeader, 0x3C);
            ushort sectionCount = BitConverter.ToUInt16(peHeader, peOff + 6);
            ushort optHeaderSize = BitConverter.ToUInt16(peHeader, peOff + 20);
            int sectionTableOff = peOff + 24 + optHeaderSize;

            ulong textStart = 0;
            uint textSize = 0;

            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                uint chars = BitConverter.ToUInt32(peHeader, off + 36);
                if ((chars & 0x20000000) != 0 && textStart == 0)
                {
                    textStart = gaBase + vAddr;
                    textSize = vSize;
                }
            }

            if (textStart == 0) return result;

            // Scan .data section for method pointer arrays
            for (int s = 0; s < sectionCount; s++)
            {
                int off = sectionTableOff + s * 40;
                if (off + 40 > peHeader.Length) break;
                string sName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                if (sName != ".data" && sName != ".rdata") continue;

                uint vSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint vAddr = BitConverter.ToUInt32(peHeader, off + 12);
                ulong secStart = gaBase + vAddr;
                int readSize = (int)Math.Min(vSize, 0x2000000);

                byte[] data = ReadMemory(driver, pid, secStart, readSize);
                if (data == null) continue;

                for (int i = 0; i <= data.Length - 8; i += 8)
                {
                    if (methodAddresses.Count >= maxMethods * 2) break;

                    ulong ptr = BitConverter.ToUInt64(data, i);
                    if (ptr >= textStart && ptr < textStart + textSize)
                    {
                        if (!addressToName.ContainsKey(ptr))
                        {
                            int methodIdx = methodAddresses.Count;
                            string name = methodIdx < methodNames.Length
                                ? methodNames[methodIdx]
                                : $"sub_{ptr:X}";

                            addressToName[ptr] = name;
                            methodAddresses.Add((ptr, name));
                        }
                    }
                }
            }

            result.TotalMethods = addressToName.Count;

            // For each method, disassemble and find CALL targets
            var processedMethods = new HashSet<ulong>();
            int processed = 0;

            foreach (var (methodAddr, methodName) in methodAddresses)
            {
                if (processed >= maxMethods) break;

                if (!string.IsNullOrEmpty(focusClass) &&
                    methodName.IndexOf(focusClass, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;

                if (processedMethods.Contains(methodAddr)) continue;
                processedMethods.Add(methodAddr);
                processed++;

                // Read method code (max 4KB)
                byte[] code = ReadMemory(driver, pid, methodAddr, 4096);
                if (code == null) continue;

                // Find CALL instructions
                for (int i = 0; i < code.Length - 5; i++)
                {
                    // E8 rel32 (CALL relative)
                    if (code[i] == 0xE8)
                    {
                        int disp = BitConverter.ToInt32(code, i + 1);
                        ulong target = methodAddr + (ulong)(i + 5) + (ulong)disp;

                        // Check if we hit ret/int3 before this (method ended)
                        if (i > 0 && (code[i - 1] == 0xC3 || code[i - 1] == 0xCC)) break;

                        if (addressToName.TryGetValue(target, out string targetName))
                        {
                            var call = new MethodCallEntry
                            {
                                CallerAddress = methodAddr,
                                TargetAddress = target,
                                CallerName = methodName,
                                TargetName = targetName,
                                ReturnAddress = methodAddr + (ulong)(i + 5),
                                CallType = 0
                            };
                            result.Calls.Add(call);

                            // Build graph nodes
                            EnsureNode(result.Graph, methodName, methodAddr);
                            EnsureNode(result.Graph, targetName, target);
                            result.Graph[methodName].OutgoingCalls++;
                            result.Graph[methodName].Callees.Add(targetName);
                            result.Graph[targetName].IncomingCalls++;
                            result.Graph[targetName].Callers.Add(methodName);
                        }
                    }
                }
            }

            result.TotalEdges = result.Calls.Count;

            // Find hot methods (most incoming calls)
            result.HotMethods = result.Graph.Values
                .OrderByDescending(n => n.IncomingCalls)
                .Take(20)
                .Select(n => $"{n.Name} ({n.IncomingCalls} callers)")
                .ToList();

            return result;
        }

        private static void EnsureNode(Dictionary<string, CallGraphNode> graph, string name, ulong addr)
        {
            if (!graph.ContainsKey(name))
                graph[name] = new CallGraphNode { Name = name, Address = addr };
        }

        public static string GenerateReport(TraceResult result, string search = null)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Unity Method Call Graph");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Methods analyzed: {result.TotalMethods}");
            sb.AppendLine($"// Call edges: {result.TotalEdges}");
            sb.AppendLine($"// Graph nodes: {result.Graph.Count}");
            sb.AppendLine();

            if (result.HotMethods.Count > 0)
            {
                sb.AppendLine("// Hot methods (most called):");
                foreach (var m in result.HotMethods)
                    sb.AppendLine($"//   {m}");
                sb.AppendLine();
            }

            var nodes = result.Graph.Values.AsEnumerable();
            if (!string.IsNullOrEmpty(search))
            {
                nodes = nodes.Where(n =>
                    n.Name.IndexOf(search, StringComparison.OrdinalIgnoreCase) >= 0);
            }

            foreach (var node in nodes.OrderByDescending(n => n.IncomingCalls + n.OutgoingCalls).Take(200))
            {
                sb.AppendLine($"{node.Name} @ 0x{node.Address:X}");
                sb.AppendLine($"  In: {node.IncomingCalls} Out: {node.OutgoingCalls}");

                if (node.Callers.Count > 0)
                {
                    var uniqueCallers = node.Callers.Distinct().Take(10);
                    foreach (var c in uniqueCallers)
                        sb.AppendLine($"    <- {c}");
                }

                if (node.Callees.Count > 0)
                {
                    var uniqueCallees = node.Callees.Distinct().Take(10);
                    foreach (var c in uniqueCallees)
                        sb.AppendLine($"    -> {c}");
                }
                sb.AppendLine();
            }

            return sb.ToString();
        }

        private static string[] BuildMethodNameMap(Il2CppMetadataSnapshot snapshot)
        {
            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;
            string[] names = new string[snapshot.Methods.Length];

            // Build type names first
            string[] typeNames = new string[snapshot.TypeDefinitions.Length];
            for (int i = 0; i < snapshot.TypeDefinitions.Length; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                string n = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);
                string ns = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);
                typeNames[i] = string.IsNullOrEmpty(ns) ? n : $"{ns}.{n}";
            }

            for (int i = 0; i < snapshot.Methods.Length; i++)
            {
                var md = snapshot.Methods[i];
                string mName = ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)md.NameIndex);
                string typeName = "";

                for (int t = 0; t < snapshot.TypeDefinitions.Length; t++)
                {
                    var td = snapshot.TypeDefinitions[t];
                    if (i >= td.MethodStart && i < td.MethodStart + td.MethodCount)
                    {
                        typeName = typeNames[t];
                        break;
                    }
                }

                names[i] = string.IsNullOrEmpty(typeName) ? mName : $"{typeName}::{mName}";
            }

            return names;
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
    }
}
