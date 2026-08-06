using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using KsDumperClient.Driver;

namespace KsDumperClient.Utility
{
    public static class BeebyteDumper
    {
        public class RecoveredName
        {
            public int TypeIndex;
            public string ObfuscatedName;
            public string ObfuscatedNamespace;
            public string RealName;
            public string RealNamespace;
            public uint Token;
            public List<MethodNamePair> Methods = new List<MethodNamePair>();
            public List<FieldNamePair> Fields = new List<FieldNamePair>();
            public List<PropertyNamePair> Properties = new List<PropertyNamePair>();
            public List<EventNamePair> Events = new List<EventNamePair>();
        }

        public class MethodNamePair
        {
            public string ObfuscatedName;
            public string RealName;
            public uint Token;
            public int Slot;
        }

        public class FieldNamePair
        {
            public string ObfuscatedName;
            public string RealName;
            public uint Token;
        }

        public class PropertyNamePair
        {
            public string ObfuscatedName;
            public string RealName;
            public uint Token;
        }

        public class EventNamePair
        {
            public string ObfuscatedName;
            public string RealName;
            public uint Token;
        }

        public class RecoveryResult
        {
            public int TotalTypes;
            public int RecoveredTypes;
            public int RecoveredMethods;
            public int RecoveredFields;
            public int RecoveredProperties;
            public int RecoveredEvents;
            public bool IsObfuscated;
            public List<RecoveredName> Names = new List<RecoveredName>();
        }

        // IL2CPP runtime struct offsets (64-bit)
        // Il2CppClass layout (key fields):
        //   +0x00: Il2CppImage* image
        //   +0x08: void* gc_desc
        //   +0x10: char* name
        //   +0x18: char* namespaze
        //   +0x20: Il2CppType byval_arg
        //   +0x30: Il2CppType this_arg   (each Il2CppType is 16 bytes on x64)
        //   +0x40: uint16_t token (at varying offsets depending on version)
        //   ...field_count, method_count at known offsets
        //
        // We use pattern scanning to find the s_TypeInfoTable which is an array of Il2CppClass*

        public static RecoveryResult RecoverNames(
            IMemoryReader driver, int processId,
            ulong gameAssemblyBase, uint gameAssemblySize,
            Il2CppDumper.Il2CppMetadataSnapshot snapshot,
            Action<string> log)
        {
            var result = new RecoveryResult();
            result.TotalTypes = snapshot.TypeDefinitions.Length;

            byte[] metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            // Step 1: Check if metadata is actually obfuscated
            result.IsObfuscated = DetectObfuscation(snapshot, metadata, header);
            if (!result.IsObfuscated)
            {
                log("Metadata strings appear to be unobfuscated — skipping Beebyte recovery");
                return result;
            }

            log($"Beebyte obfuscation detected — scanning for runtime class info...");

            // Step 2: Find s_Il2CppMetadataRegistration or type info table in GameAssembly.dll
            // We scan for the pattern: a pointer to an array of Il2CppClass* pointers
            // The Il2CppMetadataRegistration contains:
            //   int32_t typesCount
            //   Il2CppType** types
            //   ...
            // But more reliably, we can find Il2CppClass instances by scanning for
            // pointers that reference strings within GameAssembly.dll's .rdata

            log("Scanning for Il2CppClass instances in process memory...");

            var classMap = ScanForIl2CppClasses(driver, processId, gameAssemblyBase, gameAssemblySize,
                snapshot.TypeDefinitions.Length, log);

            if (classMap.Count == 0)
            {
                log("WARNING: Could not find Il2CppClass instances — trying alternative scan...");
                classMap = ScanForClassesByExport(driver, processId, gameAssemblyBase, gameAssemblySize,
                    snapshot.TypeDefinitions.Length, log);
            }

            if (classMap.Count == 0)
            {
                log("WARNING: No Il2CppClass instances found. Beebyte recovery failed.");
                log("  The game may use a custom protection or the process needs to be fully loaded.");
                return result;
            }

            log($"Found {classMap.Count} Il2CppClass instances");

            // Step 3: Match recovered names to metadata type definitions
            foreach (var kvp in classMap)
            {
                int typeIndex = kvp.Key;
                var classInfo = kvp.Value;

                if (typeIndex < 0 || typeIndex >= snapshot.TypeDefinitions.Length)
                    continue;

                var td = snapshot.TypeDefinitions[typeIndex];
                string obfName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);
                string obfNs = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);

                if (classInfo.Name == obfName && classInfo.Namespace == obfNs)
                    continue; // Not obfuscated for this type

                var recovered = new RecoveredName
                {
                    TypeIndex = typeIndex,
                    ObfuscatedName = obfName,
                    ObfuscatedNamespace = obfNs,
                    RealName = classInfo.Name,
                    RealNamespace = classInfo.Namespace,
                    Token = td.Token
                };

                // Recover method names from Il2CppClass->methods array
                if (classInfo.Methods != null)
                {
                    int methodEnd = td.MethodStart + td.MethodCount;
                    for (int mi = 0; mi < classInfo.Methods.Count && (td.MethodStart + mi) < snapshot.Methods.Length; mi++)
                    {
                        int methodIdx = td.MethodStart + mi;
                        if (methodIdx < 0 || methodIdx >= snapshot.Methods.Length) break;

                        var md = snapshot.Methods[methodIdx];
                        string obfMethodName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)md.NameIndex);

                        if (classInfo.Methods[mi] != obfMethodName)
                        {
                            recovered.Methods.Add(new MethodNamePair
                            {
                                ObfuscatedName = obfMethodName,
                                RealName = classInfo.Methods[mi],
                                Token = md.Token,
                                Slot = md.Slot
                            });
                            result.RecoveredMethods++;
                        }
                    }
                }

                // Recover field names
                if (classInfo.Fields != null)
                {
                    for (int fi = 0; fi < classInfo.Fields.Count && (td.FieldStart + fi) < snapshot.Fields.Length; fi++)
                    {
                        int fieldIdx = td.FieldStart + fi;
                        if (fieldIdx < 0 || fieldIdx >= snapshot.Fields.Length) break;

                        var fd = snapshot.Fields[fieldIdx];
                        string obfFieldName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)fd.NameIndex);

                        if (classInfo.Fields[fi] != obfFieldName)
                        {
                            recovered.Fields.Add(new FieldNamePair
                            {
                                ObfuscatedName = obfFieldName,
                                RealName = classInfo.Fields[fi],
                                Token = fd.Token
                            });
                            result.RecoveredFields++;
                        }
                    }
                }

                // Recover property names
                if (classInfo.Properties != null && snapshot.Properties != null)
                {
                    for (int pi = 0; pi < classInfo.Properties.Count && (td.PropertyStart + pi) < snapshot.Properties.Length; pi++)
                    {
                        int propIdx = td.PropertyStart + pi;
                        if (propIdx < 0 || propIdx >= snapshot.Properties.Length) break;

                        var pd = snapshot.Properties[propIdx];
                        string obfPropName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)pd.NameIndex);

                        if (classInfo.Properties[pi] != obfPropName)
                        {
                            recovered.Properties.Add(new PropertyNamePair
                            {
                                ObfuscatedName = obfPropName,
                                RealName = classInfo.Properties[pi],
                                Token = pd.Token
                            });
                            result.RecoveredProperties++;
                        }
                    }
                }

                // Recover event names
                if (classInfo.Events != null && snapshot.Events != null)
                {
                    for (int ei = 0; ei < classInfo.Events.Count && (td.EventStart + ei) < snapshot.Events.Length; ei++)
                    {
                        int evtIdx = td.EventStart + ei;
                        if (evtIdx < 0 || evtIdx >= snapshot.Events.Length) break;

                        var ed = snapshot.Events[evtIdx];
                        string obfEvtName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)ed.NameIndex);

                        if (classInfo.Events[ei] != obfEvtName)
                        {
                            recovered.Events.Add(new EventNamePair
                            {
                                ObfuscatedName = obfEvtName,
                                RealName = classInfo.Events[ei],
                                Token = ed.Token
                            });
                            result.RecoveredEvents++;
                        }
                    }
                }

                result.Names.Add(recovered);
                result.RecoveredTypes++;
            }

            log($"Recovery complete: {result.RecoveredTypes}/{result.TotalTypes} types, " +
                $"{result.RecoveredMethods} methods, {result.RecoveredFields} fields, " +
                $"{result.RecoveredProperties} properties, {result.RecoveredEvents} events");

            return result;
        }

        private struct RuntimeClassInfo
        {
            public string Name;
            public string Namespace;
            public List<string> Methods;
            public List<string> Fields;
            public List<string> Properties;
            public List<string> Events;
        }

        private static bool DetectObfuscation(Il2CppDumper.Il2CppMetadataSnapshot snapshot, byte[] metadata, Il2CppDumper.Il2CppMetadataHeader header)
        {
            int obfuscatedCount = 0;
            int sampleSize = Math.Min(200, snapshot.TypeDefinitions.Length);

            for (int i = 0; i < sampleSize; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                string name = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);

                if (IsObfuscatedName(name))
                    obfuscatedCount++;
            }

            // If >30% of sampled names look obfuscated, it's likely Beebyte
            return obfuscatedCount > sampleSize * 0.3;
        }

        private static bool IsObfuscatedName(string name)
        {
            if (string.IsNullOrEmpty(name) || name.Length < 2) return false;
            if (name.StartsWith("<") || name.StartsWith("$") || name == "<Module>") return false;

            // Beebyte typically generates names like single chars, 2-3 random chars,
            // or names with unusual patterns like mixing upper/lower without word boundaries
            if (name.Length <= 3 && !char.IsUpper(name[0])) return true;

            // Check for random-looking character sequences (no vowels, no word patterns)
            int consonants = 0;
            int uppers = 0;
            foreach (char c in name)
            {
                if ("aeiouAEIOU".IndexOf(c) < 0 && char.IsLetter(c))
                    consonants++;
                if (char.IsUpper(c))
                    uppers++;
            }

            // All-consonant names of reasonable length are suspicious
            if (name.Length >= 4 && name.Length <= 20 && consonants == name.Length)
                return true;

            // Very short names that aren't common patterns
            if (name.Length <= 2 && char.IsLetter(name[0]))
                return true;

            return false;
        }

        // Scan for Il2CppClass pointers by finding the il2cpp_class_from_type export
        // and tracing its usage to find s_TypeInfoTable
        private static Dictionary<int, RuntimeClassInfo> ScanForClassesByExport(
            IMemoryReader driver, int processId,
            ulong gameAssemblyBase, uint gameAssemblySize,
            int typeCount, Action<string> log)
        {
            var result = new Dictionary<int, RuntimeClassInfo>();

            // Look for "il2cpp_class_get_name" export — it reads Il2CppClass->name
            // The export table gives us an entry point; we can use it to validate our class pointer parsing
            var exports = driver.GetExportMap(processId);
            if (exports == null || exports.Count == 0)
            {
                log("  No exports found via GetExportMap");
                return result;
            }

            ulong classGetNameAddr = 0;
            foreach (var exp in exports)
            {
                if (exp.Value.funcName == "il2cpp_class_get_name")
                    classGetNameAddr = exp.Key;
            }

            if (classGetNameAddr == 0)
            {
                log("  il2cpp_class_get_name export not found");
            }

            // Scan .data/.bss sections for the type info table
            // It's a contiguous array of (typeCount) pointers to Il2CppClass*
            return ScanDataSectionsForTypeTable(driver, processId, gameAssemblyBase, gameAssemblySize,
                typeCount, log);
        }

        // Primary scan: find Il2CppClass instances by scanning the data sections
        // of GameAssembly.dll for s_TypeInfoTable (array of Il2CppClass* pointers)
        private static Dictionary<int, RuntimeClassInfo> ScanForIl2CppClasses(
            IMemoryReader driver, int processId,
            ulong gameAssemblyBase, uint gameAssemblySize,
            int typeCount, Action<string> log)
        {
            return ScanDataSectionsForTypeTable(driver, processId, gameAssemblyBase, gameAssemblySize,
                typeCount, log);
        }

        private static Dictionary<int, RuntimeClassInfo> ScanDataSectionsForTypeTable(
            IMemoryReader driver, int processId,
            ulong gameAssemblyBase, uint gameAssemblySize,
            int typeCount, Action<string> log)
        {
            var result = new Dictionary<int, RuntimeClassInfo>();

            // Read the PE header to find .data and .rdata sections
            int headerSize = 0x1000;
            byte[] peHeader = ReadMemory(driver, processId, gameAssemblyBase, headerSize);
            if (peHeader == null || peHeader.Length < 0x200) return result;

            int e_lfanew = BitConverter.ToInt32(peHeader, 0x3C);
            if (e_lfanew < 0 || e_lfanew + 0x108 > peHeader.Length) return result;

            int numSections = BitConverter.ToUInt16(peHeader, e_lfanew + 6);
            int optHeaderSize = BitConverter.ToUInt16(peHeader, e_lfanew + 20);
            int sectionTableOff = e_lfanew + 24 + optHeaderSize;

            // Find all data-like sections
            var dataSections = new List<(uint rva, uint virtualSize, string name)>();
            for (int i = 0; i < numSections && sectionTableOff + 40 <= peHeader.Length; i++)
            {
                int off = sectionTableOff + i * 40;
                string secName = Encoding.ASCII.GetString(peHeader, off, 8).TrimEnd('\0');
                uint virtualSize = BitConverter.ToUInt32(peHeader, off + 8);
                uint rva = BitConverter.ToUInt32(peHeader, off + 12);
                uint characteristics = BitConverter.ToUInt32(peHeader, off + 36);

                // Look for sections with initialized data or writable flag
                bool isData = secName == ".data" || secName == ".rdata" || secName == ".bss" ||
                              (characteristics & 0x00000040) != 0 || // initialized data
                              (characteristics & 0x80000000) != 0;   // writable

                if (isData && virtualSize > 0 && virtualSize < 0x40000000)
                {
                    dataSections.Add((rva, virtualSize, secName));
                }
            }

            if (dataSections.Count == 0)
            {
                log("  No data sections found in GameAssembly.dll");
                return result;
            }

            // Scan each data section for a run of valid Il2CppClass* pointers
            foreach (var (rva, virtualSize, secName) in dataSections)
            {
                ulong sectionAddr = gameAssemblyBase + rva;
                int readSize = (int)Math.Min(virtualSize, 0x4000000); // 64MB max per section
                byte[] sectionData = ReadMemory(driver, processId, sectionAddr, readSize);
                if (sectionData == null) continue;

                log($"  Scanning {secName} (0x{rva:X}, {readSize / 1024}KB) for type info table...");

                // Look for a contiguous array of valid pointers (8 bytes each, non-null, in user-space range)
                int minConsecutive = Math.Min(typeCount, 50); // need at least 50 consecutive valid ptrs
                int bestRunStart = -1;
                int bestRunLength = 0;

                int runStart = -1;
                int runLength = 0;

                for (int off = 0; off + 8 <= sectionData.Length; off += 8)
                {
                    ulong ptr = BitConverter.ToUInt64(sectionData, off);

                    if (IsValidUserPointer(ptr))
                    {
                        if (runStart < 0) runStart = off;
                        runLength++;
                    }
                    else
                    {
                        if (runLength > bestRunLength)
                        {
                            bestRunStart = runStart;
                            bestRunLength = runLength;
                        }
                        runStart = -1;
                        runLength = 0;
                    }
                }
                if (runLength > bestRunLength)
                {
                    bestRunStart = runStart;
                    bestRunLength = runLength;
                }

                // Check if the best run could be the type info table
                if (bestRunLength < minConsecutive)
                    continue;

                log($"  Found candidate pointer array in {secName}: {bestRunLength} pointers at offset 0x{bestRunStart:X}");

                // Validate by reading a few Il2CppClass* and checking the name field
                int validateCount = Math.Min(10, bestRunLength);
                int validClasses = 0;
                for (int vi = 0; vi < validateCount; vi++)
                {
                    ulong classPtr = BitConverter.ToUInt64(sectionData, bestRunStart + vi * 8);
                    string name = ReadClassName(driver, processId, classPtr);
                    if (!string.IsNullOrEmpty(name) && name.Length < 200)
                        validClasses++;
                }

                if (validClasses < validateCount / 2)
                {
                    log($"  Validation failed: only {validClasses}/{validateCount} had valid names");
                    continue;
                }

                log($"  Validated! Reading {Math.Min(bestRunLength, typeCount)} class entries...");

                // Read all class names
                int readCount = Math.Min(bestRunLength, typeCount);
                for (int ci = 0; ci < readCount; ci++)
                {
                    ulong classPtr = BitConverter.ToUInt64(sectionData, bestRunStart + ci * 8);
                    if (!IsValidUserPointer(classPtr)) continue;

                    var classData = ReadClassInfo(driver, processId, classPtr);
                    if (classData.Name != null)
                    {
                        result[ci] = classData;
                    }
                }

                if (result.Count > 0)
                {
                    log($"  Read {result.Count} class names from type info table");
                    break; // Found it
                }
            }

            return result;
        }

        private static string ReadClassName(IMemoryReader driver, int processId, ulong classPtr)
        {
            // Il2CppClass->name is at offset 0x10 (64-bit)
            byte[] classHeader = ReadMemory(driver, processId, classPtr, 0x20);
            if (classHeader == null || classHeader.Length < 0x20) return null;

            ulong namePtr = BitConverter.ToUInt64(classHeader, 0x10);
            if (!IsValidUserPointer(namePtr)) return null;

            return ReadCString(driver, processId, namePtr, 256);
        }

        private static RuntimeClassInfo ReadClassInfo(IMemoryReader driver, int processId, ulong classPtr)
        {
            var info = new RuntimeClassInfo();

            // Read first 0x100 bytes of Il2CppClass
            byte[] classData = ReadMemory(driver, processId, classPtr, 0x100);
            if (classData == null || classData.Length < 0x20) return info;

            // Il2CppClass layout (x64):
            // +0x00: Il2CppImage* image
            // +0x08: void* gc_desc
            // +0x10: char* name
            // +0x18: char* namespaze
            ulong namePtr = BitConverter.ToUInt64(classData, 0x10);
            ulong nsPtr = BitConverter.ToUInt64(classData, 0x18);

            if (IsValidUserPointer(namePtr))
                info.Name = ReadCString(driver, processId, namePtr, 256);
            if (IsValidUserPointer(nsPtr))
                info.Namespace = ReadCString(driver, processId, nsPtr, 512);

            // Read method names from Il2CppClass->methods (Il2CppMethodInfo**)
            // The methods pointer is at varying offsets depending on IL2CPP version
            // Common offsets: 0x98 (v24), 0xA0 (v27), 0xA8 (v29)
            // We try multiple offsets
            info.Methods = TryReadMethodNames(driver, processId, classData, classPtr);
            info.Fields = TryReadFieldNames(driver, processId, classData, classPtr);
            info.Properties = TryReadPropertyNames(driver, processId, classData, classPtr);
            info.Events = TryReadEventNames(driver, processId, classData, classPtr);

            return info;
        }

        private static List<string> TryReadMethodNames(IMemoryReader driver, int processId, byte[] classData, ulong classPtr)
        {
            var methods = new List<string>();

            // Try common offsets for Il2CppClass->methods and Il2CppClass->method_count
            // These vary by IL2CPP version:
            //   v24: methods at 0x98, method_count (uint16) at 0xCC
            //   v27: methods at 0xA0, method_count at 0xD0
            //   v29: methods at 0xA8, method_count at 0xD4
            int[][] candidates = new int[][]
            {
                new int[] { 0x98, 0xC8 },  // v24-ish
                new int[] { 0xA0, 0xCC },  // v27-ish
                new int[] { 0xA8, 0xD0 },  // v29+
                new int[] { 0xB0, 0xD4 },  // newer
            };

            foreach (var offsets in candidates)
            {
                int methodsOff = offsets[0];
                int countOff = offsets[1];

                if (methodsOff + 8 > classData.Length || countOff + 2 > classData.Length)
                    continue;

                ulong methodsPtr = BitConverter.ToUInt64(classData, methodsOff);
                ushort methodCount = BitConverter.ToUInt16(classData, countOff);

                if (!IsValidUserPointer(methodsPtr) || methodCount == 0 || methodCount > 5000)
                    continue;

                // Il2CppClass->methods is Il2CppMethodInfo** (array of pointers)
                int arrSize = methodCount * 8;
                byte[] methodPtrs = ReadMemory(driver, processId, methodsPtr, arrSize);
                if (methodPtrs == null) continue;

                var names = new List<string>();
                bool allValid = true;

                int readCount = Math.Min(methodCount, (ushort)3); // validate first 3
                for (int mi = 0; mi < readCount; mi++)
                {
                    ulong methodInfoPtr = BitConverter.ToUInt64(methodPtrs, mi * 8);
                    if (!IsValidUserPointer(methodInfoPtr)) { allValid = false; break; }

                    // Il2CppMethodInfo->name is at offset 0x00 (it's a char* pointer)
                    byte[] methodInfo = ReadMemory(driver, processId, methodInfoPtr, 0x10);
                    if (methodInfo == null) { allValid = false; break; }

                    ulong methodNamePtr = BitConverter.ToUInt64(methodInfo, 0x00);
                    if (!IsValidUserPointer(methodNamePtr)) { allValid = false; break; }

                    string name = ReadCString(driver, processId, methodNamePtr, 256);
                    if (string.IsNullOrEmpty(name)) { allValid = false; break; }
                    names.Add(name);
                }

                if (!allValid || names.Count == 0) continue;

                // Valid! Read all method names
                for (int mi = names.Count; mi < methodCount; mi++)
                {
                    if (mi * 8 + 8 > methodPtrs.Length) break;
                    ulong methodInfoPtr = BitConverter.ToUInt64(methodPtrs, mi * 8);
                    if (!IsValidUserPointer(methodInfoPtr)) { names.Add(""); continue; }

                    byte[] methodInfo = ReadMemory(driver, processId, methodInfoPtr, 0x10);
                    if (methodInfo == null) { names.Add(""); continue; }

                    ulong methodNamePtr = BitConverter.ToUInt64(methodInfo, 0x00);
                    if (!IsValidUserPointer(methodNamePtr)) { names.Add(""); continue; }

                    string name = ReadCString(driver, processId, methodNamePtr, 256);
                    names.Add(name ?? "");
                }

                return names;
            }

            return methods;
        }

        private static List<string> TryReadFieldNames(IMemoryReader driver, int processId, byte[] classData, ulong classPtr)
        {
            var fields = new List<string>();

            // Il2CppClass->fields (Il2CppFieldInfo*) and field_count
            // Il2CppFieldInfo is a struct (not pointer), each entry has:
            //   +0x00: char* name
            //   +0x08: Il2CppType* type
            //   +0x10: Il2CppClass* parent
            //   Size: 0x18 (24 bytes on x64)
            int[][] candidates = new int[][]
            {
                new int[] { 0x80, 0xCA },  // v24-ish
                new int[] { 0x88, 0xCE },  // v27-ish
                new int[] { 0x90, 0xD2 },  // v29+
                new int[] { 0x98, 0xD6 },  // newer
            };

            foreach (var offsets in candidates)
            {
                int fieldsOff = offsets[0];
                int countOff = offsets[1];

                if (fieldsOff + 8 > classData.Length || countOff + 2 > classData.Length)
                    continue;

                ulong fieldsPtr = BitConverter.ToUInt64(classData, fieldsOff);
                ushort fieldCount = BitConverter.ToUInt16(classData, countOff);

                if (!IsValidUserPointer(fieldsPtr) || fieldCount == 0 || fieldCount > 5000)
                    continue;

                int structSize = 0x18; // Il2CppFieldInfo size on x64
                byte[] fieldData = ReadMemory(driver, processId, fieldsPtr, fieldCount * structSize);
                if (fieldData == null) continue;

                var names = new List<string>();
                bool allValid = true;

                int readCount = Math.Min(fieldCount, (ushort)3);
                for (int fi = 0; fi < readCount; fi++)
                {
                    int off = fi * structSize;
                    if (off + 8 > fieldData.Length) { allValid = false; break; }

                    ulong fieldNamePtr = BitConverter.ToUInt64(fieldData, off);
                    if (!IsValidUserPointer(fieldNamePtr)) { allValid = false; break; }

                    string name = ReadCString(driver, processId, fieldNamePtr, 256);
                    if (string.IsNullOrEmpty(name)) { allValid = false; break; }
                    names.Add(name);
                }

                if (!allValid || names.Count == 0) continue;

                for (int fi = names.Count; fi < fieldCount; fi++)
                {
                    int off = fi * structSize;
                    if (off + 8 > fieldData.Length) { names.Add(""); continue; }

                    ulong fieldNamePtr = BitConverter.ToUInt64(fieldData, off);
                    if (!IsValidUserPointer(fieldNamePtr)) { names.Add(""); continue; }

                    string name = ReadCString(driver, processId, fieldNamePtr, 256);
                    names.Add(name ?? "");
                }

                return names;
            }

            return fields;
        }

        private static List<string> TryReadPropertyNames(IMemoryReader driver, int processId, byte[] classData, ulong classPtr)
        {
            // Il2CppClass->properties (Il2CppPropertyInfo*) at offset 0x90 (varies by version)
            // Il2CppPropertyInfo layout (x64):
            //   +0x00: Il2CppClass* parent
            //   +0x08: char* name
            //   +0x10: MethodInfo* get
            //   +0x18: MethodInfo* set
            //   +0x20: uint32_t attrs
            //   Size: ~0x28 (40 bytes)
            int[][] candidates = new int[][]
            {
                new int[] { 0x90, 0xCC },  // v24-ish: properties ptr, property_count
                new int[] { 0x98, 0xD0 },  // v27-ish
                new int[] { 0xA0, 0xD4 },  // v29+
                new int[] { 0xA8, 0xD8 },  // newer
            };

            int propStructSize = 0x28;

            foreach (var offsets in candidates)
            {
                int propsOff = offsets[0];
                int countOff = offsets[1];

                if (propsOff + 8 > classData.Length || countOff + 2 > classData.Length)
                    continue;

                ulong propsPtr = BitConverter.ToUInt64(classData, propsOff);
                ushort propCount = BitConverter.ToUInt16(classData, countOff);

                if (!IsValidUserPointer(propsPtr) || propCount == 0 || propCount > 1000)
                    continue;

                byte[] propData = ReadMemory(driver, processId, propsPtr, propCount * propStructSize);
                if (propData == null) continue;

                var names = new List<string>();
                bool valid = true;
                int check = Math.Min(propCount, (ushort)2);
                for (int i = 0; i < check; i++)
                {
                    int off = i * propStructSize + 0x08; // name is at +0x08
                    if (off + 8 > propData.Length) { valid = false; break; }
                    ulong namePtr = BitConverter.ToUInt64(propData, off);
                    if (!IsValidUserPointer(namePtr)) { valid = false; break; }
                    string name = ReadCString(driver, processId, namePtr, 256);
                    if (string.IsNullOrEmpty(name)) { valid = false; break; }
                    names.Add(name);
                }

                if (!valid || names.Count == 0) continue;

                for (int i = names.Count; i < propCount; i++)
                {
                    int off = i * propStructSize + 0x08;
                    if (off + 8 > propData.Length) { names.Add(""); continue; }
                    ulong namePtr = BitConverter.ToUInt64(propData, off);
                    if (!IsValidUserPointer(namePtr)) { names.Add(""); continue; }
                    string name = ReadCString(driver, processId, namePtr, 256);
                    names.Add(name ?? "");
                }
                return names;
            }
            return null;
        }

        private static List<string> TryReadEventNames(IMemoryReader driver, int processId, byte[] classData, ulong classPtr)
        {
            // Il2CppClass->events (Il2CppEventInfo*) at offset 0x88 (varies by version)
            // Il2CppEventInfo layout (x64):
            //   +0x00: char* name
            //   +0x08: Il2CppType* eventType
            //   +0x10: Il2CppClass* parent
            //   +0x18: MethodInfo* add
            //   +0x20: MethodInfo* remove
            //   +0x28: MethodInfo* raise
            //   Size: ~0x30 (48 bytes)
            int[][] candidates = new int[][]
            {
                new int[] { 0x88, 0xCE },  // v24-ish: events ptr, event_count
                new int[] { 0x90, 0xD2 },  // v27-ish
                new int[] { 0x98, 0xD6 },  // v29+
                new int[] { 0xA0, 0xDA },  // newer
            };

            int evtStructSize = 0x30;

            foreach (var offsets in candidates)
            {
                int eventsOff = offsets[0];
                int countOff = offsets[1];

                if (eventsOff + 8 > classData.Length || countOff + 2 > classData.Length)
                    continue;

                ulong eventsPtr = BitConverter.ToUInt64(classData, eventsOff);
                ushort eventCount = BitConverter.ToUInt16(classData, countOff);

                if (!IsValidUserPointer(eventsPtr) || eventCount == 0 || eventCount > 1000)
                    continue;

                byte[] evtData = ReadMemory(driver, processId, eventsPtr, eventCount * evtStructSize);
                if (evtData == null) continue;

                var names = new List<string>();
                bool valid = true;
                int check = Math.Min(eventCount, (ushort)2);
                for (int i = 0; i < check; i++)
                {
                    int off = i * evtStructSize; // name is at +0x00
                    if (off + 8 > evtData.Length) { valid = false; break; }
                    ulong namePtr = BitConverter.ToUInt64(evtData, off);
                    if (!IsValidUserPointer(namePtr)) { valid = false; break; }
                    string name = ReadCString(driver, processId, namePtr, 256);
                    if (string.IsNullOrEmpty(name)) { valid = false; break; }
                    names.Add(name);
                }

                if (!valid || names.Count == 0) continue;

                for (int i = names.Count; i < eventCount; i++)
                {
                    int off = i * evtStructSize;
                    if (off + 8 > evtData.Length) { names.Add(""); continue; }
                    ulong namePtr = BitConverter.ToUInt64(evtData, off);
                    if (!IsValidUserPointer(namePtr)) { names.Add(""); continue; }
                    string name = ReadCString(driver, processId, namePtr, 256);
                    names.Add(name ?? "");
                }
                return names;
            }
            return null;
        }

        private static bool IsValidUserPointer(ulong ptr)
        {
            return ptr > 0x10000 && ptr < 0x7FFFFFFFFFFF;
        }

        private static byte[] ReadMemory(IMemoryReader driver, int processId, ulong address, int size)
        {
            if (size <= 0 || size > 0x10000000) return null;

            IntPtr buf = WinApi.VirtualAlloc(IntPtr.Zero, (UIntPtr)size,
                WinApi.MEM_COMMIT | WinApi.MEM_RESERVE, WinApi.PAGE_READWRITE);
            if (buf == IntPtr.Zero) return null;

            try
            {
                if (!driver.CopyVirtualMemory(processId, (IntPtr)address, buf, size))
                    return null;

                byte[] data = new byte[size];
                Marshal.Copy(buf, data, 0, size);
                return data;
            }
            finally
            {
                WinApi.VirtualFree(buf, UIntPtr.Zero, WinApi.MEM_RELEASE);
            }
        }

        private static string ReadCString(IMemoryReader driver, int processId, ulong address, int maxLen)
        {
            byte[] data = ReadMemory(driver, processId, address, maxLen);
            if (data == null) return null;

            int end = Array.IndexOf(data, (byte)0);
            if (end < 0) end = data.Length;
            if (end == 0) return "";

            return Encoding.UTF8.GetString(data, 0, end);
        }

        // Save recovery results as a mapping file
        public static void SaveMapping(string outputPath, RecoveryResult result, string processName)
        {
            using (var writer = new StreamWriter(outputPath, false, Encoding.UTF8))
            {
                writer.WriteLine("// KsDumper - Beebyte Deobfuscation Map");
                writer.WriteLine($"// Process: {processName}");
                writer.WriteLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                writer.WriteLine($"// Types: {result.RecoveredTypes}/{result.TotalTypes} recovered");
                writer.WriteLine($"// Methods: {result.RecoveredMethods} recovered");
                writer.WriteLine($"// Fields: {result.RecoveredFields} recovered");
                writer.WriteLine($"// Properties: {result.RecoveredProperties} recovered");
                writer.WriteLine($"// Events: {result.RecoveredEvents} recovered");
                writer.WriteLine();
                writer.WriteLine("// Format: OBFUSCATED -> REAL");
                writer.WriteLine();

                foreach (var name in result.Names.OrderBy(n => n.RealNamespace).ThenBy(n => n.RealName))
                {
                    string obfFull = string.IsNullOrEmpty(name.ObfuscatedNamespace)
                        ? name.ObfuscatedName
                        : $"{name.ObfuscatedNamespace}.{name.ObfuscatedName}";
                    string realFull = string.IsNullOrEmpty(name.RealNamespace)
                        ? name.RealName
                        : $"{name.RealNamespace}.{name.RealName}";

                    writer.WriteLine($"[Type] Token:0x{name.Token:X8}  {obfFull} -> {realFull}");

                    foreach (var method in name.Methods)
                    {
                        writer.WriteLine($"  [Method] Token:0x{method.Token:X8}  {method.ObfuscatedName} -> {method.RealName}");
                    }

                    foreach (var field in name.Fields)
                    {
                        writer.WriteLine($"  [Field]  Token:0x{field.Token:X8}  {field.ObfuscatedName} -> {field.RealName}");
                    }

                    foreach (var prop in name.Properties)
                    {
                        writer.WriteLine($"  [Prop]   Token:0x{prop.Token:X8}  {prop.ObfuscatedName} -> {prop.RealName}");
                    }

                    foreach (var evt in name.Events)
                    {
                        writer.WriteLine($"  [Event]  Token:0x{evt.Token:X8}  {evt.ObfuscatedName} -> {evt.RealName}");
                    }
                }
            }
        }

        // Save as IDA Python script that renames functions
        public static void SaveIdaScript(string outputPath, RecoveryResult result)
        {
            using (var writer = new StreamWriter(outputPath, false, Encoding.UTF8))
            {
                writer.WriteLine("# KsDumper - Beebyte Deobfuscation IDA Script");
                writer.WriteLine($"# Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
                writer.WriteLine($"# Types: {result.RecoveredTypes}, Methods: {result.RecoveredMethods}");
                writer.WriteLine();
                writer.WriteLine("import idaapi");
                writer.WriteLine("import ida_name");
                writer.WriteLine("import idc");
                writer.WriteLine();
                writer.WriteLine("# Rename map: obfuscated -> real");
                writer.WriteLine("renames = {");

                foreach (var name in result.Names)
                {
                    string ns = string.IsNullOrEmpty(name.RealNamespace) ? "" : name.RealNamespace + "::";
                    foreach (var method in name.Methods)
                    {
                        string realName = $"{ns}{name.RealName}::{method.RealName}".Replace(".", "::");
                        string obfName = $"{name.ObfuscatedName}$${method.ObfuscatedName}";
                        writer.WriteLine($"    \"{obfName}\": \"{realName}\",");
                    }
                }

                writer.WriteLine("}");
                writer.WriteLine();
                writer.WriteLine("renamed = 0");
                writer.WriteLine("for obf, real in renames.items():");
                writer.WriteLine("    ea = idc.get_name_ea_simple(obf)");
                writer.WriteLine("    if ea != idaapi.BADADDR:");
                writer.WriteLine("        ida_name.set_name(ea, real, ida_name.SN_FORCE)");
                writer.WriteLine("        renamed += 1");
                writer.WriteLine("print(f'Renamed {renamed}/{len(renames)} functions')");
            }
        }

        // Generate a deobfuscated SDK with real names applied
        public static string GenerateDeobfuscatedSdk(
            Il2CppDumper.Il2CppMetadataSnapshot snapshot,
            RecoveryResult recovery)
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Deobfuscated IL2CPP SDK");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Types recovered: {recovery.RecoveredTypes}/{recovery.TotalTypes}");
            sb.AppendLine();

            var nameMap = new Dictionary<int, RecoveredName>();
            foreach (var r in recovery.Names)
                nameMap[r.TypeIndex] = r;

            var metadata = snapshot.RawMetadata;
            var header = snapshot.Header;

            // Group by namespace
            var byNamespace = new SortedDictionary<string, List<(int idx, Il2CppDumper.Il2CppTypeDefinition td)>>();

            for (int i = 0; i < snapshot.TypeDefinitions.Length; i++)
            {
                var td = snapshot.TypeDefinitions[i];
                string ns;
                if (nameMap.TryGetValue(i, out var recovered))
                    ns = recovered.RealNamespace ?? "";
                else
                    ns = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NamespaceIndex);

                if (!byNamespace.TryGetValue(ns, out var list))
                {
                    list = new List<(int, Il2CppDumper.Il2CppTypeDefinition)>();
                    byNamespace[ns] = list;
                }
                list.Add((i, td));
            }

            foreach (var kvp in byNamespace)
            {
                string ns = kvp.Key;
                if (!string.IsNullOrEmpty(ns))
                {
                    sb.AppendLine($"namespace {ns}");
                    sb.AppendLine("{");
                }

                foreach (var (idx, td) in kvp.Value)
                {
                    string className;
                    RecoveredName rec = null;
                    nameMap.TryGetValue(idx, out rec);

                    if (rec != null)
                        className = rec.RealName;
                    else
                        className = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, td.NameIndex);

                    if (string.IsNullOrEmpty(className) || className == "<Module>") continue;

                    string indent = string.IsNullOrEmpty(ns) ? "" : "    ";

                    bool isInterface = (td.Flags & 0x00000020) == 0 && (td.Flags & 0x00000100) != 0;
                    string keyword = isInterface ? "interface" : "class";

                    sb.AppendLine($"{indent}// Token: 0x{td.Token:X8}");
                    if (rec != null)
                        sb.AppendLine($"{indent}// Deobfuscated: {rec.ObfuscatedName} -> {rec.RealName}");
                    sb.AppendLine($"{indent}public {keyword} {className}");
                    sb.AppendLine($"{indent}{{");

                    // Fields
                    if (td.FieldStart >= 0 && td.FieldCount > 0)
                    {
                        var methodMap = rec?.Fields?.ToDictionary(f => f.Token, f => f.RealName);
                        for (int fi = 0; fi < td.FieldCount && (td.FieldStart + fi) < snapshot.Fields.Length; fi++)
                        {
                            var fd = snapshot.Fields[td.FieldStart + fi];
                            string fieldName;
                            if (rec != null && fi < (rec.Fields?.Count ?? 0))
                                fieldName = rec.Fields[fi].RealName;
                            else
                                fieldName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)fd.NameIndex);

                            sb.AppendLine($"{indent}    public var {fieldName}; // Token: 0x{fd.Token:X8}");
                        }
                    }

                    // Methods
                    if (td.MethodStart >= 0 && td.MethodCount > 0)
                    {
                        for (int mi = 0; mi < td.MethodCount && (td.MethodStart + mi) < snapshot.Methods.Length; mi++)
                        {
                            var md = snapshot.Methods[td.MethodStart + mi];
                            string methodName;
                            if (rec != null && mi < (rec.Methods?.Count ?? 0))
                                methodName = rec.Methods[mi].RealName;
                            else
                                methodName = Il2CppDumper.ReadStringFromTable(metadata, header.StringOffset, header.StringSize, (int)md.NameIndex);

                            bool isStatic = (md.Flags & 0x0010) != 0;
                            bool isVirtual = (md.Flags & 0x0040) != 0;
                            string modifiers = isStatic ? "static " : isVirtual ? "virtual " : "";

                            sb.AppendLine($"{indent}    public {modifiers}void {methodName}(); // Token: 0x{md.Token:X8} Slot: {md.Slot}");
                        }
                    }

                    sb.AppendLine($"{indent}}}");
                    sb.AppendLine();
                }

                if (!string.IsNullOrEmpty(ns))
                    sb.AppendLine("}");
                sb.AppendLine();
            }

            return sb.ToString();
        }
    }
}
