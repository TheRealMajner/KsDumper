using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using static KsDumperClient.Utility.Il2CppSdkGenerator;

namespace KsDumperClient.Utility
{
    public static class FridaScriptGenerator
    {
        public static string GenerateFridaScript(
            List<Il2CppClassInfo> classes,
            Dictionary<int, ulong> methodRvas,
            string moduleName = "GameAssembly.dll")
        {
            var sb = new StringBuilder();
            sb.AppendLine("// KsDumper - Frida Hook Script (auto-generated)");
            sb.AppendLine($"// Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"// Module: {moduleName}");
            sb.AppendLine($"// Classes: {classes.Count}");
            sb.AppendLine();

            sb.AppendLine("'use strict';");
            sb.AppendLine();
            sb.AppendLine($"const moduleName = '{moduleName}';");
            sb.AppendLine("const moduleBase = Module.findBaseAddress(moduleName);");
            sb.AppendLine("if (!moduleBase) { console.error('Module not found: ' + moduleName); }");
            sb.AppendLine();

            // Method address lookup table
            sb.AppendLine("// ===== Method Addresses =====");
            sb.AppendLine("const methods = {");
            int methodIdx = 0;
            foreach (var cls in classes)
            {
                foreach (var method in cls.Methods)
                {
                    if (method.Rva == 0) continue;
                    string fullName = string.IsNullOrEmpty(cls.Namespace)
                        ? $"{cls.Name}.{method.Name}"
                        : $"{cls.Namespace}.{cls.Name}.{method.Name}";
                    string safeName = SanitizeJsIdentifier(fullName);
                    sb.AppendLine($"  '{safeName}': moduleBase.add(0x{method.Rva:X}), // {fullName}");
                    methodIdx++;
                    if (methodIdx > 5000) break;
                }
                if (methodIdx > 5000) break;
            }
            sb.AppendLine("};");
            sb.AppendLine();

            // Hook helper function
            sb.AppendLine("// ===== Hook Helpers =====");
            sb.AppendLine(@"function hookMethod(name, opts) {
  const addr = methods[name];
  if (!addr) { console.warn('Method not found: ' + name); return; }

  const callbacks = {};
  if (opts && opts.onEnter) {
    callbacks.onEnter = function(args) {
      const ctx = { method: name, args: args, retval: null };
      opts.onEnter.call(this, ctx);
    };
  } else {
    callbacks.onEnter = function(args) {
      console.log('[ENTER] ' + name);
      // args[0] = this pointer (Il2CppObject*)
      for (let i = 0; i < Math.min(6, (opts && opts.argCount) || 4); i++) {
        console.log('  arg' + i + ' = ' + args[i]);
      }
    };
  }

  if (opts && opts.onLeave) {
    callbacks.onLeave = function(retval) {
      opts.onLeave.call(this, retval);
    };
  } else {
    callbacks.onLeave = function(retval) {
      console.log('[LEAVE] ' + name + ' => ' + retval);
    };
  }

  try {
    Interceptor.attach(addr, callbacks);
    console.log('[HOOKED] ' + name + ' @ ' + addr);
  } catch(e) {
    console.error('[FAIL] ' + name + ': ' + e);
  }
}");
            sb.AppendLine();

            // Il2CppString reader
            sb.AppendLine(@"function readIl2CppString(ptr) {
  if (ptr.isNull()) return '<null>';
  try {
    const len = ptr.add(0x10).readS32();
    if (len <= 0 || len > 4096) return '<invalid>';
    return ptr.add(0x14).readUtf16String(len);
  } catch(e) { return '<error>'; }
}");
            sb.AppendLine();

            // Field reader
            sb.AppendLine(@"function readField(objPtr, offset, type) {
  if (objPtr.isNull()) return null;
  const fieldPtr = objPtr.add(offset);
  switch(type) {
    case 'int': return fieldPtr.readS32();
    case 'uint': return fieldPtr.readU32();
    case 'float': return fieldPtr.readFloat();
    case 'double': return fieldPtr.readDouble();
    case 'long': return fieldPtr.readS64();
    case 'bool': return fieldPtr.readU8() !== 0;
    case 'byte': return fieldPtr.readU8();
    case 'short': return fieldPtr.readS16();
    case 'string': return readIl2CppString(fieldPtr.readPointer());
    case 'ptr': return fieldPtr.readPointer();
    default: return fieldPtr.readPointer();
  }
}");
            sb.AppendLine();

            // Method replacer
            sb.AppendLine(@"function replaceMethod(name, retType, impl) {
  const addr = methods[name];
  if (!addr) { console.warn('Method not found: ' + name); return; }

  Interceptor.replace(addr, new NativeCallback(impl, retType, ['pointer']));
  console.log('[REPLACED] ' + name);
}");
            sb.AppendLine();

            // Class field offset table
            sb.AppendLine("// ===== Class Field Offsets =====");
            sb.AppendLine("const fieldOffsets = {");
            int fieldCount = 0;
            foreach (var cls in classes)
            {
                var instanceFields = cls.Fields.Where(f => !f.IsStatic && f.FieldOffset > 0).ToList();
                if (instanceFields.Count == 0) continue;

                string className = string.IsNullOrEmpty(cls.Namespace) ? cls.Name : $"{cls.Namespace}.{cls.Name}";
                string safeClass = SanitizeJsIdentifier(className);
                sb.AppendLine($"  '{safeClass}': {{");
                foreach (var f in instanceFields)
                {
                    sb.AppendLine($"    '{SanitizeJsIdentifier(f.Name)}': 0x{f.FieldOffset:X}, // {f.TypeName ?? "object"}");
                }
                sb.AppendLine("  },");
                fieldCount++;
                if (fieldCount > 2000) break;
            }
            sb.AppendLine("};");
            sb.AppendLine();

            // Example usage
            sb.AppendLine("// ===== Example Usage =====");
            sb.AppendLine("// hookMethod('PlayerController.TakeDamage');");
            sb.AppendLine("// hookMethod('GameManager.get_Instance', { argCount: 1 });");
            sb.AppendLine("// replaceMethod('AntiCheat.Detect', 'void', function() { });");
            sb.AppendLine("// readField(playerPtr, fieldOffsets['PlayerController']['health'], 'float');");

            return sb.ToString();
        }

        public static string GenerateGameGuardianLua(
            List<Il2CppClassInfo> classes,
            string moduleName = "libil2cpp.so")
        {
            var sb = new StringBuilder();
            sb.AppendLine("-- KsDumper - GameGuardian Lua Script (auto-generated)");
            sb.AppendLine($"-- Generated: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"-- Module: {moduleName}");
            sb.AppendLine();

            sb.AppendLine("gg.clearResults()");
            sb.AppendLine($"local lib = gg.getRangesList('{moduleName}')");
            sb.AppendLine("if #lib == 0 then");
            sb.AppendLine($"  gg.alert('{moduleName} not found!')");
            sb.AppendLine("  return");
            sb.AppendLine("end");
            sb.AppendLine("local base = lib[1].start");
            sb.AppendLine($"gg.toast('Base: ' .. string.format('0x%X', base))");
            sb.AppendLine();

            // Method offset table
            sb.AppendLine("-- ===== Method Offsets =====");
            sb.AppendLine("local methods = {");
            int count = 0;
            foreach (var cls in classes)
            {
                foreach (var method in cls.Methods)
                {
                    if (method.Rva == 0) continue;
                    string fullName = string.IsNullOrEmpty(cls.Namespace)
                        ? $"{cls.Name}.{method.Name}"
                        : $"{cls.Namespace}.{cls.Name}.{method.Name}";
                    sb.AppendLine($"  ['{EscapeLua(fullName)}'] = 0x{method.Rva:X},");
                    count++;
                    if (count > 3000) break;
                }
                if (count > 3000) break;
            }
            sb.AppendLine("}");
            sb.AppendLine();

            // Field offset table
            sb.AppendLine("-- ===== Field Offsets =====");
            sb.AppendLine("local fields = {");
            count = 0;
            foreach (var cls in classes)
            {
                var instanceFields = cls.Fields.Where(f => !f.IsStatic && f.FieldOffset > 0).ToList();
                if (instanceFields.Count == 0) continue;

                string className = string.IsNullOrEmpty(cls.Namespace) ? cls.Name : $"{cls.Namespace}.{cls.Name}";
                sb.AppendLine($"  ['{EscapeLua(className)}'] = {{");
                foreach (var f in instanceFields)
                    sb.AppendLine($"    ['{EscapeLua(f.Name)}'] = 0x{f.FieldOffset:X},");
                sb.AppendLine("  },");
                count++;
                if (count > 2000) break;
            }
            sb.AppendLine("}");
            sb.AppendLine();

            // Helpers
            sb.AppendLine(@"-- ===== Helpers =====
function patchNop(methodName)
  local offset = methods[methodName]
  if not offset then gg.toast('Method not found: ' .. methodName); return end
  local addr = base + offset
  -- ARM64 NOP = 0xD503201F, ARM32 NOP = 0xE320F000, x86 NOP = 0x90
  gg.setValues({{address = addr, flags = gg.TYPE_DWORD, value = 0xD503201F}})
  gg.toast('Patched: ' .. methodName)
end

function patchReturnTrue(methodName)
  local offset = methods[methodName]
  if not offset then gg.toast('Method not found: ' .. methodName); return end
  local addr = base + offset
  -- ARM64: MOV W0, #1; RET
  gg.setValues({
    {address = addr, flags = gg.TYPE_DWORD, value = 0x52800020},
    {address = addr + 4, flags = gg.TYPE_DWORD, value = 0xD65F03C0},
  })
  gg.toast('Return true: ' .. methodName)
end

function patchReturnFalse(methodName)
  local offset = methods[methodName]
  if not offset then gg.toast('Method not found: ' .. methodName); return end
  local addr = base + offset
  -- ARM64: MOV W0, #0; RET
  gg.setValues({
    {address = addr, flags = gg.TYPE_DWORD, value = 0x52800000},
    {address = addr + 4, flags = gg.TYPE_DWORD, value = 0xD65F03C0},
  })
  gg.toast('Return false: ' .. methodName)
end");
            sb.AppendLine();
            sb.AppendLine("-- Example: patchReturnTrue('AntiCheat.IsDetected')");

            return sb.ToString();
        }

        private static string SanitizeJsIdentifier(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_empty";
            return name.Replace("'", "\\'").Replace("\\", "\\\\");
        }

        private static string EscapeLua(string name)
        {
            if (string.IsNullOrEmpty(name)) return "_empty";
            return name.Replace("'", "\\'").Replace("\\", "\\\\");
        }
    }
}
