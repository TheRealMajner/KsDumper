using System;
using System.Collections.Generic;

namespace KsDumperClient.Utility
{
    public static class SystemDllFilter
    {
        private static readonly HashSet<string> SystemDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
            "advapi32.dll", "shell32.dll", "ole32.dll", "oleaut32.dll", "msvcrt.dll",
            "combase.dll", "rpcrt4.dll", "sechost.dll", "bcryptprimitives.dll",
            "ucrtbase.dll", "msvcp_win.dll", "win32u.dll", "gdi32full.dll",
            "imm32.dll", "ws2_32.dll", "nsi.dll", "crypt32.dll", "msasn1.dll",
            "d3d11.dll", "dxgi.dll", "d3d9.dll", "dwmapi.dll", "uxtheme.dll",
            "shcore.dll", "comdlg32.dll", "setupapi.dll", "cfgmgr32.dll",
            "clbcatq.dll", "propsys.dll", "version.dll", "winmm.dll",
            "wldap32.dll", "normaliz.dll", "bcrypt.dll", "iphlpapi.dll",
            "dbghelp.dll", "psapi.dll", "avrt.dll", "devobj.dll",
            "dcomp.dll", "dxcore.dll", "mfplat.dll", "mf.dll",
            "msimg32.dll", "winspool.drv", "comctl32.dll",
            "vcruntime140.dll", "msvcp140.dll", "concrt140.dll",
            "vcruntime140_1.dll", "msvcp140_codecvt_ids.dll",
            "vcruntime140_threads.dll", "msvcp140_atomic_wait.dll",
            "msvcp140_1.dll", "msvcp140_2.dll",
            "concrt140_1.dll", "vcomp140.dll", "vccorlib140.dll",
            "mfc140.dll", "mfc140u.dll", "mfcm140.dll", "mfcm140u.dll"
        };

        public static bool IsSystemDll(string moduleName)
        {
            if (string.IsNullOrEmpty(moduleName))
                return false;

            if (SystemDlls.Contains(moduleName))
                return true;

            // Pattern match api-ms-win-* DLLs
            if (moduleName.StartsWith("api-ms-win-", StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        public static bool IsGameModule(ModuleSummary mod)
        {
            return !IsSystemDll(mod.ModuleName);
        }
    }
}
