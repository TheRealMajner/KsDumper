using KsDumperClient.PE;

using static KsDumperClient.PE.NativePEStructs;

namespace KsDumperClient.Utility
{
    public static class PEProtectionBypass
    {
        public static void StripAll(PEFile pe)
        {
            StripChecksum(pe);
            StripForceIntegrity(pe);
            StripCFG(pe);
            StripASLR(pe);
            StripSecurityDirectory(pe);
            StripLoadConfig(pe);
        }

        public static void StripChecksum(PEFile pe)
        {
            if (pe is PE64File pe64)
                pe64.PEHeader.OptionalHeader.CheckSum = 0;
            else if (pe is PE32File pe32)
                pe32.PEHeader.OptionalHeader.CheckSum = 0;
        }

        public static void StripForceIntegrity(PEFile pe)
        {
            ushort mask = unchecked((ushort)~IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY);
            if (pe is PE64File pe64)
                pe64.PEHeader.OptionalHeader.DllCharacteristics &= mask;
            else if (pe is PE32File pe32)
                pe32.PEHeader.OptionalHeader.DllCharacteristics &= mask;
        }

        public static void StripCFG(PEFile pe)
        {
            ushort mask = unchecked((ushort)~IMAGE_DLLCHARACTERISTICS_GUARD_CF);
            if (pe is PE64File pe64)
            {
                pe64.PEHeader.OptionalHeader.DllCharacteristics &= mask;
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
            }
            else if (pe is PE32File pe32)
            {
                pe32.PEHeader.OptionalHeader.DllCharacteristics &= mask;
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
            }
        }

        public static void StripASLR(PEFile pe)
        {
            ushort mask = (ushort)(IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA);
            ushort inverse = unchecked((ushort)~mask);
            if (pe is PE64File pe64)
                pe64.PEHeader.OptionalHeader.DllCharacteristics &= inverse;
            else if (pe is PE32File pe32)
                pe32.PEHeader.OptionalHeader.DllCharacteristics &= inverse;
        }

        public static void StripSecurityDirectory(PEFile pe)
        {
            if (pe is PE64File pe64)
            {
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
            }
            else if (pe is PE32File pe32)
            {
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = 0;
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = 0;
            }
        }

        public static void StripLoadConfig(PEFile pe)
        {
            if (pe is PE64File pe64)
            {
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
                pe64.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
            }
            else if (pe is PE32File pe32)
            {
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
                pe32.PEHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
            }
        }
    }
}
