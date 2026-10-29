using Microsoft.Win32;
using System;

namespace IronSharp.Utilities
{
    internal class AlwaysInstallElevated
    {
        private const string SubKey = @"SOFTWARE\Policies\Microsoft\Windows\Installer";
        private const string ValueName = "AlwaysInstallElevated";

        public static void AlwaysInstallElevatedCheck()
        {
            // The policy is only exploitable when BOTH HKLM and HKCU are set to 1.
            bool hklm = ReadDword(Registry.LocalMachine) == 1;
            bool hkcu = ReadDword(Registry.CurrentUser) == 1;

            if (hklm && hkcu)
            {
                Console.WriteLine("[+] AlwaysInstallElevated is enabled in BOTH HKLM and HKCU - exploitable.");
            }
            else if (hklm || hkcu)
            {
                Console.WriteLine("[-] AlwaysInstallElevated is only set in {0} - not exploitable on its own (both hives must be 1).",
                    hklm ? "HKLM" : "HKCU");
            }
            else
            {
                Console.WriteLine("[-] AlwaysInstallElevated is not enabled.");
            }
        }

        private static int ReadDword(RegistryKey hive)
        {
            try
            {
                using (RegistryKey sk = hive.OpenSubKey(SubKey))
                {
                    if (sk == null) return 0;
                    object value = sk.GetValue(ValueName);
                    if (value == null) return 0;
                    int result;
                    return int.TryParse(value.ToString(), out result) ? result : 0;
                }
            }
            catch
            {
                return 0;
            }
        }
    }
}
