using Microsoft.Win32;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    internal class AlwaysInstallElevated
    {
        private const string SubKey = @"SOFTWARE\Policies\Microsoft\Windows\Installer";
        private const string ValueName = "AlwaysInstallElevated";
        private const string Category = "Privilege escalation";

        public static void AlwaysInstallElevatedCheck()
        {
            bool hklm = ReadDword(Registry.LocalMachine) == 1;
            bool hkcu = ReadDword(Registry.CurrentUser) == 1;

            if (hklm && hkcu)
            {
                Report.Weak(Category, "AlwaysInstallElevated enabled", Severity.High,
                    "Policy is set to 1 in both HKLM and HKCU - any MSI runs as SYSTEM.",
                    "Disable AlwaysInstallElevated in both Computer and User policy (set to 0 or Not Configured).",
                    "CIS 'Always install with elevated privileges' / MS Security Baseline");
            }
            else if (hklm || hkcu)
            {
                Report.Weak(Category, "AlwaysInstallElevated partially set", Severity.Low,
                    "Policy is set in only " + (hklm ? "HKLM" : "HKCU") + " - not exploitable alone, but should be cleared.",
                    "Set AlwaysInstallElevated to 0 / Not Configured in both hives.",
                    "CIS 'Always install with elevated privileges'");
            }
            else
            {
                Report.Ok(Category, "AlwaysInstallElevated", "Not enabled.");
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
