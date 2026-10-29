using System;
using IronSharp.Core;

namespace IronSharp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Information.Banner();
            PrintSystemInfo();

            // All checks are read-only: they inspect WMI, the registry and file
            // ACLs and record findings. Nothing on the system is modified.
            Utilities.CVECheck.CheckAll();
            Utilities.UnquotedPathCheck.CheckUnquotedPath();
            Utilities.HijackablePaths.HighjackablePaths();
            Utilities.ModifiableAutorun.CheckAutoRun();
            Utilities.ModifiableKeys.ModifiableKey();
            Utilities.AlwaysInstallElevated.AlwaysInstallElevatedCheck();
            Utilities.AutoLogon.LoginCheck();
            Utilities.GetAv.CheckSecurityProduct();

            Report.PrintAll();
            Report.PrintSummary();
        }

        private static void PrintSystemInfo()
        {
            Console.WriteLine("------------------------");
            string os = Utilities.GetWMIQuery.GetOSName();
            Console.WriteLine("[*] OS Name            : " + os);
            if (os != null && !os.Contains("Server"))
            {
                Console.WriteLine("[*] Display Version    : " + Utilities.RegistryUtilities.GetVersionFromRegistry());
            }
            Console.WriteLine("[*] Build Number       : " + Utilities.GetWMIQuery.GetBuildNumber());
            Console.WriteLine("[*] Release ID         : " + Utilities.RegistryUtilities.GetReleaseIdFromRegistiry());
            Console.WriteLine("[*] Installed KB count : " + Utilities.GetWMIQuery.GetInstalledKBs().Count);
            Console.WriteLine("------------------------");
        }
    }
}
