using System;
using Microsoft.Win32;


namespace IronSharp
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Information.Banner();
            Console.WriteLine("-----------------------");
            Console.WriteLine("[+] OS Name: " + Utilities.GetWMIQuery.GetOSName());
            if (!Utilities.GetWMIQuery.GetOSName().Contains("Server"))
            {
                Console.WriteLine("[+] Windows Display Version: " + Utilities.RegistryUtilities.GetVersionFromRegistry());
            }
            Console.WriteLine("[+] Windows Build Name: " + Utilities.GetWMIQuery.GetBuildNumber());
            Console.WriteLine("[+] Windows Release ID: " + Utilities.RegistryUtilities.GetReleaseIdFromRegistiry());
            Console.WriteLine("------------------------");
            Console.WriteLine("[+] Checking installed Kb list...");
            var installedKBs = Utilities.GetWMIQuery.GetInstalledKBs();
            foreach (var kb in installedKBs)
            {
                Console.WriteLine("    KB: {0}", kb);
            }
            Console.WriteLine("    Installed KB Count: " + installedKBs.Count);
            Console.WriteLine("------------------------");
            Console.WriteLine("[*] Listing Unquoted Paths");
            Utilities.UnquotedPathCheck.CheckUnquotedPath();
            Console.WriteLine("------------------------");
            Console.WriteLine("[*] Checking Vulnerabilities");
            Utilities.CVECheck.CheckAll();
            Console.WriteLine("------------------------");
            Console.WriteLine("[*] Hijackable Paths");
            Utilities.HijackablePaths.HighjackablePaths();
            Console.WriteLine("------------------------");
            Console.WriteLine("[*] Modifiable binaries saved as Registry AutoRun List");
            Utilities.ModifiableAutorun.CheckAutoRun();
            Console.WriteLine("------------------------");
            Console.WriteLine("[*] Modifiable keys");
            Utilities.ModifiableKeys.ModifiableKey();
            Console.WriteLine("------------------------");
            Console.WriteLine("[*] Always Install Elevated");
            Utilities.AlwaysInstallElevated.AlwaysInstallElevatedCheck();
            Console.WriteLine("------------------------");
            Console.WriteLine("[*] Autologon");
            Utilities.AutoLogon.LoginCheck();
        }
    }
}
