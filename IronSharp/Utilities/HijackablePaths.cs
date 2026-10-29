using System;
using System.Security.AccessControl;

namespace IronSharp.Utilities
{
    public class HijackablePaths
    {
        const string regPath = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        const string regName = "Path";

        public static void HighjackablePaths()
        {
            string registrypath = RegistryUtilities.GetRegistryValue("HKLM", regPath, regName);
            if (string.IsNullOrEmpty(registrypath))
            {
                Console.WriteLine("[-] Could not read machine %PATH%");
                return;
            }

            foreach (var item in registrypath.Split(';'))
            {
                if (!string.IsNullOrEmpty(item))
                {
                    AccessControl.CheckPermission(item, FileSystemRights.Write);
                }
            }
        }
    }
}

//specialthanks to: https://github.com/erdemstar
