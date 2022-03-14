using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;

namespace IronSharp.Utilities
{
    internal class UnquotedPathCheck
    {
        public static void CheckUnquotedPath()
        {
            List<string> vulnSvcs = new List<string>();
            RegistryKey services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\");
            foreach (var service in services.GetSubKeyNames())
            {
                RegistryKey imagePath = services.OpenSubKey(service);
                foreach (var value in imagePath.GetValueNames())
                {
                    string path = Convert.ToString(imagePath.GetValue("ImagePath"));
                    if (!string.IsNullOrEmpty(path))
                    {
                        if (!path.Contains("\"") && path.Contains(" "))
                        {
                            if (!path.Contains("System32") && !path.Contains("system32") && !path.Contains("SysWow64"))
                            {
                                vulnSvcs.Add(path);
                            }
                        }
                    }
                }
            }
            List<string> distinctPaths = vulnSvcs.Distinct().ToList();
            if (!distinctPaths.Any())
            {
                Console.WriteLine("[-] Couldn't find any unquoted services paths");
            }
            else
            {
                Console.WriteLine("[+] Unquoted service paths found");
                foreach (string path in distinctPaths)
                {
                    Console.WriteLine("Distict Path: " + path);
                }
            }
        }

    }
}
