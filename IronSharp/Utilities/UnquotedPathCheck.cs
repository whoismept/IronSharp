using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Win32;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    internal class UnquotedPathCheck
    {
        private const string Category = "Service configuration";

        public static void CheckUnquotedPath()
        {
            List<string> vulnSvcs = new List<string>();
            RegistryKey services = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\");
            if (services == null)
            {
                return;
            }
            foreach (var service in services.GetSubKeyNames())
            {
                RegistryKey imagePath = services.OpenSubKey(service);
                if (imagePath == null)
                {
                    continue;
                }
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
            List<string> distinctPaths = vulnSvcs.Distinct().ToList();
            if (!distinctPaths.Any())
            {
                Report.Ok(Category, "Unquoted service paths", "None found.");
            }
            else
            {
                Report.Weak(Category, "Unquoted service paths", Severity.Medium,
                    distinctPaths.Count + " service(s) with an unquoted path containing spaces:",
                    distinctPaths,
                    "Wrap each affected service ImagePath in double quotes so a planted binary in a parent folder cannot be launched.",
                    "CIS / common Windows service hardening");
            }
        }
    }
}
