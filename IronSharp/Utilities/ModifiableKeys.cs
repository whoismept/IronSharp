using Microsoft.Win32;
using System.Collections.Generic;
using System.ServiceProcess;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    internal class ModifiableKeys
    {
        private const string Category = "Service configuration";

        public static void ModifiableKey()
        {
            var modifiable = new List<string>();
            ServiceController[] scServices;
            try
            {
                scServices = ServiceController.GetServices();
            }
            catch
            {
                return;
            }

            foreach (ServiceController sc in scServices)
            {
                try
                {
                    string subKey = "SYSTEM\\CurrentControlSet\\Services\\" + sc.ServiceName;
                    RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey);
                    if (RegistryUtilities.IsModifiable(key))
                    {
                        modifiable.Add(sc.ServiceName);
                    }
                }
                catch { }
            }

            if (modifiable.Count == 0)
            {
                Report.Ok(Category, "Modifiable service registry keys", "None writable by the current user.");
            }
            else
            {
                Report.Weak(Category, "User-modifiable service registry keys", Severity.High,
                    "The current user can modify the registry key of service(s): " + string.Join(", ", modifiable),
                    "Restrict write access on these HKLM\\SYSTEM\\CurrentControlSet\\Services keys to administrators; a user who can repoint ImagePath gains the service's privileges.",
                    "CIS - registry permissions");
            }
        }
    }
}
