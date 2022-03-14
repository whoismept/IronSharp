using Microsoft.Win32;
using System;
using System.Management;
using System.ServiceProcess;

namespace IronSharp.Utilities
{
    internal class ModifiableKeys
    {
        public static void ModifiableKey()
        {
            ServiceController[] scServices;
            scServices = ServiceController.GetServices();
            foreach (ServiceController sc in scServices)
            {
                try
                {
                    RegistryKey key = Registry.LocalMachine.OpenSubKey("SYSTEM\\CurrentControlSet\\Services\\" + sc.ServiceName);
                    if (RegistryUtilities.IsModifiable(key))
                    {
                        ManagementObjectSearcher wmiData = new ManagementObjectSearcher(@"root\cimv2", String.Format("SELECT * FROM win32_service WHERE Name LIKE '{0}'", sc.ServiceName));
                        ManagementObjectCollection data = wmiData.Get();
                        foreach (ManagementObject result in data)
                        {
                            Console.WriteLine("Modifiable key found :" +
                                         $"{"SYSTEM\\CurrentControlSet\\Services\\" + sc.ServiceName}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"[X] Exception: {ex.Message}");
                }
            }
        }
    }
}
