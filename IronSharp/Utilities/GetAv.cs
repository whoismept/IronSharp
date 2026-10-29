using System;
using System.Linq;
using System.Management;

namespace IronSharp.Utilities
{
    public class GetAv
    {
        public static void CheckSecurityProduct()
        {
            bool found = false;

            // SecurityCenter2 is the namespace used on Windows Vista and later.
            // The old SecurityCenter namespace only exists on XP-era systems and
            // throws on modern Windows, so query it defensively.
            found |= QueryNamespace(@"root\SecurityCenter2");
            found |= QueryNamespace(@"root\SecurityCenter");

            if (!found)
            {
                Console.WriteLine("[-] No registered AV/EDR product reported by SecurityCenter.");
            }
        }

        private static bool QueryNamespace(string wmiNamespace)
        {
            bool any = false;
            try
            {
                var scope = string.Format(@"\\{0}\{1}", Environment.MachineName, wmiNamespace);
                using (var searcher = new ManagementObjectSearcher(scope, "SELECT * FROM AntivirusProduct"))
                {
                    foreach (var instance in searcher.Get().OfType<ManagementObject>())
                    {
                        var props = instance.Properties.OfType<PropertyData>();
                        var nameProp = props.FirstOrDefault(p => p.Name == "displayName");
                        if (nameProp != null && nameProp.Value != null)
                        {
                            Console.WriteLine("[+] {0}", nameProp.Value);
                            any = true;
                        }
                    }
                }
            }
            catch (ManagementException)
            {
                // Namespace not present on this OS version; ignore.
            }
            catch (Exception e)
            {
                Console.Error.WriteLine("[!] AV query failed ({0}): {1}", wmiNamespace, e.Message);
            }
            return any;
        }
    }
}
