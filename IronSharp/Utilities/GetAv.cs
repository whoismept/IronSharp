using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    public class GetAv
    {
        private const string Category = "Endpoint defense";

        public static void CheckSecurityProduct()
        {
            var products = new List<string>();
            CollectFromNamespace(@"root\SecurityCenter2", products);
            CollectFromNamespace(@"root\SecurityCenter", products);

            var distinct = products.Distinct().ToList();
            if (distinct.Count > 0)
            {
                Report.Ok(Category, "Antivirus / EDR registered", string.Join(", ", distinct));
            }
            else
            {
                Report.Weak(Category, "No antivirus / EDR registered", Severity.Medium,
                    "Windows Security Center reports no registered antivirus product.",
                    "Ensure a supported AV/EDR (e.g. Microsoft Defender) is installed, running and up to date.",
                    "MS Security Baseline - Defender");
            }
        }

        private static void CollectFromNamespace(string wmiNamespace, List<string> products)
        {
            try
            {
                var scope = string.Format(@"\\{0}\{1}", Environment.MachineName, wmiNamespace);
                using (var searcher = new ManagementObjectSearcher(scope, "SELECT * FROM AntivirusProduct"))
                {
                    foreach (var instance in searcher.Get().OfType<ManagementObject>())
                    {
                        var nameProp = instance.Properties.OfType<PropertyData>()
                            .FirstOrDefault(p => p.Name == "displayName");
                        if (nameProp != null && nameProp.Value != null)
                        {
                            products.Add(nameProp.Value.ToString());
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
        }
    }
}
