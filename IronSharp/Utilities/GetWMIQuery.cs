using System;
using System.Collections.Generic;
using System.Management;

namespace IronSharp.Utilities
{
    internal class GetWMIQuery
    {
        public static List<int> GetInstalledKBs()
        {
            var KbList = new List<int>();
            try
            {
                var searcher = new ManagementObjectSearcher(@"root\cimv2", "SELECT HotFixID FROM Win32_QuickFixEngineering");
                var hotFixes = searcher.Get();
                foreach (var hotFix in hotFixes)
                {
                   var line = hotFix["HotFixID"].ToString().Remove(0, 2);
                   if (int.TryParse(line, out int kb))
                   {
                     KbList.Add(kb);  
                   }
                }
            }
            catch (ManagementException e)
            {
                Console.Error.WriteLine(" [!] {0}", e.Message);
            }
            return KbList;
        }
        public static int GetBuildNumber()
        {
            try
            {
                var searcher = new ManagementObjectSearcher(@"root\cimv2", "SELECT BuildNumber FROM Win32_OperatingSystem");
                var collection = searcher.Get();
                foreach (var num in collection)
                {
                    if (int.TryParse(num["BuildNumber"] as string, out int buildNumber))
                    {
                        return buildNumber;
                    }
                }
            }
            catch (ManagementException e)
            {
                Console.Error.WriteLine("[!] {0}", e.Message);
            }
            return 0;
        }
        public static string GetOSName()
        {
            try
            {
                var searcher = new ManagementObjectSearcher(@"root\cimv2", "SELECT Caption FROM Win32_OperatingSystem");
                var details = searcher.Get();
                foreach (var item in details)
                {
                    var operatingSystem = item["Caption"].ToString();
                    return operatingSystem;
                }
            }
            catch (ManagementException e)
            {
                Console.WriteLine("[!] {0}",e.Message);
                throw;
            }
            return "";
        }
       
    }
}
