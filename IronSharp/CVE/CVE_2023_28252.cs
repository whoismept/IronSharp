using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    // Windows Common Log File System (CLFS) Driver Elevation of Privilege.
    // Patched in the April 2023 cumulative updates. Exploited in the wild as
    // a zero-day (Nokoyawa ransomware) and listed in the CISA Known Exploited
    // Vulnerabilities catalog; allows a local attacker to gain SYSTEM.
    internal class CVE_2023_28252
    {
        public static void Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 14393: // Windows 10 1607 / Server 2016
                    vulnkblist.AddRange(new int[] { 5025228 });
                    break;
                case 17763: // Windows 10 1809 / Server 2019
                    vulnkblist.AddRange(new int[] { 5025229 });
                    break;
                case 19042: // Windows 10 20H2
                case 19044: // Windows 10 21H2
                case 19045: // Windows 10 22H2
                    vulnkblist.AddRange(new int[] { 5025221 });
                    break;
                case 20348: // Windows Server 2022
                    vulnkblist.AddRange(new int[] { 5025230 });
                    break;
                case 22000: // Windows 11 21H2
                    vulnkblist.AddRange(new int[] { 5025224 });
                    break;
                case 22621: // Windows 11 22H2
                    vulnkblist.AddRange(new int[] { 5025239 });
                    break;
                default:
                    break;
            }
            if (vulnkblist.Any() && !vulnkblist.Intersect(installedkblist).Any())
            {
                Console.WriteLine("Vulnerable for CLFS Driver EoP (CVE-2023-28252)");
            }
        }
    }
}
