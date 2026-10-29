using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    // Windows Common Log File System (CLFS) Driver Elevation of Privilege
    // (use-after-free). Patched in the April 2025 cumulative updates. Exploited
    // in the wild as a zero-day (Storm-2460 / RansomEXX, PipeMagic) and listed in
    // the CISA Known Exploited Vulnerabilities catalog; allows SYSTEM.
    internal class CVE_2025_29824
    {
        public static bool Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 10240: // Windows 10 1507 (LTSB 2015)
                    vulnkblist.AddRange(new int[] { 5055547 });
                    break;
                case 14393: // Windows 10 1607 / Server 2016
                    vulnkblist.AddRange(new int[] { 5055521 });
                    break;
                case 17763: // Windows 10 1809 / Server 2019
                    vulnkblist.AddRange(new int[] { 5055519 });
                    break;
                case 19044: // Windows 10 21H2
                case 19045: // Windows 10 22H2
                    vulnkblist.AddRange(new int[] { 5055518 });
                    break;
                case 20348: // Windows Server 2022
                    vulnkblist.AddRange(new int[] { 5055526 });
                    break;
                case 22621: // Windows 11 22H2
                case 22631: // Windows 11 23H2
                    vulnkblist.AddRange(new int[] { 5055528 });
                    break;
                case 26100: // Windows 11 24H2 / Server 2025
                    vulnkblist.AddRange(new int[] { 5055523 });
                    break;
                default:
                    break;
            }
            return vulnkblist.Any() && !vulnkblist.Intersect(installedkblist).Any();
        }
    }
}
