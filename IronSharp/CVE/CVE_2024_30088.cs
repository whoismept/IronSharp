using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    // Windows Kernel Elevation of Privilege (TOCTOU race condition).
    // Patched in the June 2024 cumulative updates. Actively exploited
    // (added to the CISA Known Exploited Vulnerabilities catalog); allows
    // a local attacker to gain SYSTEM.
    internal class CVE_2024_30088
    {
        public static bool Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 10240: // Windows 10 1507
                    vulnkblist.AddRange(new int[] { 5039225 });
                    break;
                case 14393: // Windows 10 1607 / Server 2016
                    vulnkblist.AddRange(new int[] { 5039214 });
                    break;
                case 17763: // Windows 10 1809 / Server 2019
                    vulnkblist.AddRange(new int[] { 5039217 });
                    break;
                case 19044: // Windows 10 21H2
                case 19045: // Windows 10 22H2
                    vulnkblist.AddRange(new int[] { 5039211 });
                    break;
                case 20348: // Windows Server 2022
                    vulnkblist.AddRange(new int[] { 5039227 });
                    break;
                case 22000: // Windows 11 21H2
                    vulnkblist.AddRange(new int[] { 5039213 });
                    break;
                case 22621: // Windows 11 22H2
                case 22631: // Windows 11 23H2
                    vulnkblist.AddRange(new int[] { 5039212 });
                    break;
                default:
                    break;
            }
            return vulnkblist.Any() && !vulnkblist.Intersect(installedkblist).Any();
        }
    }
}
