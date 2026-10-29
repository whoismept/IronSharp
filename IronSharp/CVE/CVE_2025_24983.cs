using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    // Windows Win32 Kernel Subsystem (Win32k) Elevation of Privilege
    // (use-after-free). Patched in the March 2025 cumulative updates. Exploited
    // in the wild (PipeMagic) and listed in the CISA Known Exploited
    // Vulnerabilities catalog. Per the reporter (ESET) it only affects builds
    // before Windows 10 1809, so it is scoped to those legacy builds only.
    internal class CVE_2025_24983
    {
        public static bool Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 9600: // Windows Server 2012 R2
                    vulnkblist.AddRange(new int[] { 5053887 });
                    break;
                case 10240: // Windows 10 1507
                    vulnkblist.AddRange(new int[] { 5053618 });
                    break;
                case 14393: // Windows 10 1607 / Server 2016
                    vulnkblist.AddRange(new int[] { 5053594 });
                    break;
                default:
                    break;
            }
            return vulnkblist.Any() && !vulnkblist.Intersect(installedkblist).Any();
        }
    }
}
