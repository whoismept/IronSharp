using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    internal class CVE_2020_0787
    {
        public static void Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 16299:
                    vulnkblist.AddRange(new int[] {
                        4540681
                    });
                    break;
                case 17763:
                    vulnkblist.AddRange(new int[] {
                        4538461
                    });
                    break;
                case 17134:
                    vulnkblist.AddRange(new int[] {
                        4540689
                    });
                    break;
                case 18362:
                    vulnkblist.AddRange(new int[] {
                        4540673
                    });
                    break;
                case 18363:
                    vulnkblist.AddRange(new int[] {
                        4540673
                    });
                    break;
                default:
                    break;
            }
            if (vulnkblist.Intersect(installedkblist).Any())
            {
                Console.WriteLine("Vulnerable for CVE-2020-0787");
            }
        }
    }
}
