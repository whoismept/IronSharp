using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    internal class CVE_2020_1013
    {
        public static void Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 10240:
                    vulnkblist.AddRange(new int[] {
                        4577049
                    });
                    break;
                case 14393:
                    vulnkblist.AddRange(new int[] {
                        4577015
                    });
                    break;
                case 16299:
                    vulnkblist.AddRange(new int[] {
                        4577041
                    });
                    break;
                case 17134:
                    vulnkblist.AddRange(new int[] {
                        4577032
                    });
                    break;
                case 17763:
                    vulnkblist.AddRange(new int[] {
                        4570333, 4577069
                    });
                    break;
                case 18362:
                    vulnkblist.AddRange(new int[] {
                        4574727, 4577062
                    });
                    break;
                case 18363:
                    vulnkblist.AddRange(new int[] {
                        4574727, 4577062
                    });
                    break;
                case 19041:
                    vulnkblist.AddRange(new int[] {
                        4571756, 4577063
                    });
                    break;
                default:
                    break;
            }
            if (vulnkblist.Intersect(installedkblist).Any())
            {
                Console.WriteLine("Vulnerable for CVE-2020-0683");
            }
        }
    }
}
