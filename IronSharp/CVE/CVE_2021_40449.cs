using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    internal class CVE_2021_40449
    {
        public static void Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 14393:
                    vulnkblist.AddRange(new int[] {
                        5006669
                    });
                    break;
                case 17763:
                    vulnkblist.AddRange(new int[] {
                        5006672
                    });
                    break;
                case 18363:
                    vulnkblist.AddRange(new int[] {
                        5009543
                    });
                    break;
                case 19043:
                    vulnkblist.AddRange(new int[] {
                        5009543
                    });
                    break;
                case 20348:
                    vulnkblist.AddRange(new int[] {
                        5009555
                    });
                    break;
                case 22000:
                    vulnkblist.AddRange(new int[] {
                        5009566
                    });
                    break;
                default:
                    break;
            }
            if (vulnkblist.Intersect(installedkblist).Any())
            {
                Console.WriteLine("Vulnerable for CVE-2022-21882");
            }
        }
    }
}
