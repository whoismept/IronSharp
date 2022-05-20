using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    internal class CVE_2021_42278
    {
        public static void Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 18363:
                    vulnkblist.AddRange(new int[] {
                        5008102
                    });
                    break;
                case 19042:
                    vulnkblist.AddRange(new int[] {
                        5008102
                    });
                    break;
                case 19043:
                    vulnkblist.AddRange(new int[] {
                        5008102
                    });
                    break;
                case 20348:
                    vulnkblist.AddRange(new int[] {
                        5008102
                    });
                    break;
                case 22000:
                    vulnkblist.AddRange(new int[] {
                        5008102
                    });
                    break;
                default:
                    break;
            }
            if (vulnkblist.Intersect(installedkblist).Any())
            {
                Console.WriteLine("Vulnerable for sAMAccountName spoofing (CVE-2021-42278)");
            }
        }
    }
}
