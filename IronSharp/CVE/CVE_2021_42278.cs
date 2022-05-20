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
                case 9600:
                    vulnkblist.AddRange(new int[] {
                        5007247,
                        5007255
                    });
                    break;
                case 17763:
                    vulnkblist.AddRange(new int[] {
                        5007206
                    });
                    break;
                case 19041:
                    vulnkblist.AddRange(new int[] {
                        5007186
                    });
                    break;
                case 14393:
                    vulnkblist.AddRange(new int[] {
                        5007192
                    });
                    break;
                case 7601:
                    vulnkblist.AddRange(new int[] {
                        5007236, 5007233
                    });
                    break;
                case 20348:
                    vulnkblist.AddRange(new int[] {
                        5007205
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
