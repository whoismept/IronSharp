using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    internal class CVE_2021_34527
    {
        public static void Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 14393:
                    vulnkblist.AddRange(new int[] {
                        5004948
                    });
                    break;
                case 17763:
                    vulnkblist.AddRange(new int[] {
                        5004947
                    });
                    break;
                case 18363:
                    vulnkblist.AddRange(new int[] {
                        5004946
                    });
                    break;
                case 19043:
                    vulnkblist.AddRange(new int[] {
                        5004945
                    });
                    break;
                case 19042:
                    vulnkblist.AddRange(new int[] {
                        5004945
                    });
                    break;
                case 19041:
                    vulnkblist.AddRange(new int[] {
                        5004945
                    });
                    break;
                default:
                    break;
            }
            if (vulnkblist.Intersect(installedkblist).Any())
            {
                Console.WriteLine("Vulnerable for CVE-2021-34527");
            }
        }
    }
}
