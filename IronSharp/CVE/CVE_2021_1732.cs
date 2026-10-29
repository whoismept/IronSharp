using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.CVE
{
    internal class CVE_2021_1732
    {
        public static bool Check(int buildnumber, List<int> installedkblist)
        {
            var vulnkblist = new List<int>();
            switch (buildnumber)
            {
                case 19042:
                    vulnkblist.AddRange(new int[] {
                        4601319
                    });
                    break;
                case 19041:
                    vulnkblist.AddRange(new int[] {
                        4601319
                    });
                    break;
                case 18363:
                    vulnkblist.AddRange(new int[] {
                        4601315
                    });
                    break;
                case 17763:
                    vulnkblist.AddRange(new int[] {
                        4601345
                    });
                    break;
                case 17134:
                    vulnkblist.AddRange(new int[] {
                        4601345
                    });
                    break;
                default:
                    break;
            }
            return vulnkblist.Any() && !vulnkblist.Intersect(installedkblist).Any();
        }
    }
}
