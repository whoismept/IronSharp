using System;
using System.Collections.Generic;

namespace IronSharp.Utilities
{
    internal class CVECheck
    {
        public static void CheckAll()
        {
            //Name / Description                        Build Number
            //Windows Server 2012 R2                    9600
            //Windows 10, Version 1507                  10240
            //Windows 10, Version 1511                  10586
            //Windows 10, Version 1607                  14393
            //Windows Server 2016, Version 1607         14393
            //Windows 10, Version 1703                  15063
            //Windows 10, Version 1709                  16299
            //Windows 10, Version 1803                  17134
            //Windows Server 2019, Version 1809         17763
            //Windows 10, Version 1809                  17763
            //Windows 10, Version 1903                  18362
            //Windows 10, Version 1909                  18363
            //Windows Server, Version 1909              18363
            //Windows 10, Version 2004                  19041
            //Windows Server, Version 2004              19041
            //Windows 10, Version 20H2                  19042
            //Windows Server, Version 20H2              19042
            //Windows 10, Version 21H1                  19043
            //Windows Server 2022                       20348
            //Windows 11, Version 21H2                  22000

            var kblist = Utilities.GetWMIQuery.GetInstalledKBs();
            var buildnumber = Utilities.GetWMIQuery.GetBuildNumber();
            CVE.CVE_2019_0836.Check(buildnumber, kblist);
            CVE.CVE_2019_0841.Check(buildnumber, kblist);
            CVE.CVE_2019_1064.Check(buildnumber, kblist);
            CVE.CVE_2019_1130.Check(buildnumber, kblist);
            CVE.CVE_2019_1253.Check(buildnumber, kblist);
            CVE.CVE_2019_1315.Check(buildnumber, kblist);
            CVE.CVE_2019_1385.Check(buildnumber, kblist);
            CVE.CVE_2019_1388.Check(buildnumber, kblist);
            CVE.CVE_2019_1405.Check(buildnumber, kblist);
            CVE.CVE_2020_0668.Check(buildnumber, kblist);
            CVE.CVE_2020_0683.Check(buildnumber, kblist);
            CVE.CVE_2020_0787.Check(buildnumber, kblist);
            CVE.CVE_2020_0796.Check(buildnumber, kblist);
            CVE.CVE_2020_1013.Check(buildnumber, kblist);
            CVE.CVE_2021_1732.Check(buildnumber, kblist);
            CVE.CVE_2021_34527.Check(buildnumber, kblist);
            CVE.CVE_2021_40449.Check(buildnumber, kblist);
            CVE.CVE_2022_21882.Check(buildnumber, kblist);
            CVE.CVE_2021_42278.Check(buildnumber, kblist);
        }
    }
}
