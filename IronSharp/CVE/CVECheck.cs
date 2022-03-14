using System;
using System.Collections.Generic;

namespace IronSharp.CVE
{
    internal class CVECheck
    {
        public static void CheckAll()
        {
            //Name / Description                        Build Number
            //Windows Server 2008                       6001
            //Windows XP, Service Pack 3                2600
            //Windows Vista, Service Pack 2             6002
            //Windows Server 2008, Service Pack 2       6002
            //Windows 7                                 7600
            //Windows Server 2008 R2                    7600
            //Windows 7, Service Pack 1                 7601
            //Windows Server 2008 R2, Service Pack 1    7601
            //Windows Home Server 2011                  8400
            //Windows Server 2012                       9200
            //Windows 8                                 9200
            //Windows 8.1                               9600
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
            CVE_2019_0836.Check(buildnumber, kblist);            
            CVE_2019_0841.Check(buildnumber, kblist);
        }
    }
}
