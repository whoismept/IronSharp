using System.Collections.Generic;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    internal class CVECheck
    {
        private const string Category = "Missing updates";

        public static void CheckAll()
        {
            var kb = GetWMIQuery.GetInstalledKBs();
            int build = GetWMIQuery.GetBuildNumber();

            int vulnCount = 0;
            vulnCount += Eval("CVE-2019-0836", "Windows Elevation of Privilege", CVE.CVE_2019_0836.Check(build, kb));
            vulnCount += Eval("CVE-2019-0841", "Windows AppX Deployment EoP", CVE.CVE_2019_0841.Check(build, kb));
            vulnCount += Eval("CVE-2019-1064", "Windows Elevation of Privilege", CVE.CVE_2019_1064.Check(build, kb));
            vulnCount += Eval("CVE-2019-1130", "Windows Elevation of Privilege", CVE.CVE_2019_1130.Check(build, kb));
            vulnCount += Eval("CVE-2019-1253", "Windows Kernel EoP", CVE.CVE_2019_1253.Check(build, kb));
            vulnCount += Eval("CVE-2019-1315", "Windows Error Reporting EoP", CVE.CVE_2019_1315.Check(build, kb));
            vulnCount += Eval("CVE-2019-1385", "Windows AppX Deployment EoP", CVE.CVE_2019_1385.Check(build, kb));
            vulnCount += Eval("CVE-2019-1388", "Windows UAC / certificate dialog EoP", CVE.CVE_2019_1388.Check(build, kb));
            vulnCount += Eval("CVE-2019-1405", "Windows UPnP EoP", CVE.CVE_2019_1405.Check(build, kb));
            vulnCount += Eval("CVE-2020-0668", "Windows Kernel (service tracing) EoP", CVE.CVE_2020_0668.Check(build, kb));
            vulnCount += Eval("CVE-2020-0683", "Windows Installer EoP", CVE.CVE_2020_0683.Check(build, kb));
            vulnCount += Eval("CVE-2020-0787", "Windows BITS EoP", CVE.CVE_2020_0787.Check(build, kb));
            vulnCount += Eval("CVE-2020-0796", "SMBv3 'SMBGhost' RCE/EoP", CVE.CVE_2020_0796.Check(build, kb));
            vulnCount += Eval("CVE-2020-1013", "WSUS / WPAD EoP", CVE.CVE_2020_1013.Check(build, kb));
            vulnCount += Eval("CVE-2021-1732", "Win32k EoP (exploited)", CVE.CVE_2021_1732.Check(build, kb));
            vulnCount += Eval("CVE-2021-34527", "Print Spooler 'PrintNightmare' RCE/EoP", CVE.CVE_2021_34527.Check(build, kb));
            vulnCount += Eval("CVE-2021-40449", "Win32k EoP (exploited)", CVE.CVE_2021_40449.Check(build, kb));
            vulnCount += Eval("CVE-2021-42278", "Active Directory sAMAccountName spoofing", CVE.CVE_2021_42278.Check(build, kb));
            vulnCount += Eval("CVE-2022-21882", "Win32k EoP (exploited)", CVE.CVE_2022_21882.Check(build, kb));
            vulnCount += Eval("CVE-2023-28252", "CLFS Driver EoP (exploited)", CVE.CVE_2023_28252.Check(build, kb));
            vulnCount += Eval("CVE-2024-30088", "Windows Kernel EoP (CISA KEV)", CVE.CVE_2024_30088.Check(build, kb));
            vulnCount += Eval("CVE-2025-24983", "Win32k EoP (CISA KEV, legacy builds)", CVE.CVE_2025_24983.Check(build, kb));
            vulnCount += Eval("CVE-2025-29824", "CLFS Driver EoP (CISA KEV)", CVE.CVE_2025_29824.Check(build, kb));

            if (vulnCount == 0)
            {
                Report.Ok(Category, "Known patch-level CVEs",
                    "No supported CVE matched as unpatched for build " + build + ".");
            }
        }

        private static int Eval(string id, string title, bool vulnerable)
        {
            if (!vulnerable)
            {
                return 0;
            }
            Report.Weak(Category, id + " - " + title, Severity.High,
                "This Windows build appears unpatched (no fixing KB for it was found among installed updates).",
                "Install the latest cumulative security update for this Windows build.",
                "Microsoft Security Update Guide: " + id);
            return 1;
        }
    }
}
