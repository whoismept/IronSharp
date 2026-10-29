using System.Collections.Generic;
using System.Linq;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    internal class CVECheck
    {
        private const string Category = "Missing updates";

        // Uses the embedded dataset.
        public static void CheckAll()
        {
            CheckAll(null);
        }

        // overrideJson: when supplied (e.g. from --online), use it instead of the
        // embedded dataset.
        public static void CheckAll(string overrideJson)
        {
            var kb = GetWMIQuery.GetInstalledKBs();
            int build = GetWMIQuery.GetBuildNumber();

            string json = overrideJson ?? CveData.LoadEmbeddedJson();
            var records = CveData.Load(json);

            int vuln = 0;
            foreach (var rec in records)
            {
                int[] kbsForBuild;
                if (!rec.Builds.TryGetValue(build, out kbsForBuild) || kbsForBuild.Length == 0)
                {
                    continue; // this build is not listed as affected
                }
                bool patched = kbsForBuild.Any(k => kb.Contains(k));
                if (!patched)
                {
                    Report.Weak(Category, rec.Id + " - " + rec.Title, ParseSeverity(rec.Severity),
                        "This Windows build appears unpatched (no fixing KB for it was found among installed updates).",
                        "Install the latest cumulative security update for this Windows build.",
                        "Microsoft Security Update Guide: " + rec.Id);
                    vuln++;
                }
            }

            if (vuln == 0)
            {
                Report.Ok(Category, "Known patch-level CVEs",
                    "No listed CVE matched as unpatched for build " + build +
                    " (" + records.Count + " CVEs in dataset).");
            }
        }

        private static Severity ParseSeverity(string s)
        {
            if (s != null)
            {
                switch (s.Trim().ToLowerInvariant())
                {
                    case "high": return Severity.High;
                    case "medium": return Severity.Medium;
                    case "low": return Severity.Low;
                }
            }
            return Severity.High;
        }
    }
}
