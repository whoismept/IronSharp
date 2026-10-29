using System.Collections.Generic;
using System.Linq;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    internal class CVECheck
    {
        private const string Category = "Missing updates";

        public static void CheckAll()
        {
            CheckAll(null);
        }

        // overrideJson: when supplied (e.g. from --online or --data) it is used
        // instead of the embedded dataset.
        public static void CheckAll(string overrideJson)
        {
            int build = GetWMIQuery.GetBuildNumber();
            int? ubrNullable = RegistryUtilities.GetHklmDword(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");

            string json = overrideJson ?? CveData.LoadEmbeddedJson();
            var records = CveData.Load(json);

            // Gather, for this build, the CVE fixes that carry a revision (UBR).
            int latest = 0;
            var gaps = new List<CveRecord>();
            int covered = 0;
            foreach (var rec in records)
            {
                BuildFix fix;
                if (!rec.Builds.TryGetValue(build, out fix) || fix.Ubr <= 0)
                {
                    continue;
                }
                covered++;
                if (fix.Ubr > latest) latest = fix.Ubr;
                if (ubrNullable.HasValue && ubrNullable.Value < fix.Ubr)
                {
                    gaps.Add(rec);
                }
            }

            if (covered == 0)
            {
                Report.Ok(Category, "Patch level",
                    "No build-revision data for build " + build + " in the dataset (" + records.Count + " CVEs).");
                return;
            }
            if (!ubrNullable.HasValue)
            {
                Report.Weak(Category, "Patch level could not be determined", Severity.Low,
                    "The build revision (UBR) could not be read, so missing updates cannot be assessed.",
                    "Run from an elevated prompt, or check Windows Update manually.",
                    "Windows release health");
                return;
            }

            int ubr = ubrNullable.Value;
            if (gaps.Count == 0)
            {
                Report.Ok(Category, "Patch level",
                    "Build " + build + "." + ubr + " is at or above the latest fix revision in the dataset (." + latest + ").");
                return;
            }

            int high = gaps.Count(g => Eq(g.Severity, "high"));
            int med = gaps.Count(g => Eq(g.Severity, "medium"));
            int low = gaps.Count - high - med;
            int kev = gaps.Count(g => g.Kev);
            // List every missing fix, actively-exploited (KEV) first then newest.
            var affected = gaps
                .OrderByDescending(g => g.Kev)
                .ThenByDescending(g => g.Builds[build].Ubr)
                .Select(g => g.Kev ? g.Id + "*  (ACTIVELY EXPLOITED - CISA KEV)" : g.Id)
                .ToList();

            string kevText = kev > 0
                ? " " + kev + " are ACTIVELY EXPLOITED (CISA KEV, marked *)."
                : "";

            Report.Weak(Category, "Windows build is behind on security updates", Severity.High,
                "Build " + build + "." + ubr + " is below the latest fix revision ." + latest +
                ". " + gaps.Count + " Windows EoP/RCE CVE fix(es) were released after this revision" +
                " (High: " + high + ", Medium: " + med + ", Low: " + low + ")." + kevText,
                affected,
                "Install the latest cumulative update for this build to reach revision ." + latest + " or newer."
                + (kev > 0 ? " Prioritise: actively-exploited issues are unpatched." : ""),
                "MSRC Security Update Guide / CISA KEV / Windows release health");
        }

        private static bool Eq(string a, string b)
        {
            return a != null && a.Trim().ToLowerInvariant() == b;
        }
    }
}
