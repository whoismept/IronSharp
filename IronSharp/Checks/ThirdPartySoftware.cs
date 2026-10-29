using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Win32;
using IronSharp.Core;
using IronSharp.Utilities;

namespace IronSharp.Checks
{
    // Read-only inventory of installed third-party software (from the registry
    // Uninstall keys) matched against a curated NVD-sourced vulnerability
    // dataset. Only products on the curated list are assessed; everything else
    // is reported as "not assessed" so coverage is explicit and false positives
    // are avoided.
    internal static class ThirdPartySoftware
    {
        private const string Category = "Third-party software";
        private const string UninstallPath =
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";

        private class InvItem
        {
            public string Name;
            public string Version;
        }

        public static void Run(string overrideJson)
        {
            string json = overrideJson ?? ThirdPartyData.LoadEmbeddedJson();
            var products = ThirdPartyData.Load(json);

            var inventory = ReadInventory();
            if (inventory.Count == 0)
            {
                Report.Ok(Category, "Installed third-party software",
                    "No installed programs could be enumerated from the registry.");
                return;
            }

            // Pre-normalise aliases once.
            var aliasIndex = products
                .Select(p => new { p, aliases = p.Aliases.Select(Normalize).ToList() })
                .ToList();

            int assessed = 0;
            var notAssessed = new List<string>();

            foreach (var item in inventory)
            {
                string nameNorm = Normalize(item.Name);
                var match = aliasIndex.FirstOrDefault(x => x.aliases.Any(a => AliasMatches(nameNorm, a)));
                if (match == null)
                {
                    notAssessed.Add(item.Name + (string.IsNullOrEmpty(item.Version) ? "" : " " + item.Version));
                    continue;
                }

                assessed++;
                var vuln = match.p.Cves.Where(c => VersionCompare.InRange(item.Version,
                    c.VersionStartIncluding, c.VersionStartExcluding,
                    c.VersionEndIncluding, c.VersionEndExcluding)).ToList();

                if (vuln.Count == 0)
                {
                    continue; // on the curated list and not in any affected range
                }

                ReportVulnerableProduct(match.p, item, vuln);
            }

            // Coverage summary (informational): what was and was not assessed.
            string observed = assessed + " installed program(s) matched the curated list; "
                + notAssessed.Count + " were not assessed (outside the curated vulnerability list).";
            notAssessed.Sort(StringComparer.OrdinalIgnoreCase);
            Report.Ok(Category, "Third-party software coverage", observed, notAssessed);
        }

        private static void ReportVulnerableProduct(ProductRecord p, InvItem item, List<ProductCve> vuln)
        {
            int high = vuln.Count(c => Sev(c.Severity) == Severity.High);
            int med = vuln.Count(c => Sev(c.Severity) == Severity.Medium);
            int low = vuln.Count - high - med;
            int kev = vuln.Count(c => c.Kev);

            string kevText = kev > 0 ? " " + kev + " actively exploited (CISA KEV, marked *)." : "";
            string observed = item.Name + " " + item.Version + " is affected by " + vuln.Count
                + " known CVE(s) (High: " + high + ", Medium: " + med + ", Low: " + low + ")." + kevText;

            var ids = vuln
                .OrderByDescending(c => c.Kev)
                .ThenBy(c => c.Id, StringComparer.OrdinalIgnoreCase)
                .Select(c => c.Kev ? c.Id + "*  (ACTIVELY EXPLOITED - CISA KEV)" : c.Id)
                .ToList();

            string fixedTo = HighestFix(vuln);
            string rec = "Update " + p.Name + " to the latest version"
                + (fixedTo != null ? " (at least " + fixedTo + ", the newest fix among the listed CVEs)." : ".");

            string firstId = vuln
                .OrderByDescending(c => c.Kev).ThenByDescending(c => Sev(c.Severity))
                .Select(c => c.Id).FirstOrDefault();
            string reference = "NVD - https://nvd.nist.gov/vuln/detail/" + firstId;

            Severity worst = vuln.Max(c => Sev(c.Severity));
            Report.Weak(Category, p.Name + " is outdated and vulnerable", worst, observed, ids, rec, reference);
        }

        // Highest fixed version across the matched CVEs (max end bound), for a
        // concrete "update to at least X" recommendation.
        private static string HighestFix(List<ProductCve> vuln)
        {
            string best = null;
            int[] bestParsed = null;
            foreach (var c in vuln)
            {
                string cand = !string.IsNullOrEmpty(c.VersionEndExcluding) ? c.VersionEndExcluding
                            : c.VersionEndIncluding;
                int[] parsed = VersionCompare.Parse(cand);
                if (parsed == null) continue;
                if (bestParsed == null || VersionCompare.Compare(parsed, bestParsed) > 0)
                {
                    bestParsed = parsed;
                    best = cand;
                }
            }
            return best;
        }

        private static List<InvItem> ReadInventory()
        {
            var items = new List<InvItem>();
            AddFrom(items, RegistryHive.LocalMachine, RegistryView.Registry64);
            AddFrom(items, RegistryHive.LocalMachine, RegistryView.Registry32);
            AddFrom(items, RegistryHive.CurrentUser, RegistryView.Default);

            // De-duplicate on name + version (same app appears in 32/64 views).
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var distinct = new List<InvItem>();
            foreach (var it in items)
            {
                string key = (it.Name ?? "") + "\u0001" + (it.Version ?? "");
                if (seen.Add(key)) distinct.Add(it);
            }
            return distinct;
        }

        private static void AddFrom(List<InvItem> items, RegistryHive hive, RegistryView view)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(hive, view))
                using (var root = baseKey.OpenSubKey(UninstallPath))
                {
                    if (root == null) return;
                    foreach (var sub in root.GetSubKeyNames())
                    {
                        try
                        {
                            using (var k = root.OpenSubKey(sub))
                            {
                                if (k == null) continue;
                                var name = k.GetValue("DisplayName") as string;
                                if (string.IsNullOrEmpty(name)) continue;
                                if (IsUpdateOrSystem(k, name)) continue;
                                items.Add(new InvItem
                                {
                                    Name = name.Trim(),
                                    Version = (k.GetValue("DisplayVersion") as string ?? "").Trim(),
                                });
                            }
                        }
                        catch { }
                    }
                }
            }
            catch { }
        }

        // Drop OS updates / patches / system components so only real applications
        // remain in the inventory.
        private static bool IsUpdateOrSystem(RegistryKey k, string name)
        {
            try
            {
                object sc = k.GetValue("SystemComponent");
                if (sc != null && Convert.ToInt32(sc) == 1) return true;
            }
            catch { }
            if (k.GetValue("ParentKeyName") != null) return true;
            string rt = (k.GetValue("ReleaseType") as string ?? "").ToLowerInvariant();
            if (rt.Contains("update") || rt.Contains("hotfix")) return true;
            string n = name.ToLowerInvariant();
            if (Regex.IsMatch(n, @"^kb\d{6,}")) return true;
            if (n.StartsWith("security update for") || n.StartsWith("update for")
                || n.StartsWith("hotfix for")) return true;
            return false;
        }

        private static string Normalize(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return Regex.Replace(s.Trim().ToLowerInvariant(), @"\s+", " ");
        }

        // Strict match: exact, or the alias followed by a space (so
        // "7-Zip 22.01 (x64)" matches alias "7-zip" but "7-zipper" does not).
        private static bool AliasMatches(string nameNorm, string aliasNorm)
        {
            if (aliasNorm.Length == 0) return false;
            return nameNorm == aliasNorm || nameNorm.StartsWith(aliasNorm + " ", StringComparison.Ordinal);
        }

        private static Severity Sev(string s)
        {
            switch ((s ?? "").Trim().ToLowerInvariant())
            {
                case "critical":
                case "high": return Severity.High;
                case "medium": return Severity.Medium;
                case "low": return Severity.Low;
                default: return Severity.High;
            }
        }
    }
}
