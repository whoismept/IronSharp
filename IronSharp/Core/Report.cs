using System;
using System.Collections.Generic;
using System.Linq;

namespace IronSharp.Core
{
    // Central, read-only collector for hardening findings. Checks call Add/Weak/Ok
    // and the runner prints everything at the end, grouped and severity-ranked.
    internal static class Report
    {
        private static readonly List<Finding> Findings = new List<Finding>();

        public static void Add(string category, string title, Severity severity, bool isWeak,
                               string observed, string recommendation, string reference)
        {
            Findings.Add(new Finding
            {
                Category = category,
                Title = title,
                Severity = severity,
                IsWeak = isWeak,
                Observed = observed,
                Recommendation = recommendation,
                Reference = reference
            });
        }

        // A weakness that should be hardened.
        public static void Weak(string category, string title, Severity severity,
                                string observed, string recommendation, string reference)
        {
            Add(category, title, severity, true, observed, recommendation, reference);
        }

        // A control that is configured correctly, or purely informational context.
        public static void Ok(string category, string title, string observed)
        {
            Add(category, title, Severity.Info, false, observed, null, null);
        }

        public static void PrintAll()
        {
            foreach (var group in Findings.GroupBy(f => f.Category))
            {
                Console.WriteLine();
                Console.WriteLine("==== " + group.Key + " ====");
                foreach (var f in group.OrderByDescending(x => x.IsWeak).ThenByDescending(x => x.Severity))
                {
                    string tag = f.IsWeak ? "[" + f.Severity.ToString().ToUpperInvariant() + "]" : "[OK]";
                    Console.WriteLine("{0} {1}", tag, f.Title);
                    if (!string.IsNullOrEmpty(f.Observed))
                    {
                        Console.WriteLine("    Observed       : " + f.Observed);
                    }
                    if (f.IsWeak && !string.IsNullOrEmpty(f.Recommendation))
                    {
                        Console.WriteLine("    Recommendation : " + f.Recommendation);
                    }
                    if (f.IsWeak && !string.IsNullOrEmpty(f.Reference))
                    {
                        Console.WriteLine("    Reference      : " + f.Reference);
                    }
                }
            }
        }

        public static void PrintSummary()
        {
            Console.WriteLine();
            Console.WriteLine("==== Summary ====");
            foreach (Severity sev in new[] { Severity.High, Severity.Medium, Severity.Low })
            {
                int n = Findings.Count(f => f.IsWeak && f.Severity == sev);
                Console.WriteLine("  {0,-6} : {1}", sev, n);
            }
            int total = Findings.Count(f => f.IsWeak);
            Console.WriteLine("  Total weaknesses : " + total);
            Console.WriteLine();
            Console.WriteLine("IronSharp only reports configuration; nothing on this system was changed.");
            Console.WriteLine("Review each item and apply changes via Group Policy / secpol / your baseline.");
        }
    }
}
