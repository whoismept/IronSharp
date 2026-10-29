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

        public static void Weak(string category, string title, Severity severity,
                                string observed, string recommendation, string reference)
        {
            Add(category, title, severity, true, observed, recommendation, reference);
        }

        // Weakness with a full detail list printed one entry per line under Observed.
        public static void Weak(string category, string title, Severity severity,
                                string observed, IEnumerable<string> items,
                                string recommendation, string reference)
        {
            Findings.Add(new Finding
            {
                Category = category,
                Title = title,
                Severity = severity,
                IsWeak = true,
                Observed = observed,
                Recommendation = recommendation,
                Reference = reference,
                Items = items == null ? null : items.ToList()
            });
        }

        public static void Ok(string category, string title, string observed)
        {
            Add(category, title, Severity.Info, false, observed, null, null);
        }

        // Informational finding that also carries a full detail list.
        public static void Ok(string category, string title, string observed, IEnumerable<string> items)
        {
            Findings.Add(new Finding
            {
                Category = category,
                Title = title,
                Severity = Severity.Info,
                IsWeak = false,
                Observed = observed,
                Items = items == null ? null : items.ToList()
            });
        }

        public static void PrintAll()
        {
            foreach (var group in Findings.GroupBy(f => f.Category))
            {
                Console.WriteLine();
                WriteLine(ConsoleColor.Cyan, "==== " + group.Key + " ====");
                foreach (var f in group.OrderByDescending(x => x.IsWeak).ThenByDescending(x => x.Severity))
                {
                    string tag = f.IsWeak ? "[" + f.Severity.ToString().ToUpperInvariant() + "]" : "[OK]";
                    Write(ColorFor(f.IsWeak, f.Severity), tag);
                    Console.WriteLine(" " + f.Title);
                    if (!string.IsNullOrEmpty(f.Observed))
                    {
                        Console.WriteLine("    Observed       : " + f.Observed);
                    }
                    if (f.Items != null && f.Items.Count > 0)
                    {
                        foreach (var item in f.Items)
                        {
                            WriteLine(ConsoleColor.DarkGray, "        - " + item);
                        }
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
            WriteLine(ConsoleColor.Cyan, "==== Summary ====");
            WriteLine(ColorFor(true, Severity.High), "  High   : " + Count(Severity.High));
            WriteLine(ColorFor(true, Severity.Medium), "  Medium : " + Count(Severity.Medium));
            WriteLine(ColorFor(true, Severity.Low), "  Low    : " + Count(Severity.Low));
            Console.WriteLine("  Total weaknesses : " + Findings.Count(f => f.IsWeak));
            Console.WriteLine();
            Console.WriteLine("IronSharp only reports configuration; nothing on this system was changed.");
            Console.WriteLine("Review each item and apply changes via Group Policy / secpol / your baseline.");
        }

        private static int Count(Severity sev)
        {
            return Findings.Count(f => f.IsWeak && f.Severity == sev);
        }

        private static ConsoleColor ColorFor(bool isWeak, Severity sev)
        {
            if (!isWeak) return ConsoleColor.Green;
            switch (sev)
            {
                case Severity.High: return ConsoleColor.Red;
                case Severity.Medium: return ConsoleColor.Yellow;
                case Severity.Low: return ConsoleColor.DarkYellow;
                default: return ConsoleColor.Gray;
            }
        }

        // Colored writes degrade cleanly: when output is redirected to a file the
        // color calls are no-ops, so the file stays plain text.
        private static void Write(ConsoleColor color, string text)
        {
            try { Console.ForegroundColor = color; } catch { }
            Console.Write(text);
            try { Console.ResetColor(); } catch { }
        }

        private static void WriteLine(ConsoleColor color, string text)
        {
            Write(color, text);
            Console.WriteLine();
        }
    }
}
