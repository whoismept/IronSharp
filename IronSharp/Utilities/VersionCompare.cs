using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace IronSharp.Utilities
{
    // Compares arbitrary dotted-numeric version strings (e.g. "22.01",
    // "116.0.5845.188", "6.23.0") and tests NVD-style affected ranges.
    // Deliberately conservative: a version that cannot be parsed into any
    // numeric component is treated as unknown and never reported as vulnerable.
    internal static class VersionCompare
    {
        private static readonly Regex NumberGroup = new Regex(@"\d+");

        // Numeric components of a version, or null when there is nothing numeric
        // to compare (caller must then leave the item "not assessed").
        public static int[] Parse(string version)
        {
            if (string.IsNullOrEmpty(version)) return null;
            var parts = new List<int>();
            foreach (Match m in NumberGroup.Matches(version))
            {
                int n;
                if (int.TryParse(m.Value, out n)) parts.Add(n);
            }
            return parts.Count == 0 ? null : parts.ToArray();
        }

        // Component-wise comparison; the shorter version is zero-padded.
        public static int Compare(int[] a, int[] b)
        {
            int len = a.Length > b.Length ? a.Length : b.Length;
            for (int i = 0; i < len; i++)
            {
                int ai = i < a.Length ? a[i] : 0;
                int bi = i < b.Length ? b[i] : 0;
                if (ai != bi) return ai < bi ? -1 : 1;
            }
            return 0;
        }

        // True when `version` falls inside the (optional) bounds. Each bound is a
        // version string or null/empty when not set. A range with no upper bound
        // ("affects all versions") returns false on purpose: without a fixed
        // version there is nothing actionable and the false-positive risk is high.
        public static bool InRange(string version,
            string startIncluding, string startExcluding,
            string endIncluding, string endExcluding)
        {
            int[] v = Parse(version);
            if (v == null) return false;
            if (string.IsNullOrEmpty(endIncluding) && string.IsNullOrEmpty(endExcluding))
                return false;

            int[] b;
            if ((b = Parse(startIncluding)) != null && Compare(v, b) < 0) return false;
            if ((b = Parse(startExcluding)) != null && Compare(v, b) <= 0) return false;
            if ((b = Parse(endIncluding)) != null && Compare(v, b) > 0) return false;
            if ((b = Parse(endExcluding)) != null && Compare(v, b) >= 0) return false;
            return true;
        }
    }
}
