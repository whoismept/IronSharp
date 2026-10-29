using System.Collections.Generic;
using System.Linq;

namespace IronSharp.Core
{
    internal static class Fmt
    {
        // Joins items with ", " but caps the output at `max` entries, appending
        // "(+N more)" so long observed lists stay readable.
        public static string List(IEnumerable<string> items, int max = 15)
        {
            var all = items.ToList();
            if (all.Count <= max)
            {
                return string.Join(", ", all);
            }
            return string.Join(", ", all.Take(max)) + " (+" + (all.Count - max) + " more)";
        }
    }
}
