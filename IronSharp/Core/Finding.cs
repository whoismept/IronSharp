namespace IronSharp.Core
{
    // A single hardening observation. A finding is either a weakness
    // (IsWeak = true, carrying a recommendation) or an informational /
    // passed control (IsWeak = false).
    internal class Finding
    {
        public string Category;
        public string Title;
        public Severity Severity;
        public bool IsWeak;
        public string Observed;
        public string Recommendation;
        public string Reference;
        // Optional detail list printed one entry per line under Observed
        // (e.g. every affected path / service / CVE). Null when there is none.
        public System.Collections.Generic.List<string> Items;
    }
}
