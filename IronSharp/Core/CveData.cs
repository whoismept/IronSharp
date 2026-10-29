using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web.Script.Serialization;

namespace IronSharp.Core
{
    // The fix for a CVE on one Windows base build: the build revision (UBR) that
    // first addressed it, plus the KB article for reference. A machine is behind
    // on this CVE when its UBR is below Ubr.
    internal class BuildFix
    {
        public int Ubr;
        public int Kb;
    }

    internal class CveRecord
    {
        public string Id;
        public string Title;
        public string Severity;
        public Dictionary<int, BuildFix> Builds = new Dictionary<int, BuildFix>();
    }

    internal static class CveData
    {
        public static string LoadEmbeddedJson()
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                var name = asm.GetManifestResourceNames()
                    .FirstOrDefault(n => n.EndsWith("cve-data.json", StringComparison.OrdinalIgnoreCase));
                if (name == null) return null;
                using (var s = asm.GetManifestResourceStream(name))
                using (var r = new StreamReader(s))
                {
                    return r.ReadToEnd();
                }
            }
            catch
            {
                return null;
            }
        }

        public static List<CveRecord> Load(string json)
        {
            var records = new List<CveRecord>();
            if (string.IsNullOrEmpty(json)) return records;
            try
            {
                var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                var root = ser.DeserializeObject(json) as Dictionary<string, object>;
                if (root == null || !root.ContainsKey("cves")) return records;
                var cves = root["cves"] as object[];
                if (cves == null) return records;

                foreach (var item in cves)
                {
                    var c = item as Dictionary<string, object>;
                    if (c == null) continue;

                    var rec = new CveRecord
                    {
                        Id = AsString(c, "id"),
                        Title = AsString(c, "title"),
                        Severity = AsString(c, "severity")
                    };
                    if (string.IsNullOrEmpty(rec.Id)) continue;

                    var builds = c.ContainsKey("builds") ? c["builds"] as Dictionary<string, object> : null;
                    if (builds != null)
                    {
                        foreach (var kv in builds)
                        {
                            int b;
                            if (!int.TryParse(kv.Key, out b)) continue;
                            var fix = ParseFix(kv.Value);
                            if (fix != null) rec.Builds[b] = fix;
                        }
                    }
                    records.Add(rec);
                }
            }
            catch
            {
                // Malformed data: return whatever parsed so far.
            }
            return records;
        }

        // Accepts the current schema {"ubr":N,"kb":M} and tolerates the older
        // KB-array schema [kb, ...] (treated as Ubr=0 so it is skipped by the
        // revision-based check rather than causing false positives).
        private static BuildFix ParseFix(object value)
        {
            var obj = value as Dictionary<string, object>;
            if (obj != null)
            {
                return new BuildFix
                {
                    Ubr = ToInt(obj.ContainsKey("ubr") ? obj["ubr"] : null),
                    Kb = ToInt(obj.ContainsKey("kb") ? obj["kb"] : null)
                };
            }
            var arr = value as object[];
            if (arr != null)
            {
                return new BuildFix { Ubr = 0, Kb = arr.Length > 0 ? ToInt(arr[0]) : 0 };
            }
            return null;
        }

        private static int ToInt(object o)
        {
            if (o == null) return 0;
            try { return Convert.ToInt32(o); }
            catch { return 0; }
        }

        private static string AsString(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) && v != null ? v.ToString() : null;
        }
    }
}
