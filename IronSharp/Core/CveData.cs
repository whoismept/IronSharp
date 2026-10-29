using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web.Script.Serialization;

namespace IronSharp.Core
{
    // One CVE entry from the data file: which fixing KBs apply per Windows build.
    internal class CveRecord
    {
        public string Id;
        public string Title;
        public string Severity;
        public Dictionary<int, int[]> Builds = new Dictionary<int, int[]>();
    }

    // Loads the CVE / missing-update dataset. The dataset ships embedded
    // (offline) and can be refreshed by tools/update_cve_data.py via CI, or
    // downloaded at runtime with --online. Parsing uses JavaScriptSerializer
    // (System.Web.Extensions) so there is no external dependency.
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
                            var arr = kv.Value as object[];
                            if (arr == null) continue;
                            var kbs = new List<int>();
                            foreach (var n in arr)
                            {
                                try { kbs.Add(Convert.ToInt32(n)); }
                                catch { }
                            }
                            rec.Builds[b] = kbs.ToArray();
                        }
                    }
                    records.Add(rec);
                }
            }
            catch
            {
                // Malformed data: return whatever parsed so far (possibly empty).
            }
            return records;
        }

        private static string AsString(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) && v != null ? v.ToString() : null;
        }
    }
}
