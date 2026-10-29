using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Web.Script.Serialization;

namespace IronSharp.Core
{
    // One known CVE affecting a curated third-party product, with the affected
    // version range (NVD semantics). A fixed upper bound is required for the
    // record to be actionable (see VersionCompare.InRange).
    internal class ProductCve
    {
        public string Id;
        public string Severity;
        public bool Kev;
        public string Reference;
        public string VersionStartIncluding;
        public string VersionStartExcluding;
        public string VersionEndIncluding;
        public string VersionEndExcluding;
    }

    // A curated product: its display-name aliases (how it appears in the
    // registry Uninstall list) and the CVEs known to affect it.
    internal class ProductRecord
    {
        public string Name;
        public string Vendor;
        public List<string> Aliases = new List<string>();
        public List<ProductCve> Cves = new List<ProductCve>();
    }

    internal static class ThirdPartyData
    {
        public static string LoadEmbeddedJson()
        {
            try
            {
                var asm = Assembly.GetExecutingAssembly();
                var name = asm.GetManifestResourceNames()
                    .FirstOrDefault(n => n.EndsWith("thirdparty-cve-data.json", StringComparison.OrdinalIgnoreCase));
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

        public static List<ProductRecord> Load(string json)
        {
            var products = new List<ProductRecord>();
            if (string.IsNullOrEmpty(json)) return products;
            try
            {
                var ser = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
                var root = ser.DeserializeObject(json) as Dictionary<string, object>;
                if (root == null || !root.ContainsKey("products")) return products;
                var items = root["products"] as object[];
                if (items == null) return products;

                foreach (var it in items)
                {
                    var p = it as Dictionary<string, object>;
                    if (p == null) continue;

                    var rec = new ProductRecord
                    {
                        Name = AsString(p, "name"),
                        Vendor = AsString(p, "vendor"),
                    };
                    if (string.IsNullOrEmpty(rec.Name)) continue;

                    var aliases = p.ContainsKey("aliases") ? p["aliases"] as object[] : null;
                    if (aliases != null)
                    {
                        foreach (var a in aliases)
                        {
                            if (a != null) rec.Aliases.Add(a.ToString());
                        }
                    }
                    if (rec.Aliases.Count == 0) rec.Aliases.Add(rec.Name);

                    var cves = p.ContainsKey("cves") ? p["cves"] as object[] : null;
                    if (cves != null)
                    {
                        foreach (var c in cves)
                        {
                            var cd = c as Dictionary<string, object>;
                            if (cd == null) continue;
                            string id = AsString(cd, "id");
                            if (string.IsNullOrEmpty(id)) continue;
                            rec.Cves.Add(new ProductCve
                            {
                                Id = id,
                                Severity = AsString(cd, "severity"),
                                Kev = cd.ContainsKey("kev") && cd["kev"] is bool && (bool)cd["kev"],
                                Reference = AsString(cd, "reference"),
                                VersionStartIncluding = AsString(cd, "versionStartIncluding"),
                                VersionStartExcluding = AsString(cd, "versionStartExcluding"),
                                VersionEndIncluding = AsString(cd, "versionEndIncluding"),
                                VersionEndExcluding = AsString(cd, "versionEndExcluding"),
                            });
                        }
                    }
                    products.Add(rec);
                }
            }
            catch
            {
                // Malformed data: return whatever parsed so far.
            }
            return products;
        }

        private static string AsString(Dictionary<string, object> d, string key)
        {
            object v;
            return d.TryGetValue(key, out v) && v != null ? v.ToString() : null;
        }
    }
}
