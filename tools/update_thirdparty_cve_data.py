#!/usr/bin/env python3
"""Refresh IronSharp's third-party application CVE dataset from the NVD 2.0 API.

The curated product allowlist lives in the dataset file itself
(IronSharp/Data/thirdparty-cve-data.json): each product carries a `vendor` and
`product` (its NVD CPE identity) plus registry `aliases`. For each product this
queries NVD for all CVEs affecting that CPE, keeps only those with an actionable
affected-version range (a fixed upper bound), maps CVSS to a severity, and flags
the ones in the CISA KEV catalog. The allowlist is preserved; only the per-product
`cves` are rewritten. A product whose NVD query fails keeps its previous CVEs, so
a transient NVD error never silently drops coverage.

Standard library only. Read-only against NVD / CISA. Runs in CI (internet required).
Set NVD_API_KEY for a higher rate limit.

Usage: python tools/update_thirdparty_cve_data.py [--out PATH]
"""

import argparse
import datetime
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_OUT = os.path.join("IronSharp", "Data", "thirdparty-cve-data.json")
API_KEY = os.environ.get("NVD_API_KEY", "").strip()
# NVD asks for <=5 req/30s without a key, <=50 with one. Stay well under.
SLEEP = 0.8 if API_KEY else 6.5
PAGE = 2000


def http_json(url):
    headers = {"User-Agent": "IronSharp-thirdparty-updater", "Accept": "application/json"}
    if API_KEY and url.startswith(NVD_URL):
        headers["apiKey"] = API_KEY
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_kev():
    try:
        data = http_json(KEV_URL)
        ids = {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
        print("CISA KEV entries:", len(ids))
        return ids
    except Exception as e:
        print("KEV fetch failed (continuing without it):", e, file=sys.stderr)
        return set()


def severity_from_metrics(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        arr = metrics.get(key)
        if arr:
            try:
                score = float(arr[0]["cvssData"]["baseScore"])
            except (KeyError, IndexError, TypeError, ValueError):
                continue
            if score >= 9.0:
                return "Critical"
            if score >= 7.0:
                return "High"
            if score >= 4.0:
                return "Medium"
            return "Low"
    return "High"


def cpe_matches(criteria, vendor, product):
    # criteria: cpe:2.3:part:vendor:product:version:...
    parts = criteria.split(":")
    return len(parts) > 4 and parts[2] == "a" and parts[3] == vendor and parts[4] == product


def ranges_for_cve(cve, vendor, product):
    """Yield one affected-version range dict per matching, vulnerable cpeMatch
    that carries a fixed upper bound (actionable). Ranges without an end bound
    are skipped to avoid flagging every installed version."""
    out = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable"):
                    continue
                if not cpe_matches(m.get("criteria", ""), vendor, product):
                    continue
                end_inc = m.get("versionEndIncluding")
                end_exc = m.get("versionEndExcluding")
                if not end_inc and not end_exc:
                    continue
                r = {}
                if m.get("versionStartIncluding"):
                    r["versionStartIncluding"] = m["versionStartIncluding"]
                if m.get("versionStartExcluding"):
                    r["versionStartExcluding"] = m["versionStartExcluding"]
                if end_inc:
                    r["versionEndIncluding"] = end_inc
                if end_exc:
                    r["versionEndExcluding"] = end_exc
                out.append(r)
    return out


def fetch_product_cves(vendor, product, kev):
    cpe = "cpe:2.3:a:{}:{}:*:*:*:*:*:*:*:*".format(vendor, product)
    start = 0
    found = {}  # cve id -> record
    while True:
        url = "{}?virtualMatchString={}&resultsPerPage={}&startIndex={}".format(
            NVD_URL, urllib.parse.quote(cpe, safe=""), PAGE, start)
        data = http_json(url)
        vulns = data.get("vulnerabilities", [])
        for entry in vulns:
            cve = entry.get("cve", {})
            cid = cve.get("id")
            if not cid:
                continue
            ranges = ranges_for_cve(cve, vendor, product)
            if not ranges:
                continue
            sev = severity_from_metrics(cve)
            for r in ranges:
                rec = dict(r)
                rec["id"] = cid
                rec["severity"] = sev
                rec["kev"] = cid in kev
                rec["reference"] = "https://nvd.nist.gov/vuln/detail/" + cid
                # One record per (id, range); dedupe identical ranges.
                found[json.dumps(rec, sort_keys=True)] = rec
        total = data.get("totalResults", 0)
        start += PAGE
        if start >= total or not vulns:
            break
        time.sleep(SLEEP)
    return list(found.values())


def order_cves(cves):
    return sorted(cves, key=lambda c: (not c.get("kev"), c.get("id", "")))


def cve_key(cid):
    m = re.match(r"CVE-(\d+)-(\d+)", cid or "")
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def cap_newest(cves, n):
    """Keep only ranges belonging to the n newest distinct CVE ids; return
    (kept, omitted_count). For high-volume products (browsers) this bounds the
    dataset while still flagging the most recent issues."""
    ids = sorted({c["id"] for c in cves}, key=cve_key, reverse=True)
    keep = set(ids[:n])
    kept = [c for c in cves if c["id"] in keep]
    return kept, max(0, len(ids) - len(keep))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    if not os.path.exists(args.out):
        print("Allowlist file not found:", args.out, file=sys.stderr)
        return 1
    with open(args.out, encoding="utf-8") as f:
        doc = json.load(f)
    products = doc.get("products", [])
    if not products:
        print("No products in allowlist.", file=sys.stderr)
        return 1

    kev = fetch_kev()

    for p in products:
        vendor, product = p.get("vendor"), p.get("product")
        if not vendor or not product:
            print("Skip (no cpe):", p.get("name"))
            continue
        try:
            cves = fetch_product_cves(vendor, product, kev)
            cap = p.get("capNewest")
            if cap:
                cves, omitted = cap_newest(cves, int(cap))
                p["omitted"] = omitted
            else:
                p.pop("omitted", None)
            p["cves"] = order_cves(cves)
            extra = " (+{} omitted)".format(p["omitted"]) if p.get("omitted") else ""
            print("{}: {} CVE range(s){}".format(p.get("name"), len(p["cves"]), extra))
        except Exception as e:
            # Keep whatever was there; never drop coverage on a transient error.
            print("NVD query failed for {} ({}); keeping existing CVEs.".format(
                p.get("name"), e), file=sys.stderr)
        time.sleep(SLEEP)

    new_products = json.dumps(doc.get("products", []), sort_keys=True)
    old_products = None
    try:
        with open(args.out, encoding="utf-8") as f:
            old_products = json.dumps(json.load(f).get("products", []), sort_keys=True)
    except Exception:
        old_products = None
    if new_products == old_products:
        print("No dataset changes.")
        return 0

    doc["generated"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    total = sum(len(p.get("cves", [])) for p in products)
    print("Wrote", args.out, "-", len(products), "products,", total, "CVE ranges.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
