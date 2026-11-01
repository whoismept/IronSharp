#!/usr/bin/env python3
"""Refresh IronSharp's combined CVE dataset (IronSharp/Data/cve-data.json).

The single dataset has two sections written atomically by this one script:

  "windows":     Windows OS missing-update CVEs from the MSRC CVRF v3.0 API,
                 keyed per base build to the fixed build revision (UBR).
  "thirdparty":  Curated third-party applications (the allowlist already in the
                 file) checked against the NVD 2.0 API for affected version
                 ranges. Browsers and other high-volume products may carry a
                 `capNewest` so only their N most recent CVEs are kept.

Both sections are enriched with the CISA KEV catalog. A section whose upstream
fetch fails keeps its previous contents, so a transient error never drops
coverage. Standard library only; read-only against MSRC / NVD / CISA. Runs in
CI (internet required). Set NVD_API_KEY for a higher NVD rate limit.

Usage: python tools/update_cve_data.py [--months N] [--out PATH]
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

API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_OUT = os.path.join("IronSharp", "Data", "cve-data.json")

API_KEY = os.environ.get("NVD_API_KEY", "").strip()
# NVD asks for <=5 req/30s without a key, <=50 with one. Stay well under.
SLEEP = 0.8 if API_KEY else 6.5
PAGE = 2000

IMPACTS = {"elevation of privilege", "remote code execution"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
FIXEDBUILD_RE = re.compile(r"^\d+\.\d+\.(\d+)\.(\d+)$")  # X.Y.BUILD.REV
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

# Only record Windows fixes for base builds the tool can match on a live machine.
WINDOWS_BUILDS = {
    7600, 7601, 9200, 9600,
    10240, 10586, 14393, 15063, 16299,
    17134, 17763, 18362, 18363,
    19041, 19042, 19043, 19044, 19045,
    20348, 25398,
    22000, 22621, 22631, 26100,
}


# ---------------------------------------------------------------------------
# Shared HTTP + CISA KEV
# ---------------------------------------------------------------------------
def http_json(url):
    headers = {"User-Agent": "IronSharp-dataset-updater", "Accept": "application/json"}
    if API_KEY and url.startswith(NVD_URL):
        headers["apiKey"] = API_KEY
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_kev():
    """CVE ids in the CISA Known Exploited Vulnerabilities catalog. Enrichment
    only - a fetch failure must not fail the run."""
    try:
        data = http_json(KEV_URL)
        ids = {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}
        print("CISA KEV entries:", len(ids))
        return ids
    except Exception as e:
        print("KEV fetch failed (continuing without it):", e, file=sys.stderr)
        return set()


# ---------------------------------------------------------------------------
# Windows section (MSRC CVRF)
# ---------------------------------------------------------------------------
def id_sort_key(cid):
    m = re.match(r"(\d{4})-([A-Za-z]{3})", cid or "")
    if not m:
        return (0, 0)
    return (int(m.group(1)), MONTHS.get(m.group(2), 0))


def product_to_build(name):
    n = name.lower()
    is_win11 = "windows 11" in n
    is_win10 = "windows 10" in n
    if "version 1507" in n:
        return 10240
    if "version 1607" in n or "windows server 2016" in n:
        return 14393
    if "version 1809" in n or "windows server 2019" in n:
        return 17763
    if "version 21h2" in n:
        return 22000 if is_win11 else (19044 if is_win10 else None)
    if "version 22h2" in n:
        return 22621 if is_win11 else (19045 if is_win10 else None)
    if "version 23h2" in n:
        return 22631 if is_win11 else None
    if "version 24h2" in n:
        return 26100
    if "windows server 2025" in n:
        return 26100
    if "windows server 2022" in n:
        return 20348
    if "windows server 2012 r2" in n:
        return 9600
    if "windows server 2012" in n:
        return 9200
    if "windows 7" in n or "windows server 2008 r2" in n:
        return 7601
    return None


def value(obj):
    return obj.get("Value") if isinstance(obj, dict) else obj


def severity_from_cvss(score):
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "High"
    if s >= 7.0:
        return "High"
    if s >= 4.0:
        return "Medium"
    return "Low"


def recent_update_ids(months):
    data = http_json(API_BASE + "/updates")
    rows = data.get("value", data if isinstance(data, list) else [])
    ids = [entry.get("ID") or entry.get("id") for entry in rows]
    ids = [c for c in ids if c and id_sort_key(c) != (0, 0)]
    keys = sorted({id_sort_key(c) for c in ids})
    keep = set(keys[-months:])
    chosen = [c for c in ids if id_sort_key(c) in keep]
    chosen.sort(key=id_sort_key)
    return chosen


def parse_document(doc, stats):
    out = {}
    products = {}
    for fp in doc.get("ProductTree", {}).get("FullProductName", []):
        pid = fp.get("ProductID")
        name = value(fp) or fp.get("Value")
        if pid and name:
            products[pid] = name

    for vuln in doc.get("Vulnerability", []):
        cve = vuln.get("CVE")
        if not cve or not CVE_RE.match(cve):
            continue
        impacts = set()
        for th in vuln.get("Threats", []):
            if th.get("Type") == 0:
                d = (value(th.get("Description")) or "").strip().lower()
                if d:
                    impacts.add(d)
        if not (impacts & IMPACTS):
            continue

        score = None
        for css in vuln.get("CVSSScoreSets", []):
            bs = css.get("BaseScore")
            if bs is not None and (score is None or bs > score):
                score = bs

        builds = {}
        for rem in vuln.get("Remediations", []):
            if rem.get("Type") != 2:  # 2 = Vendor Fix
                continue
            kb_text = (value(rem.get("Description")) or "").strip()
            kb = int(kb_text) if re.fullmatch(r"\d+", kb_text) else None
            fixed = (rem.get("FixedBuild") or "").strip()
            m = FIXEDBUILD_RE.match(fixed)
            if m:
                base, ubr = int(m.group(1)), int(m.group(2))
                if base in WINDOWS_BUILDS:
                    stats["with_fixedbuild"] += 1
                    _add(builds, base, ubr, kb)
            else:
                for pid in rem.get("ProductID", []):
                    base = product_to_build(products.get(pid, ""))
                    if base in WINDOWS_BUILDS:
                        stats["without_fixedbuild"] += 1
                        _add(builds, base, 0, kb)

        if not builds:
            continue
        rec = out.setdefault(cve, {"title": value(vuln.get("Title")) or "Windows security update",
                                   "severity": severity_from_cvss(score), "builds": {}})
        for base, fix in builds.items():
            _merge_fix(rec["builds"], base, fix)
    return out


def _add(builds, base, ubr, kb):
    cur = builds.get(base)
    if cur is None:
        builds[base] = {"ubr": ubr, "kb": kb}
    else:
        if ubr and (cur["ubr"] == 0 or ubr < cur["ubr"]):
            cur["ubr"] = ubr
        if kb and not cur.get("kb"):
            cur["kb"] = kb


def _merge_fix(builds, base, fix):
    cur = builds.get(base)
    if cur is None:
        builds[base] = dict(fix)
    else:
        if fix["ubr"] and (cur["ubr"] == 0 or fix["ubr"] < cur["ubr"]):
            cur["ubr"] = fix["ubr"]
        if fix.get("kb") and not cur.get("kb"):
            cur["kb"] = fix["kb"]


def merge(base, new):
    for cve, rec in new.items():
        tgt = base.setdefault(cve, {"title": rec["title"], "severity": rec["severity"], "builds": {}})
        if rec.get("title"):
            tgt["title"] = rec["title"]
        if rec.get("severity"):
            tgt["severity"] = rec["severity"]
        for b, fix in rec["builds"].items():
            _merge_fix(tgt["builds"], int(b), fix)
    return base


def build_windows_cves(months, kev):
    stats = {"with_fixedbuild": 0, "without_fixedbuild": 0}
    ids = recent_update_ids(months)
    merged = {}
    for cid in ids:
        try:
            doc = http_json(API_BASE + "/cvrf/" + cid)
        except Exception as e:
            print("Skip", cid, ":", e, file=sys.stderr)
            continue
        merge(merged, parse_document(doc, stats))
        print("Processed", cid, "- cumulative CVEs:", len(merged))
    print("FixedBuild coverage: {with_fixedbuild} with revision, {without_fixedbuild} without".format(**stats))
    for cve in merged:
        if cve in kev:
            merged[cve]["kev"] = True

    cves = []
    for cve in sorted(merged):
        rec = merged[cve]
        builds = {}
        for b in sorted(rec["builds"]):
            fix = rec["builds"][b]
            entry = {"ubr": fix.get("ubr", 0)}
            if fix.get("kb"):
                entry["kb"] = fix["kb"]
            builds[str(b)] = entry
        if not builds:
            continue
        entry = {"id": cve, "title": rec["title"], "severity": rec["severity"], "builds": builds}
        if rec.get("kev"):
            entry["kev"] = True
        cves.append(entry)
    print("Windows CVEs:", len(cves), "| KEV:", sum(1 for c in cves if c.get("kev")))
    return cves


# ---------------------------------------------------------------------------
# Third-party section (NVD 2.0)
# ---------------------------------------------------------------------------
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
    parts = criteria.split(":")
    return len(parts) > 4 and parts[2] == "a" and parts[3] == vendor and parts[4] == product


def ranges_for_cve(cve, vendor, product):
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
    found = {}
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
    ids = sorted({c["id"] for c in cves}, key=cve_key, reverse=True)
    keep = set(ids[:n])
    kept = [c for c in cves if c["id"] in keep]
    return kept, max(0, len(ids) - len(keep))


def build_thirdparty(products, kev):
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
            print("NVD query failed for {} ({}); keeping existing CVEs.".format(
                p.get("name"), e), file=sys.stderr)
        time.sleep(SLEEP)
    return products


# ---------------------------------------------------------------------------
def section_payload(doc):
    """Comparable payload ignoring the generated timestamp."""
    win = (doc.get("windows") or {}).get("cves", doc.get("cves", []))
    tp = (doc.get("thirdparty") or {}).get("products", doc.get("products", []))
    return json.dumps({"windows": win, "thirdparty": tp}, sort_keys=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--months", type=int, default=24)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    if not os.path.exists(args.out):
        print("Combined dataset not found:", args.out, file=sys.stderr)
        return 1
    with open(args.out, encoding="utf-8") as f:
        existing = json.load(f)

    # Snapshot the comparable payload BEFORE anything mutates the product dicts
    # (build_thirdparty edits them in place, and they are shared with `existing`).
    old_payload = section_payload(existing)

    products = (existing.get("thirdparty") or {}).get("products", existing.get("products", []))
    if not products:
        print("No third-party allowlist in dataset.", file=sys.stderr)
        return 1

    kev = fetch_kev()

    try:
        win_cves = build_windows_cves(args.months, kev)
    except Exception as e:
        print("Windows refresh failed; keeping existing section:", e, file=sys.stderr)
        win_cves = (existing.get("windows") or {}).get("cves", existing.get("cves", []))

    tp_products = build_thirdparty(products, kev)

    doc = {
        "generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "MSRC CVRF v3.0 + NVD 2.0 + CISA KEV; maintained by tools/update_cve_data.py",
        "schema": "windows: build->{ubr,kb}; thirdparty: products[].cves[] NVD version ranges",
        "windows": {"cves": win_cves},
        "thirdparty": {"products": tp_products},
    }

    if section_payload(doc) == old_payload:
        print("No dataset changes.")
        return 0

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print("Wrote {} - windows {} CVEs, thirdparty {} products.".format(
        args.out, len(win_cves), len(tp_products)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
