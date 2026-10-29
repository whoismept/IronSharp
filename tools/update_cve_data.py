#!/usr/bin/env python3
"""Refresh IronSharp's CVE / missing-update dataset from the MSRC CVRF API.

Fetches recent monthly MSRC CVRF v3.0 documents, extracts Windows Elevation of
Privilege and Remote Code Execution CVEs and, for each affected Windows build,
the fixed build revision (UBR) from the remediation's FixedBuild (e.g.
10.0.19045.5679). IronSharp then flags a build as behind when its UBR is below
the fixed revision - which avoids the false positives of matching exact KB
numbers (superseded cumulative updates drop out of the installed list).

Writes IronSharp/Data/cve-data.json. Runs in CI (internet required). Standard
library only. Read-only against MSRC.

Usage: python tools/update_cve_data.py [--months N] [--out PATH]
"""

import argparse
import datetime
import json
import os
import re
import sys
import urllib.request

API_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0"
DEFAULT_OUT = os.path.join("IronSharp", "Data", "cve-data.json")
IMPACTS = {"elevation of privilege", "remote code execution"}
CVE_RE = re.compile(r"^CVE-\d{4}-\d+$")
FIXEDBUILD_RE = re.compile(r"^\d+\.\d+\.(\d+)\.(\d+)$")  # X.Y.BUILD.REV


# Fallback product-name -> base build (only used when FixedBuild is absent).
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


def http_json(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/json",
        "User-Agent": "IronSharp-dataset-updater",
    })
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))


def value(obj):
    if isinstance(obj, dict):
        return obj.get("Value")
    return obj


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
    ids = []
    for entry in rows:
        cid = entry.get("ID") or entry.get("id")
        rel = entry.get("CurrentReleaseDate") or entry.get("InitialReleaseDate") or ""
        if cid:
            ids.append((rel, cid))
    ids.sort()
    return [cid for _, cid in ids[-months:]]


def parse_document(doc, stats):
    """Return {cve: {"title","severity","builds":{base:{"ubr":int,"kb":int}}}}."""
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
                stats["with_fixedbuild"] += 1
                base, ubr = int(m.group(1)), int(m.group(2))
                _add(builds, base, ubr, kb)
            else:
                stats["without_fixedbuild"] += 1
                # No revision available: map by product name, ubr unknown (0).
                for pid in rem.get("ProductID", []):
                    base = product_to_build(products.get(pid, ""))
                    if base is not None:
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
        # Prefer the smallest non-zero UBR (earliest revision that fixes it).
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


def load_existing(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    for c in data.get("cves", []):
        if not CVE_RE.match(str(c.get("id", ""))):
            continue
        builds = {}
        for b, fix in (c.get("builds") or {}).items():
            if isinstance(fix, dict):
                builds[int(b)] = {"ubr": int(fix.get("ubr", 0)), "kb": fix.get("kb")}
        out[c["id"]] = {"title": c.get("title", ""), "severity": c.get("severity", "High"), "builds": builds}
    return out


def to_document(merged):
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
        cves.append({"id": cve, "title": rec["title"], "severity": rec["severity"], "builds": builds})
    return {
        "generated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "MSRC CVRF v3.0 (api.msrc.microsoft.com); maintained by tools/update_cve_data.py",
        "schema": "build -> {ubr: fixed revision, kb: article}",
        "cves": cves,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--months", type=int, default=24)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    merged = load_existing(args.out)
    before = json.dumps(to_document(merged), sort_keys=True)
    stats = {"with_fixedbuild": 0, "without_fixedbuild": 0}

    try:
        ids = recent_update_ids(args.months)
    except Exception as e:
        print("Failed to list MSRC updates:", e, file=sys.stderr)
        return 1

    for cid in ids:
        try:
            doc = http_json(API_BASE + "/cvrf/" + cid)
        except Exception as e:
            print("Skip", cid, ":", e, file=sys.stderr)
            continue
        merge(merged, parse_document(doc, stats))
        print("Processed", cid, "- cumulative CVEs:", len(merged))

    print("FixedBuild coverage: {with_fixedbuild} with revision, {without_fixedbuild} without".format(**stats))

    document = to_document(merged)
    if json.dumps(document, sort_keys=True) == before:
        print("No dataset changes.")
        return 0

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2)
        f.write("\n")
    print("Wrote", args.out, "with", len(document["cves"]), "CVEs.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
