#!/usr/bin/env python3
"""Refresh IronSharp's CVE / missing-update dataset from the MSRC CVRF API.

Fetches the last N monthly security-update documents from the public Microsoft
Security Response Center (MSRC) CVRF v3.0 API, extracts Windows Elevation of
Privilege and Remote Code Execution CVEs with their per-build fixing KBs, merges
them with the existing dataset (so curated historical entries are preserved),
and writes IronSharp/Data/cve-data.json.

Runs in CI (GitHub-hosted runners have internet). Uses only the Python standard
library. Read-only against MSRC; it never contacts the audited machines.

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

# Map an MSRC product name to the base build number IronSharp compares against.
# Order matters: more specific tokens first.
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
        return 22631 if is_win11 else None  # Server 23H2 (25398) intentionally skipped
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
    """CVRF wraps many fields as {"Value": ...}."""
    if isinstance(obj, dict):
        return obj.get("Value")
    return obj


def severity_from_cvss(score):
    if score is None:
        return "High"
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
    ids = []
    for entry in data.get("value", data if isinstance(data, list) else []):
        cid = entry.get("ID") or entry.get("id")
        rel = entry.get("CurrentReleaseDate") or entry.get("InitialReleaseDate")
        if cid:
            ids.append((rel or "", cid))
    ids.sort()
    return [cid for _, cid in ids[-months:]]


def parse_document(doc):
    """Return {cve_id: {"title","severity","builds":{build:set(kb)}}}."""
    out = {}

    # ProductID -> product name
    products = {}
    tree = doc.get("ProductTree", {})
    for fp in tree.get("FullProductName", []):
        pid = fp.get("ProductID")
        name = value(fp) or fp.get("Value")
        if pid and name:
            products[pid] = name

    for vuln in doc.get("Vulnerability", []):
        cve = vuln.get("CVE")
        if not cve:
            continue

        # Impact must be EoP or RCE (Threat Type 0 = Impact).
        impacts = set()
        for th in vuln.get("Threats", []):
            if th.get("Type") == 0:
                d = (value(th.get("Description")) or "").strip().lower()
                if d:
                    impacts.add(d)
        if not (impacts & IMPACTS):
            continue

        # Severity from the highest CVSS base score.
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
            if not re.fullmatch(r"\d+", kb_text):
                continue
            kb = int(kb_text)
            for pid in rem.get("ProductID", []):
                name = products.get(pid)
                if not name:
                    continue
                build = product_to_build(name)
                if build is None:
                    continue
                builds.setdefault(build, set()).add(kb)

        if not builds:
            continue

        title = value(vuln.get("Title")) or "Windows security update"
        rec = out.setdefault(cve, {"title": title, "severity": severity_from_cvss(score), "builds": {}})
        for b, kbs in builds.items():
            rec["builds"].setdefault(b, set()).update(kbs)

    return out


def load_existing(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    for c in data.get("cves", []):
        builds = {}
        for b, kbs in (c.get("builds") or {}).items():
            builds[int(b)] = set(kbs)
        out[c["id"]] = {"title": c.get("title", ""), "severity": c.get("severity", "High"), "builds": builds}
    return out


def merge(base, new):
    for cve, rec in new.items():
        if cve not in base:
            base[cve] = {"title": rec["title"], "severity": rec["severity"], "builds": {}}
        # Prefer the fresh MSRC title/severity when present.
        if rec.get("title"):
            base[cve]["title"] = rec["title"]
        if rec.get("severity"):
            base[cve]["severity"] = rec["severity"]
        for b, kbs in rec["builds"].items():
            base[cve]["builds"].setdefault(b, set()).update(kbs)
    return base


def to_document(merged):
    cves = []
    for cve in sorted(merged):
        rec = merged[cve]
        builds = {str(b): sorted(rec["builds"][b]) for b in sorted(rec["builds"])}
        cves.append({
            "id": cve,
            "title": rec["title"],
            "severity": rec["severity"],
            "builds": builds,
        })
    return {
        "generated": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "MSRC CVRF v3.0 (api.msrc.microsoft.com); maintained by tools/update_cve_data.py",
        "cves": cves,
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--months", type=int, default=24, help="how many recent months to pull")
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args()

    merged = load_existing(args.out)
    before = json.dumps(to_document(merged), sort_keys=True)

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
        found = parse_document(doc)
        merge(merged, found)
        print("Processed", cid, "- cumulative CVEs:", len(merged))

    document = to_document(merged)
    after = json.dumps(document, sort_keys=True)
    if after == before:
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
