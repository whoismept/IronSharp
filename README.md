# IronSharp

IronSharp is a **read-only Windows hardening advisor** written in C#. It audits
the local machine against common external-threat and privilege-escalation
weaknesses and reports, for each finding, a **severity**, the **observed state**,
a **recommended hardening action** and a **reference** to a relevant baseline.

It is strictly read-only: IronSharp only reads WMI, the registry and file ACLs.
It **never changes anything** — no settings are written, no features toggled.
Remediation is left to you (Group Policy, `secpol`, your baseline tooling).

Use it for authorized hardening reviews, baseline gap analysis, pentest
enumeration and CTFs.

## The name

**Iron** for resilience, **Sharp** for C# — and together a nod to the old
proverb, *"as iron sharpens iron."* A blade is made keen not by striking the
enemy but by being worked against iron. IronSharp is that whetstone for a Windows
host: it never swings at an attacker and never touches an edge in anger — it only
reads — yet by surfacing every soft spot and dull seam it leaves the system
sharper, harder, and ready.

---

## What it checks

| Category | Checks | Typical severity |
|----------|--------|------------------|
| **Missing updates** | Windows EoP / RCE CVEs the current build appears unpatched against, from a dataset auto-refreshed from MSRC (incl. several CISA KEV) | High |
| **Third-party software** | Installed third-party applications (registry inventory) checked against a curated, NVD-sourced vulnerability dataset; only curated products are assessed | Low–High |
| **Privilege escalation** | AlwaysInstallElevated (HKLM+HKCU), unquoted service paths, user-writable `%PATH%`, user-modifiable service registry keys, user-writable autorun targets | Medium–High |
| **Credential protection** | WDigest cleartext caching, LSA protection (RunAsPPL), LAN Manager auth level, outgoing NTLM restriction, cached logon count | Low–High |
| **Network protocols** | SMBv1, SMB signing, SMB encryption, LLMNR, NBT-NS, legacy SSL/TLS (SChannel) | Low–High |
| **Remote access** | RDP enabled without Network Level Authentication | High |
| **Accounts & policy** | Guest account state, anonymous / null-session access, UAC configuration | Medium–High |
| **Defense & logging** | Windows Firewall per profile, Microsoft Defender state (real-time, MAPS/cloud, PUA, Tamper Protection — best-effort), PowerShell script-block / module logging, AutoRun/AutoPlay, LAPS presence | Low–High |
| **Endpoint defense** | Registered AV / EDR products | Info/Medium |
| **Credential exposure** | Auto-logon credentials stored in the registry | Medium–High |

Each run starts with a system-info header (OS, build, release, installed KB count).

### Output model

Findings are grouped by category and printed with a severity tag:

```
==== Network protocols ====
[HIGH] SMBv1 server enabled
    Observed       : LanmanServer SMB1 = 1 - the legacy, wormable SMBv1 protocol is enabled.
    Recommendation : Disable and uninstall the SMBv1 feature (Server and Client) on all supported systems.
    Reference      : Microsoft - Stop using SMBv1 / CIS
[OK] SMB signing
    Observed       : Required on both client and server.
```

Where a finding covers many items — affected CVEs, user-writable paths,
modifiable service keys — each item is listed in full, one per line, so nothing
is hidden. A final **Summary** lists the count of weaknesses by severity.

### How the missing-update (CVE) check works

The dataset (`IronSharp/Data/cve-data.json`) maps each CVE, per Windows base
build, to the **build revision (UBR)** that first fixed it (e.g. `19045 → .5679`).
The check reads the machine's base build and its UBR and reports it as **behind**
when the UBR is below a fixing revision. Because Windows cumulative updates are
revision-monotonic, this avoids the false positives of matching exact KB numbers
(a superseded KB drops out of the installed list on a fully-patched machine).

Rather than one finding per CVE, the result is a single summary: *"build X.UBR is
below the latest fix revision .R; N EoP/RCE fixes were released after it"* — i.e.
how far behind the host is and what remains, with the remedy being the latest
cumulative update.

The dataset is **kept current automatically**: a scheduled GitHub Action
(`tools/update_cve_data.py` + `update-data.yml`) pulls recent Windows EoP/RCE CVEs
and their fixed build revisions from the official **MSRC CVRF API**, enriches them
with the **CISA Known Exploited Vulnerabilities** catalog (an `actively exploited`
flag), and commits an updated `cve-data.json`. The run fires on the Wednesday after
Patch Tuesday.

You can use a fresher dataset without rebuilding via `--online` or `--data`.
Note that `--online` does **not** contact MSRC or CISA directly: it downloads the
`cve-data.json` asset attached to the latest GitHub **Release** over HTTPS, keeping
the CVRF/KEV parsing in one place. The scheduled updater refreshes that release
asset after each Patch Tuesday, so `--online` stays current. `--data` loads an
equivalent file you supply. Both fall back to the embedded dataset on any error.

When a build is behind, the summary calls out how many of the missing fixes are
**actively exploited** (CISA KEV) so those can be prioritised.

> **Note.** Assessment needs the build revision (UBR), which reads best from an
> elevated prompt. Always confirm against Windows Update before acting.

### Third-party application CVEs

Beyond Windows itself, IronSharp inventories installed third-party applications
from the registry Uninstall keys (`HKLM`, `HKLM\WOW6432Node`, `HKCU` — read-only;
it does **not** use the slow, side-effecting `Win32_Product` WMI class) and checks
each against a **curated** vulnerability dataset
(`IronSharp/Data/thirdparty-cve-data.json`).

To stay true to IronSharp's low-noise goal, matching is deliberately conservative:

- Only products on the **curated allowlist** (common high-value apps — browsers,
  7-Zip, WinRAR, PuTTY, Java, Acrobat Reader, …) are assessed. Everything else is
  reported, in full, under a single **"not assessed"** coverage line so you can
  see exactly what was and wasn't covered.
- A product is flagged only when its installed version falls inside a CVE's
  affected range **with a known fixed version**. If the version can't be parsed,
  the item is left unassessed rather than guessed.

The dataset is produced by `tools/update_thirdparty_cve_data.py` +
`update-thirdparty-data.yml`, which query the **NVD 2.0 API** per curated product
(CPE vendor/product), keep only ranges with an actionable fixed upper bound, map
CVSS to a severity, and flag **CISA KEV** entries. Set an `NVD_API_KEY` repository
secret for a higher NVD rate limit (optional). Like the Windows dataset, it ships
embedded and is also attached to each release, so `--online` refreshes it too.

> This is a focused, curated check — not a full software-composition scanner. It
> trades breadth for a very low false-positive rate. Validate against the vendor's
> advisory before acting.

---

## Requirements

- Windows (checks rely on Windows WMI and registry APIs)
- .NET Framework 4.8 — already present on current Windows 10/11 and Server builds

Run from an **elevated** prompt for the most complete results; many machine-wide
registry and ACL reads are restricted for standard users.

---

## Installation

### Download a release (recommended)

Download `IronSharp.exe` from the latest
[Release](https://github.com/whoismept/IronSharp/releases/latest). Each release
also ships a `SHA256SUMS.txt`; verify the download before running:

```powershell
(Get-FileHash .\IronSharp.exe -Algorithm SHA256).Hash.ToLower()
# compare the printed hash against the value in SHA256SUMS.txt
```

### Download a CI build

Every push and pull request is also built by GitHub Actions (the **Build**
workflow). Open the latest successful run and download the `IronSharp` artifact.
These artifacts are retained only for a while; releases are permanent.

### Build from source

Requirements: Visual Studio 2019/2022 (or the Build Tools) with the
.NET desktop workload.

**Visual Studio:** open `IronSharp.sln` and build the `Release` configuration.

**Command line** (Developer Command Prompt / PowerShell):

```bat
nuget restore IronSharp.sln
msbuild IronSharp.sln /p:Configuration=Release
```

The binary is written to `IronSharp\bin\Release\IronSharp.exe`.

---

## Usage

Run the executable on the machine you want to audit:

```bat
IronSharp.exe                      :: audit using the embedded datasets (offline)
IronSharp.exe --online             :: fetch the latest datasets first (needs internet)
IronSharp.exe --data cve-data.json :: load the Windows dataset from a local file
IronSharp.exe --thirdparty-data thirdparty-cve-data.json :: local third-party dataset
IronSharp.exe --help               :: show usage
```

Dataset precedence is `--data` / `--thirdparty-data` > `--online` > embedded.
`--online` refreshes **both** datasets (Windows and third-party) from the latest
release's assets. The `--data` / `--thirdparty-data` flags let an air-gapped
operator refresh coverage by copying in a newer JSON (e.g. via USB) without
rebuilding the binary or any internet access.

It writes to standard output. Redirect to keep a report:

```bat
IronSharp.exe > hardening-report.txt
```

Reading the output: `[HIGH]`/`[MEDIUM]`/`[LOW]` tags mark weaknesses with a
recommendation; `[OK]` marks a control that is configured correctly or is
informational. A final **Summary** counts weaknesses by severity.

---

## References

Findings map to well-known hardening guidance. Use these as the authoritative
source when remediating:

- CIS Microsoft Windows Benchmarks — https://www.cisecurity.org/benchmark/microsoft_windows_desktop
- Microsoft Security Baselines (Security Compliance Toolkit) — https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- Microsoft Security Update Guide (CVEs) — https://msrc.microsoft.com/update-guide
- NVD — National Vulnerability Database (third-party application CVEs) — https://nvd.nist.gov
- CISA Known Exploited Vulnerabilities catalog — https://www.cisa.gov/known-exploited-vulnerabilities-catalog

IronSharp reports configuration; it does not certify compliance. Always validate
against the official baseline for your environment.

---

## Legal / authorized use

This tool is intended for security assessments, hardening reviews, CTFs and
research **on systems you own or are explicitly authorized to test**. You are
responsible for complying with all applicable laws and for obtaining permission
before running it against any system. The author assumes no liability for misuse.
