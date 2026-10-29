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

---

## What it checks

| Category | Checks | Typical severity |
|----------|--------|------------------|
| **Missing updates** | Known privilege-escalation / RCE CVEs the current build appears unpatched against (2019 → 2025, incl. several CISA KEV) | High |
| **Privilege escalation** | AlwaysInstallElevated (HKLM+HKCU), unquoted service paths, user-writable `%PATH%`, user-modifiable service registry keys, user-writable autorun targets | Medium–High |
| **Credential protection** | WDigest cleartext caching, LSA protection (RunAsPPL), LAN Manager auth level, cached logon count | Low–High |
| **Network protocols** | SMBv1, SMB signing, LLMNR, NBT-NS, legacy SSL/TLS (SChannel) | Medium–High |
| **Remote access** | RDP enabled without Network Level Authentication | High |
| **Accounts & policy** | Guest account state, anonymous / null-session access, UAC configuration | Medium–High |
| **Defense & logging** | Windows Firewall per profile, Microsoft Defender state (best-effort), PowerShell script-block / module logging, AutoRun/AutoPlay, LAPS presence | Low–High |
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

A final **Summary** lists the count of weaknesses by severity.

### How the missing-update (CVE) check works

For each supported CVE, IronSharp knows the per-build KB update(s) that fix it.
It reads the build number and installed KBs and flags a CVE as *potentially
vulnerable* when the machine runs an affected build **and none** of the fixing
KBs is installed.

> **Accuracy note.** This is a heuristic based on the *first* fixing update per
> build. Windows cumulative updates supersede one another, so a machine patched
> by a **later** cumulative update not listed for a given CVE may still be
> reported. Confirm any finding against the current patch level. Coverage runs
> from 2019 through 2025; newer CVEs can be added as verified KB data becomes
> available.

---

## Requirements

- Windows (checks rely on Windows WMI and registry APIs)
- .NET Framework 4.8 — already present on current Windows 10/11 and Server builds

Run from an **elevated** prompt for the most complete results; many machine-wide
registry and ACL reads are restricted for standard users.

---

## Installation

### Download a build

Every push and pull request is built by GitHub Actions (the **Build** workflow).
Open the latest successful run and download the `IronSharp` artifact.

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
IronSharp.exe
```

It takes no arguments and writes to standard output. Redirect to keep a report:

```bat
IronSharp.exe > hardening-report.txt
```

Reading the output: `[HIGH]`/`[MEDIUM]`/`[LOW]` tags mark weaknesses with a
recommendation; `[OK]` marks a control that is configured correctly or is
informational.

---

## References

Findings map to well-known hardening guidance. Use these as the authoritative
source when remediating:

- CIS Microsoft Windows Benchmarks — https://www.cisecurity.org/benchmark/microsoft_windows_desktop
- Microsoft Security Baselines (Security Compliance Toolkit) — https://learn.microsoft.com/windows/security/operating-system-security/device-management/windows-security-configuration-framework/windows-security-baselines
- Microsoft Security Update Guide (CVEs) — https://msrc.microsoft.com/update-guide

IronSharp reports configuration; it does not certify compliance. Always validate
against the official baseline for your environment.

---

## Legal / authorized use

This tool is intended for security assessments, hardening reviews, CTFs and
research **on systems you own or are explicitly authorized to test**. You are
responsible for complying with all applicable laws and for obtaining permission
before running it against any system. The author assumes no liability for misuse.

---

## Author

- Mert Umut — [@whoismept](https://github.com/whoismept)

Special thanks to [@erdemstar](https://github.com/erdemstar).
