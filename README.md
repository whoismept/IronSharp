# IronSharp

IronSharp is a Windows privilege-escalation **auditing** tool written in C#.
It inspects the local machine for two classes of issues:

1. **Missing security updates** that leave known, patchable CVEs exposed.
2. **Misconfigurations** that can be abused to escalate privileges
   (writable service paths, modifiable autoruns, weak policies, etc.).

It is **read-only**: IronSharp only reads system state (WMI, the registry and
the filesystem ACLs) and prints what it finds. It does not exploit anything,
install anything, or modify the host in any way. Think of it as an enumeration
aid for authorized penetration tests, CTFs and hardening reviews, similar in
spirit to WinPEAS or Seatbelt but focused and lightweight.

---

## What it checks

| Check | What it reports | Why it matters |
|-------|-----------------|----------------|
| **System info** | OS name, display version, build number, release ID | Establishes the exact build so CVE results are meaningful |
| **Installed updates** | The list of installed KB hotfixes and their count | Basis for the missing-update checks below |
| **Missing-update CVEs** | Known local privilege-escalation CVEs that the current build appears unpatched against | Unpatched LPE bugs are the most direct SYSTEM path |
| **Unquoted service paths** | Service `ImagePath` values that contain spaces but no quotes (outside System32) | A writable parent folder can let an attacker hijack service start-up |
| **Hijackable `%PATH%`** | Machine `%PATH%` directories writable by the current user | Enables DLL/binary planting that privileged processes may load |
| **Modifiable autoruns** | Entries under the `Run` / `RunOnce` (incl. Wow6432Node) keys | Writable autorun targets run at logon, potentially elevated |
| **Modifiable service keys** | Service registry keys the current user can modify | Lets an attacker repoint a service binary and gain its privileges |
| **AlwaysInstallElevated** | Whether the policy is set in **both** HKLM and HKCU | When both are `1`, any MSI runs as SYSTEM |
| **Auto-logon** | Credentials stored in the Winlogon registry keys | Plaintext passwords / SIDs left in the registry |
| **AV / EDR** | Security products registered with Windows Security Center | Helps understand what defenses are present |
| **Microsoft Teams (classic)** | Whether the classic Teams `current` directory exists | Historically vulnerable to DLL side-loading |

### How the CVE check works

For each supported CVE, IronSharp knows, per Windows build, the KB update(s)
that fix it. It reads the build number and the installed KB list, and reports a
CVE as *potentially vulnerable* when the machine runs an affected build **and
none** of the fixing KBs is installed.

> **Note on accuracy.** This is a heuristic based on the *first* fixing update
> for each build. Windows cumulative updates supersede one another, so a machine
> that was patched by a **later** cumulative update not listed for a given CVE
> may still be reported. Always confirm a finding against the current patch
> level before acting on it. Results are also most complete when IronSharp is
> run from an elevated prompt.

---

## Requirements

- Windows (the checks rely on Windows WMI and registry APIs)
- .NET Framework 4.8 — already present on current Windows 10/11 and Server builds

---

## Installation

### Download a build

Every push and pull request is built by GitHub Actions (the **Build** workflow).
Open the latest successful run and download the `IronSharp` artifact, which
contains `IronSharp.exe`.

### Build from source

Requirements: Visual Studio 2019/2022 (or the Build Tools) with the
.NET desktop workload.

**Visual Studio:** open `IronSharp.sln` and build the `Release` configuration.

**Command line** (Developer Command Prompt / PowerShell):

```bat
nuget restore IronSharp.sln
msbuild IronSharp.sln /p:Configuration=Release
```

The compiled binary is written to:

```
IronSharp\bin\Release\IronSharp.exe
```

---

## Usage

Copy `IronSharp.exe` to the machine you are auditing and run it from a console:

```bat
IronSharp.exe
```

It takes no arguments and writes its findings to standard output. Run it from an
**elevated** prompt for the most complete results (some registry and ACL reads
are restricted for standard users).

### Reading the output

- Lines prefixed with `[+]` are positive findings or facts worth attention
  (e.g. a writable path, a stored credential, a potential CVE).
- Lines prefixed with `[-]` mean the corresponding check found nothing notable.
- A `Vulnerable for ...` line means the build looks unpatched against that CVE
  (see the accuracy note above).

Redirect to a file to keep a report:

```bat
IronSharp.exe > ironsharp-report.txt
```

---

## Legal / authorized use

This tool is intended for security assessments, CTFs and research **on systems
you own or are explicitly authorized to test**. You are responsible for
complying with all applicable laws and for obtaining permission before running
it against any system. The author assumes no liability for misuse.

---

## Author

- Mert Umut — [@whoismept](https://github.com/whoismept)

Special thanks to [@erdemstar](https://github.com/erdemstar).
