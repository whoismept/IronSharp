<h1 align="center"><b>IronSharp</b></h1>

<p align="center">
<img src="https://user-images.githubusercontent.com/48562581/157753338-57e41da3-c393-42bf-a4a8-36909987a9bf.png" alt="IronSharp">
</p>

IronSharp is a tool written in C# that detects CVEs caused by missing updates and
privilege escalation vulnerabilities caused by misconfigurations on Windows.
It is a **read-only enumeration / audit** tool: it inspects the local system and
reports findings. It does not exploit anything and makes no changes to the host.

## IronSharp In Action

<p align="center">
<img src="https://user-images.githubusercontent.com/48562581/158132242-4af50ceb-0190-4be9-b5ba-786364479b10.jpg" alt="IronSharp in action">
</p>

## Detected checks

- Missing updates mapped to known CVEs
- `AlwaysInstallElevated` policy (HKLM **and** HKCU)
- Registry auto-logon credentials
- `%PATH%` entries writable by the current user (DLL hijacking)
- Modifiable registry autoruns (Run / RunOnce)
- Modifiable service registry keys
- Unquoted service paths
- Installed AV / EDR / EPP products
- Microsoft Teams (classic) presence for DLL side-loading

## Requirements

- Windows
- .NET Framework 4.8 (ships with current Windows versions)

Some checks (e.g. reading machine-wide registry keys) return more complete
results when run from an elevated prompt, but the tool runs as a standard user.

## Build

Open `IronSharp.sln` in Visual Studio and build the `Release` configuration,
or from a Developer Command Prompt:

```
nuget restore IronSharp.sln
msbuild IronSharp.sln /p:Configuration=Release
```

The resulting binary is `IronSharp/bin/Release/IronSharp.exe`.
Builds are also produced automatically by GitHub Actions (see the **Build** workflow).

## Usage

Run the compiled executable on the system you want to audit:

```
IronSharp.exe
```

## Legal / authorized use

This tool is intended for security assessments, CTFs, and research **on systems
you own or are explicitly authorized to test**. You are responsible for
complying with all applicable laws and for obtaining permission before running
it against any system. The authors assume no liability for misuse.

## Author

- Mert Umut — [@whoismept](https://github.com/whoismept)

Special thanks to [@erdemstar](https://github.com/erdemstar).
