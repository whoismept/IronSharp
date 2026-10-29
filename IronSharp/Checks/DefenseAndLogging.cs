using System.Collections.Generic;
using IronSharp.Core;
using IronSharp.Utilities;

namespace IronSharp.Checks
{
    // Endpoint defense, logging and miscellaneous hardening (read-only).
    internal static class DefenseAndLogging
    {
        private const string Category = "Defense & logging";

        public static void Run()
        {
            Firewall();
            Defender();
            PowerShellLogging();
            AutoRun();
            Laps();
        }

        private static void Firewall()
        {
            const string baseKey = @"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy";
            var profiles = new Dictionary<string, string>
            {
                { "DomainProfile", "Domain" },
                { "StandardProfile", "Private" },
                { "PublicProfile", "Public" }
            };

            var off = new List<string>();
            foreach (var p in profiles)
            {
                int? en = RegistryUtilities.GetHklmDword(baseKey + "\\" + p.Key, "EnableFirewall");
                if (en.HasValue && en.Value == 0)
                {
                    off.Add(p.Value);
                }
            }

            if (off.Count == 0)
            {
                Report.Ok(Category, "Windows Firewall", "No profile is explicitly disabled.");
            }
            else
            {
                Report.Weak(Category, "Windows Firewall disabled for a profile", Severity.High,
                    "EnableFirewall = 0 for profile(s): " + string.Join(", ", off) + ".",
                    "Enable the Windows Firewall on all profiles (Domain, Private, Public).",
                    "CIS - 'Windows Firewall: ... Firewall state'");
            }
        }

        private static void Defender()
        {
            // Best-effort: Defender keys may be unreadable when Tamper Protection is on.
            int? disableAv = RegistryUtilities.GetHklmDword(
                @"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware");
            int? disableRtp = RegistryUtilities.GetHklmDword(
                @"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring");

            if (disableAv.HasValue && disableAv.Value == 1)
            {
                Report.Weak(Category, "Microsoft Defender disabled by policy", Severity.High,
                    "DisableAntiSpyware = 1 - Defender antivirus is turned off by policy.",
                    "Remove the DisableAntiSpyware policy and ensure a supported AV/EDR is active.",
                    "MS Security Baseline - Microsoft Defender Antivirus");
            }
            else if (disableRtp.HasValue && disableRtp.Value == 1)
            {
                Report.Weak(Category, "Defender real-time protection disabled", Severity.High,
                    "DisableRealtimeMonitoring = 1 - real-time protection is turned off by policy.",
                    "Re-enable real-time protection (DisableRealtimeMonitoring = 0 / Not Configured).",
                    "MS Security Baseline - real-time protection");
            }
            // No finding when the keys are absent/unreadable (secure default or Tamper Protection).
        }

        private static void PowerShellLogging()
        {
            int? sbl = RegistryUtilities.GetHklmDword(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging");
            if (!(sbl.HasValue && sbl.Value == 1))
            {
                Report.Weak(Category, "PowerShell script block logging off", Severity.Low,
                    "EnableScriptBlockLogging is not set to 1 - malicious PowerShell is not recorded.",
                    "Enable PowerShell Script Block Logging via policy for better attack visibility.",
                    "CIS - 'Turn on PowerShell Script Block Logging'");
            }
            else
            {
                Report.Ok(Category, "PowerShell script block logging", "Enabled.");
            }

            int? ml = RegistryUtilities.GetHklmDword(
                @"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging", "EnableModuleLogging");
            if (!(ml.HasValue && ml.Value == 1))
            {
                Report.Weak(Category, "PowerShell module logging off", Severity.Low,
                    "EnableModuleLogging is not set to 1.",
                    "Enable PowerShell Module Logging via policy.",
                    "CIS - 'Turn on Module Logging'");
            }
        }

        private static void AutoRun()
        {
            // NoDriveTypeAutoRun = 0xFF (255) disables autorun on all drive types.
            int? v = RegistryUtilities.GetHklmDword(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun");
            if (v.HasValue && v.Value == 0xFF)
            {
                Report.Ok(Category, "AutoRun/AutoPlay", "Disabled for all drive types (NoDriveTypeAutoRun = 255).");
            }
            else
            {
                Report.Weak(Category, "AutoRun/AutoPlay not fully disabled", Severity.Low,
                    "NoDriveTypeAutoRun is " + (v.HasValue ? v.Value.ToString() : "not set") + " (255 disables all).",
                    "Disable AutoPlay/AutoRun for all drives (NoDriveTypeAutoRun = 255) to limit removable-media attacks.",
                    "CIS - 'Turn off AutoPlay'");
            }
        }

        private static void Laps()
        {
            bool legacy = RegistryUtilities.HklmSubKeyExists(@"SOFTWARE\Policies\Microsoft Services\AdmPwd");
            bool windowsLaps = RegistryUtilities.HklmSubKeyExists(@"SOFTWARE\Microsoft\Policies\LAPS")
                               || RegistryUtilities.HklmSubKeyExists(@"SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\State");

            if (legacy || windowsLaps)
            {
                Report.Ok(Category, "LAPS", "A local administrator password solution appears configured.");
            }
            else
            {
                Report.Weak(Category, "No LAPS detected", Severity.Low,
                    "No LAPS (legacy AdmPwd or Windows LAPS) policy was detected.",
                    "Deploy Windows LAPS to randomize and manage local administrator passwords.",
                    "Microsoft - Windows LAPS");
            }
        }
    }
}
