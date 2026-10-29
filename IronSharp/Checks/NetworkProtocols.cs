using System.Collections.Generic;
using IronSharp.Core;
using IronSharp.Utilities;

namespace IronSharp.Checks
{
    // Legacy / network protocol hardening (read-only).
    internal static class NetworkProtocols
    {
        private const string Category = "Network protocols";

        public static void Run()
        {
            Smb1();
            SmbSigning();
            Llmnr();
            NbtNs();
            LegacyTls();
        }

        private static void Smb1()
        {
            int? server = RegistryUtilities.GetHklmDword(
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1");
            if (server.HasValue && server.Value == 0)
            {
                Report.Ok(Category, "SMBv1 server", "Disabled (SMB1 = 0).");
            }
            else if (server.HasValue && server.Value == 1)
            {
                Report.Weak(Category, "SMBv1 server enabled", Severity.High,
                    "LanmanServer SMB1 = 1 - the legacy, wormable SMBv1 protocol is enabled.",
                    "Disable and uninstall the SMBv1 feature (Server and Client) on all supported systems.",
                    "Microsoft - Stop using SMBv1 / CIS");
            }
            else
            {
                Report.Weak(Category, "SMBv1 server state unconfirmed", Severity.Low,
                    "LanmanServer SMB1 value is not set; the SMBv1 feature may still be installed.",
                    "Verify the SMBv1 feature is removed (Get-WindowsOptionalFeature / Get-WindowsFeature).",
                    "Microsoft - Stop using SMBv1");
            }
        }

        private static void SmbSigning()
        {
            int? srv = RegistryUtilities.GetHklmDword(
                @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature");
            int? wks = RegistryUtilities.GetHklmDword(
                @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature");

            var missing = new List<string>();
            if (!(srv.HasValue && srv.Value == 1)) missing.Add("server");
            if (!(wks.HasValue && wks.Value == 1)) missing.Add("client");

            if (missing.Count == 0)
            {
                Report.Ok(Category, "SMB signing", "Required on both client and server.");
            }
            else
            {
                Report.Weak(Category, "SMB signing not required", Severity.High,
                    "RequireSecuritySignature is not 1 for: " + string.Join(", ", missing) + ".",
                    "Require SMB signing on both SMB client and server to defend against relay / on-path attacks.",
                    "MS Security Baseline / CIS - 'Microsoft network ... Digitally sign communications (always)'");
            }
        }

        private static void Llmnr()
        {
            int? v = RegistryUtilities.GetHklmDword(
                @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast");
            if (v.HasValue && v.Value == 0)
            {
                Report.Ok(Category, "LLMNR", "Disabled (EnableMulticast = 0).");
            }
            else
            {
                Report.Weak(Category, "LLMNR enabled", Severity.Medium,
                    "EnableMulticast is " + (v.HasValue ? v.Value.ToString() : "not set (LLMNR on by default)") +
                    " - LLMNR is susceptible to name-resolution poisoning and credential relay.",
                    "Disable LLMNR via policy: set DNSClient\\EnableMulticast = 0 ('Turn off multicast name resolution').",
                    "CIS - 'Turn off multicast name resolution'");
            }
        }

        private static void NbtNs()
        {
            const string ifaces = @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces";
            var enabledOn = new List<string>();
            foreach (var name in RegistryUtilities.GetHklmSubKeyNames(ifaces))
            {
                int? opt = RegistryUtilities.GetHklmDword(ifaces + "\\" + name, "NetbiosOptions");
                // 2 = disabled. 0 (default) or 1 = enabled.
                if (!(opt.HasValue && opt.Value == 2))
                {
                    enabledOn.Add(name);
                }
            }

            if (enabledOn.Count == 0)
            {
                Report.Ok(Category, "NetBIOS over TCP/IP (NBT-NS)", "Disabled on all interfaces, or none present.");
            }
            else
            {
                Report.Weak(Category, "NBT-NS enabled on network interfaces", Severity.Medium,
                    enabledOn.Count + " interface(s) do not have NetbiosOptions = 2 (NBT-NS still active).",
                    "Disable NetBIOS over TCP/IP (NetbiosOptions = 2) on all adapters to stop NBT-NS poisoning / relay.",
                    "CIS / hardening - disable NBT-NS");
            }
        }

        private static void LegacyTls()
        {
            const string baseKey = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols";
            string[] legacy = { "SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1" };
            var enabled = new List<string>();
            foreach (var proto in legacy)
            {
                int? en = RegistryUtilities.GetHklmDword(baseKey + "\\" + proto + "\\Server", "Enabled");
                int? dis = RegistryUtilities.GetHklmDword(baseKey + "\\" + proto + "\\Server", "DisabledByDefault");
                // Only flag when explicitly turned on, to avoid false positives on OS defaults.
                if ((en.HasValue && en.Value != 0) || (dis.HasValue && dis.Value == 0))
                {
                    enabled.Add(proto);
                }
            }

            if (enabled.Count == 0)
            {
                Report.Ok(Category, "Legacy SChannel protocols", "No legacy SSL/TLS protocol is explicitly enabled (server).");
            }
            else
            {
                Report.Weak(Category, "Legacy SSL/TLS protocols enabled", Severity.Medium,
                    "Explicitly enabled (server): " + string.Join(", ", enabled) + ".",
                    "Disable SSL 2.0/3.0 and TLS 1.0/1.1 in SCHANNEL; require TLS 1.2+.",
                    "CIS - SChannel protocol hardening");
            }
        }
    }
}
