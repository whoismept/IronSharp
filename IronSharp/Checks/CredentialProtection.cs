using IronSharp.Core;
using IronSharp.Utilities;

namespace IronSharp.Checks
{
    // Credential / LSASS protection settings (read-only).
    internal static class CredentialProtection
    {
        private const string Category = "Credential protection";

        public static void Run()
        {
            WDigest();
            LsaProtection();
            LmLevel();
            CachedLogons();
        }

        private static void WDigest()
        {
            int? v = RegistryUtilities.GetHklmDword(
                @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential");
            if (v.HasValue && v.Value == 1)
            {
                Report.Weak(Category, "WDigest caches cleartext credentials", Severity.High,
                    "UseLogonCredential = 1 - logon passwords are held in cleartext in LSASS.",
                    "Set UseLogonCredential to 0 (or remove it) so WDigest does not store plaintext credentials.",
                    "MS Security Baseline / CIS - WDigest");
            }
            else
            {
                Report.Ok(Category, "WDigest cleartext credentials", "Disabled (UseLogonCredential not set to 1).");
            }
        }

        private static void LsaProtection()
        {
            int? v = RegistryUtilities.GetHklmDword(@"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
            if (v.HasValue && (v.Value == 1 || v.Value == 2))
            {
                Report.Ok(Category, "LSA protection (RunAsPPL)", "Enabled (RunAsPPL = " + v.Value + ").");
            }
            else
            {
                Report.Weak(Category, "LSA protection (RunAsPPL) not enabled", Severity.Medium,
                    "RunAsPPL is " + (v.HasValue ? v.Value.ToString() : "not set") + " - LSASS is not running as a protected process.",
                    "Enable LSA protection (RunAsPPL = 1) to make LSASS credential theft harder. Audit LSA plug-ins first.",
                    "Microsoft - Configuring Additional LSA Protection");
            }
        }

        private static void LmLevel()
        {
            int? v = RegistryUtilities.GetHklmDword(@"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel");
            // 5 = send NTLMv2 only, refuse LM & NTLM (hardened).
            if (v.HasValue && v.Value >= 5)
            {
                Report.Ok(Category, "LAN Manager authentication level", "Hardened (LmCompatibilityLevel = " + v.Value + ").");
            }
            else
            {
                Severity sev = (v.HasValue && v.Value >= 3) ? Severity.Low : Severity.Medium;
                Report.Weak(Category, "Weak LAN Manager authentication level", sev,
                    "LmCompatibilityLevel is " + (v.HasValue ? v.Value.ToString() : "not set (OS default)") + ".",
                    "Set LmCompatibilityLevel to 5 (send NTLMv2 only; refuse LM and NTLM).",
                    "CIS - 'Network security: LAN Manager authentication level'");
            }
        }

        private static void CachedLogons()
        {
            string s = RegistryUtilities.GetRegistryValue("HKLM",
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "CachedLogonsCount");
            int count;
            if (s != null && int.TryParse(s, out count))
            {
                if (count > 4)
                {
                    Report.Weak(Category, "High cached logon count", Severity.Low,
                        "CachedLogonsCount = " + count + " - more cached domain credentials are available to offline attacks.",
                        "Lower CachedLogonsCount (e.g. 0-4) in line with your operational needs.",
                        "CIS - 'Interactive logon: Number of previous logons to cache'");
                }
                else
                {
                    Report.Ok(Category, "Cached logon count", "CachedLogonsCount = " + count + ".");
                }
            }
            // If unreadable/absent, stay silent (OS default varies) to avoid noise.
        }
    }
}
