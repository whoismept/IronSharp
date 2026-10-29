using System;
using System.Linq;
using System.Management;
using IronSharp.Core;
using IronSharp.Utilities;

namespace IronSharp.Checks
{
    // Account and local security policy settings (read-only).
    internal static class AccountPolicy
    {
        private const string Category = "Accounts & policy";
        private const string Lsa = @"SYSTEM\CurrentControlSet\Control\Lsa";

        public static void Run()
        {
            GuestAccount();
            AnonymousAccess();
            Uac();
        }

        private static void GuestAccount()
        {
            try
            {
                // The built-in Guest account always has a SID ending in -501.
                using (var searcher = new ManagementObjectSearcher(@"root\cimv2",
                    "SELECT Name, Disabled, SID FROM Win32_UserAccount WHERE LocalAccount = TRUE"))
                {
                    foreach (var acct in searcher.Get().OfType<ManagementObject>())
                    {
                        string sid = Convert.ToString(acct["SID"]);
                        if (sid != null && sid.EndsWith("-501"))
                        {
                            bool disabled = acct["Disabled"] != null && Convert.ToBoolean(acct["Disabled"]);
                            string name = Convert.ToString(acct["Name"]);
                            if (disabled)
                            {
                                Report.Ok(Category, "Guest account", "Disabled (" + name + ").");
                            }
                            else
                            {
                                Report.Weak(Category, "Guest account enabled", Severity.Medium,
                                    "The built-in Guest account (" + name + ") is enabled.",
                                    "Disable the Guest account.",
                                    "CIS - 'Accounts: Guest account status'");
                            }
                            return;
                        }
                    }
                }
            }
            catch { }
        }

        private static void AnonymousAccess()
        {
            int? restrictAnon = RegistryUtilities.GetHklmDword(Lsa, "RestrictAnonymous");
            int? everyoneAnon = RegistryUtilities.GetHklmDword(Lsa, "EveryoneIncludesAnonymous");

            bool weak = (restrictAnon.HasValue && restrictAnon.Value == 0)
                        || (everyoneAnon.HasValue && everyoneAnon.Value == 1);

            if (weak)
            {
                Report.Weak(Category, "Anonymous (null session) access allowed", Severity.Medium,
                    "RestrictAnonymous = " + (restrictAnon.HasValue ? restrictAnon.Value.ToString() : "unset") +
                    ", EveryoneIncludesAnonymous = " + (everyoneAnon.HasValue ? everyoneAnon.Value.ToString() : "unset") + ".",
                    "Restrict anonymous enumeration: RestrictAnonymous = 1 and EveryoneIncludesAnonymous = 0.",
                    "CIS - 'Network access: Do not allow anonymous enumeration ...'");
            }
            else
            {
                Report.Ok(Category, "Anonymous (null session) access", "Restricted or at secure default.");
            }
        }

        private static void Uac()
        {
            const string policies = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System";
            int? enableLua = RegistryUtilities.GetHklmDword(policies, "EnableLUA");
            int? consentAdmin = RegistryUtilities.GetHklmDword(policies, "ConsentPromptBehaviorAdmin");

            if (enableLua.HasValue && enableLua.Value == 0)
            {
                Report.Weak(Category, "UAC disabled", Severity.High,
                    "EnableLUA = 0 - User Account Control is turned off; admin approval mode is not enforced.",
                    "Enable UAC (EnableLUA = 1) and keep admin approval mode on.",
                    "CIS - 'User Account Control: Run all administrators in Admin Approval Mode'");
            }
            else if (consentAdmin.HasValue && consentAdmin.Value == 0)
            {
                Report.Weak(Category, "UAC elevation prompt weakened", Severity.Medium,
                    "ConsentPromptBehaviorAdmin = 0 - administrators elevate without any prompt.",
                    "Set ConsentPromptBehaviorAdmin to prompt for consent/credentials (e.g. 2 or 5).",
                    "CIS - 'UAC: Behavior of the elevation prompt for administrators'");
            }
            else
            {
                Report.Ok(Category, "User Account Control (UAC)", "Enabled.");
            }
        }
    }
}
