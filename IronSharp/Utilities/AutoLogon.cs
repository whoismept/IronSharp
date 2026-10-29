using Microsoft.Win32;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    public class AutoLogon
    {
        private const string Category = "Credential exposure";

        public static void LoginCheck()
        {
            try
            {
                RegistryKey rb = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                RegistryKey rb2 = rb.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                if (rb2 == null)
                {
                    Report.Ok(Category, "Auto-logon", "No Winlogon key readable.");
                    return;
                }

                var autologon = rb2.GetValue("AutoAdminLogon");
                bool enabled = autologon != null && autologon.ToString() == "1";
                var password = rb2.GetValue("DefaultPassword");

                if (enabled && password != null)
                {
                    Report.Weak(Category, "Auto-logon with stored password", Severity.High,
                        "AutoAdminLogon is enabled and a DefaultPassword is stored in cleartext in the registry (user: " +
                        (rb2.GetValue("DefaultUsername") ?? "?") + ").",
                        "Disable auto-logon (AutoAdminLogon = 0) and remove the DefaultPassword value.",
                        "MS Security Baseline / CIS - interactive logon");
                }
                else if (enabled)
                {
                    Report.Weak(Category, "Auto-logon enabled", Severity.Medium,
                        "AutoAdminLogon is enabled for user " + (rb2.GetValue("DefaultUsername") ?? "?") + ".",
                        "Disable auto-logon unless strictly required; never with a privileged account.",
                        "MS Security Baseline - interactive logon");
                }
                else
                {
                    Report.Ok(Category, "Auto-logon", "Not enabled.");
                }
            }
            catch { }
        }
    }
}
