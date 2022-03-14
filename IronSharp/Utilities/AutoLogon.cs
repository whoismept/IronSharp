using Microsoft.Win32;
using System;
namespace IronSharp.Utilities
{
    public class AutoLogon
    {
        public static void LoginCheck()
        {
            try
            {
                RegistryKey rb = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                RegistryKey rb2 = rb.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon");
                var autologon = rb2.GetValue("AutoAdminLogon");
                if (autologon.Equals("1"))
                {
                    Console.WriteLine("[+] Credentials Found: ");
                    Console.WriteLine("Admin Logon: " + rb2.GetValue("AutoAdminLogon"));
                    Console.WriteLine("SID :" + rb2.GetValue("AutoLogonSID"));
                    Console.WriteLine("Username: " + rb2.GetValue("DefaultUsername"));
                    Console.WriteLine("Password: " + rb2.GetValue("Password"));
                }
                else
                {
                    Console.WriteLine("No Autologon Registry Key Found..");
                }
            }
            catch { }
        }
    }
}
