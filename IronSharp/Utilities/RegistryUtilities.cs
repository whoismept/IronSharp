using Microsoft.Win32;
using System;
using System.Management;
using System.Security.AccessControl;
using System.Security.Principal;

namespace IronSharp.Utilities
{
    internal class RegistryUtilities
    {
        public static string GetRegistryValue(string hive, string path, string value)
        {
            string registryKeyValue = null;
            if (hive == "HKCU")
            {
                var regKey = Registry.CurrentUser.OpenSubKey(path);
                if (regKey != null)
                {
                    registryKeyValue = regKey.GetValue(value).ToString();
                }
                return registryKeyValue;
            }
            else if (hive == "HKU")
            {
                var regKey = Registry.Users.OpenSubKey(path);
                if (regKey != null)
                {
                    registryKeyValue = regKey.GetValue(value).ToString();
                }
                return registryKeyValue;
            }
            else
            {
                var regKey = Registry.LocalMachine.OpenSubKey(path);
                if (regKey != null)
                {
                    registryKeyValue = regKey.GetValue(value).ToString();
                }
                return registryKeyValue;
            }
        }
        public static string GetReleaseIdFromRegistiry()
        {
            try
            {
                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                var displayVersion = key.GetValue("ReleaseId").ToString();
                return displayVersion;
            }
            catch (ManagementException e)
            {
                Console.WriteLine("[!] {0}", e.Message);
                throw;
            }
        }
        public static string GetVersionFromRegistry()
        {
            try
            {
                RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
                var displayVersion = key.GetValue("DisplayVersion").ToString();
                return displayVersion;
            }
            catch (ManagementException e)
            {
                Console.WriteLine("[!] {0}", e.Message);
                throw;
            }
            catch (NullReferenceException)
            {
                return "";
            }
        }
        public static bool IsModifiable(RegistryKey key)
        {
            RegistryRights[] ModifyRights =
            {
                RegistryRights.ChangePermissions,
                RegistryRights.FullControl,
                RegistryRights.TakeOwnership,
                RegistryRights.SetValue,
                RegistryRights.WriteKey
            };
            WindowsIdentity identity = WindowsIdentity.GetCurrent();

            AuthorizationRuleCollection rules = key.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));

            foreach (RegistryAccessRule rule in rules)
            {
                if (identity.Groups.Contains(rule.IdentityReference) || rule.IdentityReference == identity.User)
                {
                    foreach (RegistryRights AccessRight in ModifyRights)
                    {
                        if ((AccessRight & rule.RegistryRights) == AccessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                            {
                                return true;
                            }

                        }
                    }
                }
            }
            return false;
        }
    }
}
