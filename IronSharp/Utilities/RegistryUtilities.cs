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
            RegistryKey regKey;
            if (hive == "HKCU")
            {
                regKey = Registry.CurrentUser.OpenSubKey(path);
            }
            else if (hive == "HKU")
            {
                regKey = Registry.Users.OpenSubKey(path);
            }
            else
            {
                regKey = Registry.LocalMachine.OpenSubKey(path);
            }

            if (regKey != null)
            {
                var raw = regKey.GetValue(value);
                if (raw != null)
                {
                    registryKeyValue = raw.ToString();
                }
            }
            return registryKeyValue;
        }

        // Reads a DWORD from HKLM using the 64-bit view (avoids WOW6432 redirection,
        // which matters for most security-relevant keys). Returns null if the key or
        // value is missing or unreadable.
        public static int? GetHklmDword(string subKey, string name)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = baseKey.OpenSubKey(subKey))
                {
                    if (key == null) return null;
                    object v = key.GetValue(name);
                    if (v == null) return null;
                    try { return Convert.ToInt32(v); }
                    catch { return null; }
                }
            }
            catch
            {
                return null;
            }
        }

        // Reads a value from HKLM (64-bit view) as a string. Null if missing.
        public static string GetHklmString(string subKey, string name)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = baseKey.OpenSubKey(subKey))
                {
                    if (key == null) return null;
                    object v = key.GetValue(name);
                    return v == null ? null : v.ToString();
                }
            }
            catch
            {
                return null;
            }
        }

        // True if the given HKLM subkey exists (64-bit view).
        public static bool HklmSubKeyExists(string subKey)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = baseKey.OpenSubKey(subKey))
                {
                    return key != null;
                }
            }
            catch
            {
                return false;
            }
        }
        public static string GetReleaseIdFromRegistiry()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    var v = key == null ? null : key.GetValue("ReleaseId");
                    return v == null ? "" : v.ToString();
                }
            }
            catch
            {
                return "";
            }
        }
        public static string GetVersionFromRegistry()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    var v = key == null ? null : key.GetValue("DisplayVersion");
                    return v == null ? "" : v.ToString();
                }
            }
            catch
            {
                return "";
            }
        }
        public static bool IsModifiable(RegistryKey key)
        {
            if (key == null)
            {
                return false;
            }
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
