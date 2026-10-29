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

        // Child subkey names of an HKLM key (64-bit view); empty array if missing.
        public static string[] GetHklmSubKeyNames(string subKey)
        {
            try
            {
                using (var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (var key = baseKey.OpenSubKey(subKey))
                {
                    return key == null ? new string[0] : key.GetSubKeyNames();
                }
            }
            catch
            {
                return new string[0];
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
        private const RegistryRights RegWriteMask = RegistryRights.SetValue
            | RegistryRights.CreateSubKey
            | RegistryRights.Delete
            | RegistryRights.WriteKey
            | RegistryRights.ChangePermissions
            | RegistryRights.TakeOwnership
            | RegistryRights.FullControl;

        private static readonly SecurityIdentifier[] NonPrivileged = BuildNonPrivileged();

        private static SecurityIdentifier[] BuildNonPrivileged()
        {
            var types = new[]
            {
                WellKnownSidType.WorldSid,              // Everyone
                WellKnownSidType.AuthenticatedUserSid,  // Authenticated Users
                WellKnownSidType.BuiltinUsersSid,       // BUILTIN\Users
                WellKnownSidType.InteractiveSid,        // INTERACTIVE
            };
            var list = new System.Collections.Generic.List<SecurityIdentifier>();
            foreach (var t in types)
            {
                try { list.Add(new SecurityIdentifier(t, null)); }
                catch { }
            }
            return list.ToArray();
        }

        // True if a non-privileged principal (Users / Authenticated Users /
        // Everyone / INTERACTIVE) can write to the key with no overriding Deny.
        // Administrators / SYSTEM are excluded on purpose: their write access is
        // by design, not a weakness - so this stays meaningful even when
        // IronSharp runs elevated.
        public static bool IsModifiableByNonPrivileged(RegistryKey key)
        {
            if (key == null) return false;
            try
            {
                var rules = key.GetAccessControl().GetAccessRules(true, true, typeof(SecurityIdentifier));
                foreach (var sid in NonPrivileged)
                {
                    bool allow = false, deny = false;
                    foreach (RegistryAccessRule rule in rules)
                    {
                        if (!rule.IdentityReference.Equals(sid)) continue;
                        if ((rule.RegistryRights & RegWriteMask) == 0) continue;
                        if (rule.AccessControlType == AccessControlType.Deny) deny = true;
                        else if (rule.AccessControlType == AccessControlType.Allow) allow = true;
                    }
                    if (allow && !deny) return true;
                }
            }
            catch { }
            return false;
        }
    }
}
