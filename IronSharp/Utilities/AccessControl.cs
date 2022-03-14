using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace IronSharp.Utilities
{
    class AccessControl
    {
        public static void CheckPermission(string dir, FileSystemRights AccessRight)
        {
            try
            {
                AuthorizationRuleCollection rules = Directory.GetAccessControl(dir).GetAccessRules(true, true, typeof(SecurityIdentifier));
                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                foreach (FileSystemAccessRule rule in rules)
                {
                    if (identity.Groups.Contains(rule.IdentityReference))
                    {
                        if ((AccessRight & rule.FileSystemRights) == AccessRight)
                        {
                            if (rule.AccessControlType == AccessControlType.Allow)
                            {
                                Console.WriteLine("[+] {0} : Writable", dir);
                            }
                        }
                    }
                }
            }
            catch { }
        }
    }
}