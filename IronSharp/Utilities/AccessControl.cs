using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace IronSharp.Utilities
{
    internal class AccessControl
    {
        // Returns true if the current user (via its own SID or group membership)
        // is granted a write-class right on the path (file or directory) and no
        // matching Deny rule blocks it. Deny takes precedence, matching Windows
        // ACL evaluation. Returns false on any error (e.g. access denied).
        public static bool IsWritable(string path)
        {
            try
            {
                AuthorizationRuleCollection rules = Directory.Exists(path)
                    ? Directory.GetAccessControl(path).GetAccessRules(true, true, typeof(SecurityIdentifier))
                    : File.GetAccessControl(path).GetAccessRules(true, true, typeof(SecurityIdentifier));

                WindowsIdentity identity = WindowsIdentity.GetCurrent();
                var principals = new List<IdentityReference>(identity.Groups);
                principals.Add(identity.User);

                const FileSystemRights writeMask = FileSystemRights.Write
                    | FileSystemRights.WriteData
                    | FileSystemRights.CreateFiles
                    | FileSystemRights.Modify
                    | FileSystemRights.FullControl;

                bool allowed = false;
                foreach (FileSystemAccessRule rule in rules)
                {
                    if (!principals.Contains(rule.IdentityReference))
                    {
                        continue;
                    }
                    if ((rule.FileSystemRights & writeMask) == 0)
                    {
                        continue;
                    }
                    if (rule.AccessControlType == AccessControlType.Deny)
                    {
                        return false;
                    }
                    if (rule.AccessControlType == AccessControlType.Allow)
                    {
                        allowed = true;
                    }
                }
                return allowed;
            }
            catch
            {
                return false;
            }
        }
    }
}
