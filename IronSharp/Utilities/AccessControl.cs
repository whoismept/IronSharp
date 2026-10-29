using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace IronSharp.Utilities
{
    internal class AccessControl
    {
        private const FileSystemRights WriteMask = FileSystemRights.Write
            | FileSystemRights.WriteData
            | FileSystemRights.CreateFiles
            | FileSystemRights.CreateDirectories
            | FileSystemRights.AppendData
            | FileSystemRights.Modify
            | FileSystemRights.FullControl
            | FileSystemRights.TakeOwnership
            | FileSystemRights.ChangePermissions;

        // Well-known non-privileged principals. Write access granted to any of
        // these is a real weakness regardless of whether IronSharp itself runs
        // elevated (an administrator being able to write is by design, so the
        // Administrators / SYSTEM groups are deliberately excluded).
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
            var list = new List<SecurityIdentifier>();
            foreach (var t in types)
            {
                try { list.Add(new SecurityIdentifier(t, null)); }
                catch { }
            }
            return list.ToArray();
        }

        // True if a non-privileged principal is granted a write-class right on the
        // path (file or directory) with no overriding Deny for that same principal.
        public static bool IsWritableByNonPrivileged(string path)
        {
            try
            {
                AuthorizationRuleCollection rules = Directory.Exists(path)
                    ? Directory.GetAccessControl(path).GetAccessRules(true, true, typeof(SecurityIdentifier))
                    : File.GetAccessControl(path).GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (var sid in NonPrivileged)
                {
                    bool allow = false, deny = false;
                    foreach (FileSystemAccessRule rule in rules)
                    {
                        if (!rule.IdentityReference.Equals(sid)) continue;
                        if ((rule.FileSystemRights & WriteMask) == 0) continue;
                        if (rule.AccessControlType == AccessControlType.Deny) deny = true;
                        else if (rule.AccessControlType == AccessControlType.Allow) allow = true;
                    }
                    if (allow && !deny) return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }
    }
}
