using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Principal;

namespace IronSharp.Utilities
{
    internal class CheckTeams
    {
        public static void TeamsInstalled()
        {
            // Classic (Electron) Microsoft Teams installs per-user under
            // LocalAppData, a user-writable location, and has historically
            // been abused for DLL side-loading.
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string current = Path.Combine(localAppData, "Microsoft", "Teams", "current");

            if (!Directory.Exists(current))
            {
                Console.WriteLine("[-] Teams (classic) current directory not found for this user");
                return;
            }

            Console.WriteLine("[+] Teams (classic) found at: " + current);

            bool anyWritable = false;

            // A writable 'current' directory lets an attacker drop a new DLL
            // that Teams (or its Squirrel updater) may load at start-up.
            if (IsWritable(current))
            {
                Console.WriteLine("    [+] Directory is writable - a new DLL could be planted here");
                anyWritable = true;
            }

            // Existing DLLs/EXEs the current user can overwrite are direct
            // side-loading candidates.
            string[] targets;
            try
            {
                targets = Directory.GetFiles(current, "*.dll", SearchOption.TopDirectoryOnly)
                    .Concat(Directory.GetFiles(current, "*.exe", SearchOption.TopDirectoryOnly))
                    .ToArray();
            }
            catch (Exception e)
            {
                Console.WriteLine("    [!] Could not enumerate files: " + e.Message);
                return;
            }

            foreach (var file in targets)
            {
                if (IsWritable(file))
                {
                    Console.WriteLine("    [+] Writable: " + file);
                    anyWritable = true;
                }
            }

            if (anyWritable)
            {
                Console.WriteLine("    May be susceptible to DLL side-loading (user-writable target found).");
            }
            else
            {
                Console.WriteLine("    [-] No user-writable directory or DLL/EXE found - side-loading unlikely from here");
            }
        }

        // Returns true if the current user (via its own SID or group membership)
        // is granted a write-class right on the path and no matching Deny rule
        // blocks it. Deny takes precedence, matching Windows ACL evaluation.
        private static bool IsWritable(string path)
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
