using System.Collections;
using System.Collections.Generic;
using Microsoft.Win32;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    public class ModifiableAutorun
    {
        private const string Category = "DLL / binary planting";

        public static void CheckAutoRun()
        {
            var writableTargets = new List<string>();
            try
            {
                RegistryKey rb = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
                ArrayList regkeys = new ArrayList()
                {
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
                    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
                    "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService",
                    "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService"
                };
                foreach (string item in regkeys)
                {
                    RegistryKey regkey = rb.OpenSubKey(item);
                    if (regkey == null)
                    {
                        continue;
                    }
                    foreach (string name in regkey.GetValueNames())
                    {
                        string command = System.Convert.ToString(regkey.GetValue(name));
                        string exe = ExtractExePath(command);
                        if (!string.IsNullOrEmpty(exe) && AccessControl.IsWritable(exe))
                        {
                            writableTargets.Add(name + " -> " + exe);
                        }
                    }
                }
            }
            catch { }

            if (writableTargets.Count == 0)
            {
                Report.Ok(Category, "Machine autorun targets", "No HKLM Run/RunOnce target is user-writable.");
            }
            else
            {
                Report.Weak(Category, "User-writable autorun targets", Severity.Medium,
                    "The current user can overwrite the binary launched by autorun entr(ies): " + string.Join("; ", writableTargets),
                    "Restrict write access on these executables to administrators; a writable autorun target runs at logon and can be hijacked.",
                    "CIS - startup program / file permission hardening");
            }
        }

        // Best-effort extraction of the executable path from a Run command line.
        private static string ExtractExePath(string command)
        {
            if (string.IsNullOrEmpty(command))
            {
                return null;
            }
            command = command.Trim();
            if (command.StartsWith("\""))
            {
                int end = command.IndexOf('"', 1);
                return end > 1 ? command.Substring(1, end - 1) : null;
            }
            int idx = command.ToLowerInvariant().IndexOf(".exe");
            if (idx >= 0)
            {
                return command.Substring(0, idx + 4);
            }
            // No .exe and unquoted: take the first whitespace-delimited token.
            int space = command.IndexOf(' ');
            return space > 0 ? command.Substring(0, space) : command;
        }
    }
}
