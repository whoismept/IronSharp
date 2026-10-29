using System.Collections.Generic;
using IronSharp.Core;

namespace IronSharp.Utilities
{
    public class HijackablePaths
    {
        const string regPath = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        const string regName = "Path";
        private const string Category = "DLL / binary planting";

        public static void HighjackablePaths()
        {
            string registrypath = RegistryUtilities.GetRegistryValue("HKLM", regPath, regName);
            if (string.IsNullOrEmpty(registrypath))
            {
                return;
            }

            var writable = new List<string>();
            foreach (var item in registrypath.Split(';'))
            {
                if (!string.IsNullOrEmpty(item) && AccessControl.IsWritable(item))
                {
                    writable.Add(item);
                }
            }

            if (writable.Count == 0)
            {
                Report.Ok(Category, "Writable %PATH% directories", "No machine %PATH% directory is user-writable.");
            }
            else
            {
                Report.Weak(Category, "User-writable %PATH% directories", Severity.High,
                    "The current user can write to: " + string.Join("; ", writable),
                    "Remove write permissions for non-administrators on these directories; a planted DLL/binary here can be loaded by privileged processes.",
                    "CIS - file system permissions / DLL search-order hardening");
            }
        }
    }
}

//specialthanks to: https://github.com/erdemstar
