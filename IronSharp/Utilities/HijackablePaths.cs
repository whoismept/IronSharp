using System.Security.AccessControl;

namespace IronSharp.Utilities
{
    public class HijackablePaths
    {
        const string regPath = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment";
        const string regName = "Path";
        public static string registrypath = RegistryUtilities.GetRegistryValue("HKLM", regPath, regName);
        public static void HighjackablePaths()
        {
            foreach (var item in registrypath.Split(';'))
            {
                if (!string.IsNullOrEmpty(item))
                {
                    AccessControl.CheckPermission(item, FileSystemRights.Write);
                }
            }
        }
    }
}
