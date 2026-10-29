using System;
using System.IO;

namespace IronSharp.Utilities
{
    internal class CheckTeams
    {
        public static void TeamsInstalled()
        {
            // Classic (Electron) Microsoft Teams installs under the user's
            // LocalAppData folder and historically allowed DLL side-loading
            // from its "current" directory.
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            string path = Path.Combine(localAppData, "Microsoft", "Teams", "current");

            if (Directory.Exists(path))
            {
                Console.WriteLine("[+] Teams (classic) is installed at: " + path);
                Console.WriteLine("    May be susceptible to DLL side-loading. Check writable DLLs in this directory.");
            }
            else
            {
                Console.WriteLine("[-] Teams (classic) current directory not found for this user");
            }
        }
    }
}
