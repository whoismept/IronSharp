using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Principal;
using IronSharp.Core;

namespace IronSharp
{
    internal class Program
    {
        private const string OnlineDataUrl =
            "https://raw.githubusercontent.com/whoismept/IronSharp/master/IronSharp/Data/cve-data.json";
        private const string OnlineThirdPartyDataUrl =
            "https://raw.githubusercontent.com/whoismept/IronSharp/master/IronSharp/Data/thirdparty-cve-data.json";

        static void Main(string[] args)
        {
            if (args.Any(a => a == "-h" || a == "--help" || a == "/?"))
            {
                PrintUsage();
                return;
            }

            Information.Banner();
            PrintSystemInfo();

            // Dataset precedence: --data <file>  >  --online  >  embedded.
            string datasetJson = ResolveDataset(args);
            string thirdPartyJson = ResolveThirdPartyDataset(args);

            // All checks are read-only: they inspect WMI, the registry and file
            // ACLs and record findings. Nothing on the system is modified.
            Utilities.CVECheck.CheckAll(datasetJson);
            Checks.ThirdPartySoftware.Run(thirdPartyJson);
            Utilities.UnquotedPathCheck.CheckUnquotedPath();
            Utilities.HijackablePaths.HighjackablePaths();
            Utilities.ModifiableAutorun.CheckAutoRun();
            Utilities.ModifiableKeys.ModifiableKey();
            Utilities.AlwaysInstallElevated.AlwaysInstallElevatedCheck();
            Utilities.AutoLogon.LoginCheck();
            Utilities.GetAv.CheckSecurityProduct();

            // Configuration hardening checks against external threats (read-only).
            Checks.CredentialProtection.Run();
            Checks.NetworkProtocols.Run();
            Checks.RemoteAccess.Run();
            Checks.AccountPolicy.Run();
            Checks.DefenseAndLogging.Run();

            Report.PrintAll();
            Report.PrintSummary();
        }

        private static void PrintUsage()
        {
            Console.WriteLine("IronSharp - read-only Windows hardening advisor");
            Console.WriteLine();
            Console.WriteLine("Usage: IronSharp.exe [--online | --data <file>] [--thirdparty-data <file>]");
            Console.WriteLine("  (no option)         Audit using the datasets embedded in the binary (offline).");
            Console.WriteLine("  --online            Download the latest Windows and third-party CVE datasets");
            Console.WriteLine("                      over HTTPS first (needs internet; falls back to embedded).");
            Console.WriteLine("  --data <file>       Load the Windows CVE dataset from a local JSON file");
            Console.WriteLine("                      (offline refresh without rebuilding).");
            Console.WriteLine("  --thirdparty-data <file>  Load the third-party application CVE dataset from");
            Console.WriteLine("                      a local JSON file.");
            Console.WriteLine("  -h, --help          Show this help.");
            Console.WriteLine();
            Console.WriteLine("The tool only reads and reports; it never changes the system.");
        }

        // Returns an override dataset JSON, or null to use the embedded dataset.
        private static string ResolveDataset(string[] args)
        {
            string dataPath = GetOption(args, "--data");
            if (dataPath != null)
            {
                return LoadLocalDataset(dataPath);
            }
            if (args.Any(a => a.Equals("--online", StringComparison.OrdinalIgnoreCase)))
            {
                return FetchOnline(OnlineDataUrl, "Windows CVE dataset");
            }
            return null;
        }

        // Same precedence for the third-party application dataset.
        private static string ResolveThirdPartyDataset(string[] args)
        {
            string dataPath = GetOption(args, "--thirdparty-data");
            if (dataPath != null)
            {
                return LoadLocalDataset(dataPath);
            }
            if (args.Any(a => a.Equals("--online", StringComparison.OrdinalIgnoreCase)))
            {
                return FetchOnline(OnlineThirdPartyDataUrl, "third-party CVE dataset");
            }
            return null;
        }

        // Supports "--data <value>" and "--data=<value>".
        private static string GetOption(string[] args, string name)
        {
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return i + 1 < args.Length ? args[i + 1] : null;
                }
                if (args[i].StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))
                {
                    return args[i].Substring(name.Length + 1);
                }
            }
            return null;
        }

        private static string LoadLocalDataset(string path)
        {
            try
            {
                string json = File.ReadAllText(path);
                Console.WriteLine("[*] Using CVE dataset file: " + path);
                Console.WriteLine("------------------------");
                return json;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Could not read dataset file ({0}); using the embedded dataset.", e.Message);
                Console.WriteLine("------------------------");
                return null;
            }
        }

        private static string FetchOnline(string url, string label)
        {
            try
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                using (var wc = new WebClient())
                {
                    wc.Headers.Add("User-Agent", "IronSharp");
                    string json = wc.DownloadString(url);
                    Console.WriteLine("[*] Online mode: fetched the latest {0}.", label);
                    Console.WriteLine("------------------------");
                    return json;
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Online fetch of the {0} failed ({1}); using the embedded copy.", label, e.Message);
                Console.WriteLine("------------------------");
                return null;
            }
        }

        private static void PrintSystemInfo()
        {
            Console.WriteLine("------------------------");
            string os = Utilities.GetWMIQuery.GetOSName();
            Console.WriteLine("[*] OS Name            : " + os);
            if (os != null && !os.Contains("Server"))
            {
                Console.WriteLine("[*] Display Version    : " + Utilities.RegistryUtilities.GetVersionFromRegistry());
            }
            int build = Utilities.GetWMIQuery.GetBuildNumber();
            int? ubr = Utilities.RegistryUtilities.GetHklmDword(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
            Console.WriteLine("[*] Build Number       : " + build + (ubr.HasValue ? "." + ubr.Value : ""));
            Console.WriteLine("[*] Release ID         : " + Utilities.RegistryUtilities.GetReleaseIdFromRegistiry());
            Console.WriteLine("[*] Installed KB count : " + Utilities.GetWMIQuery.GetInstalledKBs().Count);
            bool admin = IsElevated();
            Console.WriteLine("[*] Privilege          : " + (admin ? "Administrator (elevated)" : "Standard user"));
            Console.WriteLine("------------------------");
            if (!admin)
            {
                Console.WriteLine("[!] Not elevated: some registry / service / ACL reads are restricted, so results may be incomplete.");
                Console.WriteLine("    Run IronSharp from an elevated (Administrator) prompt for a complete audit.");
                Console.WriteLine("------------------------");
            }
        }

        private static bool IsElevated()
        {
            try
            {
                using (var id = WindowsIdentity.GetCurrent())
                {
                    return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }
    }
}
