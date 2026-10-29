using IronSharp.Core;
using IronSharp.Utilities;

namespace IronSharp.Checks
{
    // Remote Desktop exposure (read-only).
    internal static class RemoteAccess
    {
        private const string Category = "Remote access";

        public static void Run()
        {
            int? deny = RegistryUtilities.GetHklmDword(
                @"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections");

            // 1 (or default on clients) = RDP disabled.
            if (!deny.HasValue || deny.Value == 1)
            {
                Report.Ok(Category, "Remote Desktop (RDP)", "Disabled (fDenyTSConnections = 1 or default).");
                return;
            }

            int? nla = RegistryUtilities.GetHklmDword(
                @"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp", "UserAuthentication");

            if (nla.HasValue && nla.Value == 1)
            {
                Report.Ok(Category, "Remote Desktop (RDP)", "Enabled with Network Level Authentication required.");
            }
            else
            {
                Report.Weak(Category, "RDP enabled without NLA", Severity.High,
                    "fDenyTSConnections = 0 and UserAuthentication is " +
                    (nla.HasValue ? nla.Value.ToString() : "not set") + " - RDP accepts connections without Network Level Authentication.",
                    "Require Network Level Authentication (UserAuthentication = 1), restrict RDP exposure, and prefer a gateway/VPN.",
                    "CIS - 'Require user authentication for remote connections by using NLA'");
            }
        }
    }
}
