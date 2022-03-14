using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IronSharp.Utilities
{
    internal class AlwaysInstallElevated
    {
        public static void AlwaysInstallElevatedCheck()
        {
            string subKey = @"SOFTWARE\Policies\Microsoft\Windows\Installer\";
            if (ReadFromRegistry("AlwaysInstallElevated", subKey) == "1")
                Console.WriteLine("Always Install Elevated Is Enabled.");
        }
        static string ReadFromRegistry(string keyName, string subKey)
        {
            RegistryKey sk = Registry.LocalMachine.OpenSubKey(subKey);
            if (sk == null) return null; else return sk.GetValue(keyName.ToUpper()).ToString();
        }
    }
}
