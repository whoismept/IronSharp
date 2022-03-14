using System;
using System.Collections;
using Microsoft.Win32;

namespace IronSharp.Utilities
{
    public class ModifiableAutorun
    {
        public static void CheckAutoRun()
        {
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
                    foreach (string key in regkey.GetValueNames())
                    {
                        Console.WriteLine(key + ": " + regkey.GetValue(key));
                    }
                }
            }
            catch { }
        }
    }
}