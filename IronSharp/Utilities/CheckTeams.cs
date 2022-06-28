using System;
using System.Linq;
using System.Management;
using System.IO;
namespace IronSharp.Utilities
{


    public class CheckTeams
    {
        public static void TeamsInstalled()
        {
            
            string path = @"\\AppData\\Local\\Microsoft\\Teams\\current\";
            if (!Directory.Exists(path))
            {
                Console.WriteLine("Teams is installed. Try dll sideload");
            }
            else
            {
                Console.WriteLine("Teams not found");
            }
        }
        }
        }
