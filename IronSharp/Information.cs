﻿using System;

namespace IronSharp
{
    internal class Information
    {
        public static void Banner()
        {
            var bannerText = @"
██╗██████╗  ██████╗ ███╗   ██╗███████╗██╗  ██╗ █████╗ ██████╗ ██████╗ 
██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝██║  ██║██╔══██╗██╔══██╗██╔══██╗
██║██████╔╝██║   ██║██╔██╗ ██║███████╗███████║███████║██████╔╝██████╔╝
██║██╔══██╗██║   ██║██║╚██╗██║╚════██║██╔══██║██╔══██║██╔══██╗██╔═══╝ 
██║██║  ██║╚██████╔╝██║ ╚████║███████║██║  ██║██║  ██║██║  ██║██║     
╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     

            Mert Daş     @merterpreter
            Mert Umut    @whoismept


";
            Console.WriteLine(bannerText);
        }
    }
}