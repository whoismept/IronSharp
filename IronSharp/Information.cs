using System;

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

        Read-only Windows hardening advisor (nothing is modified)

            Mert Daş     @merterpreter
            Mert Umut    @whoismept

";
            Console.WriteLine(bannerText);
        }
    }
}
