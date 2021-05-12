using System;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using static System.Console;

namespace tracert
{
    class Program
    {
        public static void Main(string[] args)
        {
            var ping = new Ping();
            var opt = new PingOptions(1, true);
            PingReply ans;
            do
            {
                ans = ping.Send(new IPAddress(new byte[] {8, 8, 8, 8}), 1000, Array.Empty<byte>(), opt);
                WriteLine(ans.Status == IPStatus.TimedOut
                    ? $"{opt.Ttl}. *\n"
                    : $"{opt.Ttl}. {ans.Address}\n{ParseNetNameASCountry(GetWhois(ans.Address.MapToIPv4().ToString()))}\n");
                opt.Ttl++;
            } while (ans.Status != IPStatus.Success);
        }

        static string ParseNetNameASCountry(string whois)
        {
            var values =
                whois.Split("\n", StringSplitOptions.RemoveEmptyEntries).Where(x =>
                        x.StartsWith("country") || x.StartsWith("netname") || x.StartsWith("origin"))
                    .Select(x => x.Split(":")[1].Trim()).ToArray();
            return string.Join(", ", values);
        }

        static string GetWhois(string ip)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect("whois.ripe.net", 43);
            socket.Send(Encoding.UTF8.GetBytes(ip + "\r\n"));
            var buffer = new byte[4096];
            var counter = 4096;
            var result = "";
            while (counter > 0)
            {
                counter = socket.Receive(buffer);
                result += Encoding.UTF8.GetString(buffer);
            }

            return result;
        }
    }
}