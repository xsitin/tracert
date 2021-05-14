using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
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
                    : $"{opt.Ttl}. {ans.Address}\n{ParseNetNameASCountry(WhoisServerRequest(ans.Address.ToString(), "whois.iana.org"))}\n");
                opt.Ttl++;
            } while (ans.Status != IPStatus.Success);
        }

        static string ParseNetNameASCountry(string whois)
        {
            whois = whois.ToUpperInvariant();
            var values =
                whois.Split("\n", StringSplitOptions.RemoveEmptyEntries).Where(x =>
                        x.StartsWith("COUNTRY") || x.StartsWith($"NETNAME") || x.StartsWith("ORIGIN"))
                    .Select(x => x.Split(":")[1].Trim()).ToArray();
            return string.Join(", ", values);
        }


        static string WhoisServerRequest(string endpoint, string serverAddres, int ip = 43)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            socket.Connect(serverAddres, ip);
            var arinAddition = serverAddres == "whois.arin.net" ? "+ z " : "";
            socket.Send(Encoding.UTF8.GetBytes($"{arinAddition}{endpoint}\r\n"));
            var buffer = new byte[4096];
            var counter = 4096;
            var result = "";
            while (counter > 0)
            {
                counter = socket.Receive(buffer);
                result += Encoding.UTF8.GetString(buffer[..counter]);
            }

            var refer = result.Split("\n", StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault(x => x.StartsWith("refer"));
            return refer != default
                ? WhoisServerRequest(endpoint, refer.Split(":", StringSplitOptions.RemoveEmptyEntries)[1].Trim())
                : result;
        }
    }
}