using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
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
                try
                {
                    ans = ping.Send(args[0], 1000, new byte[32], opt);
                }
                catch
                {
                    WriteLine("Couldn't send ping! Possible problems with access rules or arguments!");
                    Environment.Exit(1);
                    return;
                }

                WriteLine(ans.Status == IPStatus.TimedOut
                    ? $"{opt.Ttl}. *\n"
                    : $"{opt.Ttl}. {ans.Address}\n{ParsePrintingData(WhoisServerRequest(ans.Address.ToString(), "whois.iana.org"))}\n");
                opt.Ttl++;
            } while (ans.Status != IPStatus.Success);
        }

        static string ParsePrintingData(string whois)
        {
            whois = whois.ToUpperInvariant();
            var headers = new[] {"NETNAME", "ORIGIN", "COUNTRY"};
            var values =
                whois
                    .Split("\n", StringSplitOptions.RemoveEmptyEntries)
                    .Where(x =>headers.Any(x.StartsWith))
                    .ToArray();
            
            var parameters = new List<string>();
            foreach (var header in headers)
            {
                var buffer = values.FirstOrDefault(x => x.StartsWith(header));
                if (buffer == null)
                    continue;
                if (header == "ORIGIN")
                {
                    var match = Regex.Match(buffer.Split(":")[1], @"\d+$");
                    if (match.Success) parameters.Add(match.ToString());
                }
                else
                    parameters.Add(buffer.Split(":")[1].Trim());
            }

            return string.Join(", ", parameters);
        }


        static string WhoisServerRequest(string endpoint, string serverAddres, int ip = 43)
        {
            var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
            try
            {
                socket.Connect(serverAddres, ip);
            }
            catch (SocketException)
            {
                WriteLine("Couldn't get socket! Possible problems with access rules!");
                Environment.Exit(1);
            }

            var arinAddition = serverAddres == "whois.arin.net" ? "+ z " : "";
            socket.Send(Encoding.UTF8.GetBytes($"{arinAddition}{endpoint}\r\n"));
            using var reader = new StreamReader(new BufferedStream(new NetworkStream(socket)));
            var result = reader.ReadToEnd();
            socket.Close();

            var refer = result.Split("\n", StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault(x => x.StartsWith("refer"));
            return refer != default
                ? WhoisServerRequest(endpoint, refer.Split(":", StringSplitOptions.RemoveEmptyEntries)[1].Trim())
                : result;
        }
    }
}