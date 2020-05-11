using SecureChatLib.net;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureChatServer
{
    class Program
    {
        static void Main(string[] args)
        {
            MainAsync().Wait();
        }

        static async Task MainAsync()
        {
            ChatServer chatServer = new ChatServer();
            
            if (!chatServer.StartServer(8564))
            {
                Environment.Exit(1);
            } else
            {
                await chatServer.ListenForClientsAsync();
            }
        }
    }
}
