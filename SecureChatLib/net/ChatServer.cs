using SecureChatLib.crypto;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecureChatLib.net
{
    public class ChatServer
    {
        public ChatServer()
        {
            ConnectedClients = new List<TcpClient>();
            diffieHellman = new DiffieHellman();
            commonSecrets = new Dictionary<TcpClient, byte[]>();
            ClientIDs = new Dictionary<TcpClient, Guid>();
            IDClients = new Dictionary<Guid, TcpClient>();
            Usernames = new Dictionary<Guid, string>();
        }

        TcpListener TcpListener { get; set; }
        List<TcpClient> ConnectedClients { get; set; }
        Dictionary<TcpClient, Guid> ClientIDs { get; set; }
        Dictionary<Guid, TcpClient> IDClients { get; set; }
        Dictionary<Guid, string> Usernames;
        DiffieHellman diffieHellman;
        Dictionary<TcpClient, byte[]> commonSecrets;

        public bool StartServer(int port)
        {
            try
            {
                Console.WriteLine("Starting server at port " + port + "...");
                TcpListener = new TcpListener(IPAddress.Any, port);
                TcpListener.Start();
            }
            catch (SocketException e)
            {
                Console.WriteLine("Error starting server: " + e.Message);
                return false;
            }
            Console.WriteLine("Server succesfully started.");
            return true;
        }

        public void StopServer()
        {
            TcpListener.Stop();
        }

        public async Task ListenForClientsAsync()
        {
            while (true)
            {
                TcpClient client = await TcpListener.AcceptTcpClientAsync();
                Console.WriteLine("Accepted connection from client " + client.Client.LocalEndPoint);
                ConnectedClients.Add(client);
                Guid id = Guid.NewGuid();
                ClientIDs.Add(client, id);
                IDClients.Add(id, client);
                new Task(async () => await HandleClientAsync(client)).Start();
            }
        }

        private async Task HandleClientAsync(TcpClient client)
        {
            //TODO
            while(client.Connected)
            {
                string data = await ReadData(client);
                if (data != null)
                {
                    HandleData(data, client);
                }
            }
            await NotifyClientsOfUserLeft(client);
            ConnectedClients.Remove(client);
            ClientIDs.Remove(client);
        }

        private async Task<string> ReadData(TcpClient client)
        {
            byte[] bytes = new byte[1024];
            string data = null;
            int i;
            while (true)
            {
                try
                {
                    if ((i = await client.GetStream().ReadAsync(bytes, 0, bytes.Length)) != 0)
                    {
                        data = Encoding.ASCII.GetString(bytes, 0, i);
                        Console.WriteLine("RECEIVED: " + data);
                        return data;
                    }
                }
                catch (System.IO.IOException e)
                {
                    Console.WriteLine("CLIENT HAS ABRUPTLY DISCONNECTED");
                    return null;
                }
            }
        }

        private async void HandleData(string data, TcpClient client)
        {
            string[] dataArray = data.Split(';');
            Guid receiverId;
            if (dataArray[0] == "PUBLICKEYREQUEST")
            {
                GetCommonSecret(client, Convert.FromBase64String(dataArray[PackageLocation.PUBLICKEYREQUEST.PUBLIC_KEY]));
                await SendData(MessageFactory.CreatePublicKeyAcceptMessage(diffieHellman.publicKey), client);
            }
            else
            {
                string decryptedMessage = diffieHellman.Decrypt(commonSecrets[client],
                    Convert.FromBase64String(dataArray[PackageLocation.SECURE_PACKAGE.ENCRYPTED_DATA]),
                    Convert.FromBase64String(dataArray[PackageLocation.SECURE_PACKAGE.IV]));
                string[] decryptedMessageArray = decryptedMessage.Split(';');
                switch (decryptedMessageArray[0])
                {
                    case "LOGIN":
                        string username = decryptedMessageArray[PackageLocation.LOGIN.USERNAME];
                        Usernames.Add(ClientIDs[client], username);
                        await AcceptLogin(client);
                        await SendOtherClientsIDs(client);
                        await NotifyClientsOfNewUser(client);
                        break;
                    case "FORWARDPUBLICKEYREQUEST":
                    case "FORWARDPUBLICKEYACCEPT":
                    case "FORWARD":
                        receiverId = new Guid(decryptedMessageArray[PackageLocation.FORWARD.RECEIVER_ID]);
                        forwardMessage(decryptedMessage, receiverId);
                        break;
                }
            }
        }

        private async Task SendData(string data, TcpClient client)
        {
            try
            {
                NetworkStream stream = client.GetStream();
                if (stream.CanWrite)
                {
                    byte[] dataByteArray = Encoding.ASCII.GetBytes(data);
                    await stream.WriteAsync(dataByteArray, 0, dataByteArray.Length);
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("Error sending message: " + e.Message);
            }
        }

        private async Task SendData(byte[] dataByteArray, TcpClient client)
        {
            try
            {
                NetworkStream stream = client.GetStream();
                if (stream.CanWrite)
                {
                    await stream.WriteAsync(dataByteArray, 0, dataByteArray.Length);
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("Error sending message: " + e.Message);
            }
        }

        private async Task AcceptLogin(TcpClient client)
        {
            string message = MessageFactory.CreateLoginAcceptMessage(ClientIDs[client]);

            string securePackage = CreateSecurePackage(commonSecrets[client], message);

            await SendData(securePackage, client);
        }

        private async Task SendOtherClientsIDs(TcpClient client)
        {
            foreach (TcpClient c in ConnectedClients)
            {
                if (c == client) continue;

                string message = MessageFactory.CreateLoadUserMessage(ClientIDs[c], Usernames[ClientIDs[c]]);

                string securePackage = CreateSecurePackage(commonSecrets[client], message);

                await SendData(securePackage, client);
            }
        }

        private async Task NotifyClientsOfNewUser(TcpClient client)
        {
            foreach (TcpClient c in ConnectedClients)
            {
                if (c == client) continue;

                string message = MessageFactory.CreateNewUserMessage(ClientIDs[client], Usernames[ClientIDs[client]]);

                string securePackage = CreateSecurePackage(commonSecrets[c], message);

                await SendData(securePackage, c);
            }
        }

        private async Task NotifyClientsOfUserLeft(TcpClient client)
        {
            foreach (TcpClient c in ConnectedClients)
            {
                if (c == client) continue;

                string message = MessageFactory.CreateUserLeftMessage(ClientIDs[client]);

                string securePackage = CreateSecurePackage(commonSecrets[c], message);

                await SendData(securePackage, c);
            }
        }

        private async void respondToPublicKey(TcpClient client)
        {
            string message = MessageFactory.CreatePublicKeyAcceptMessage(diffieHellman.publicKey);
            await SendData(message, client);
        }

        private async void forwardMessage(string message, Guid receiverId)
        {
            TcpClient receiverClient = IDClients[receiverId];
            string securePackage = CreateSecurePackage(commonSecrets[receiverClient], message);

            await SendData(securePackage, IDClients[receiverId]);
        }

        private void GetCommonSecret(TcpClient client, byte[] clientPublicKey)
        {
            commonSecrets[client] = diffieHellman.CalculateCommonSecret(clientPublicKey);
        }

        private string CreateSecurePackage(byte[] commonSecret, string message)
        {
            byte[] iv = diffieHellman.GenerateIV();
            byte[] encryptedMessage = diffieHellman.Encrypt(commonSecret, message, iv);
            return MessageFactory.CreateSecurePackage(iv, encryptedMessage);
        }
    }
}
