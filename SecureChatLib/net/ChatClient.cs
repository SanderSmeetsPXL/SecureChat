using SecureChatLib.crypto;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;

namespace SecureChatLib.net
{
    public class ChatClient
    {
        public ChatClient()
        {
            diffieHellman = new DiffieHellman();
            commonSecret = new Dictionary<Guid, byte[]>();
            sendQueue = new BlockingCollection<string>();
            onlineUsersIDs = new List<Guid>();
            onlineUsernames = new Dictionary<Guid, string>();
        }

        TcpClient TcpClient { get; set; }
        public string Username { get; set; }
        private DiffieHellman diffieHellman;
        private List<Guid> onlineUsersIDs;
        public Dictionary<Guid, string> onlineUsernames;
        private Dictionary<Guid, byte[]> commonSecret;
        private byte[] commonSecretServer;
        private BlockingCollection<string> sendQueue;
        private Guid id;

        public async Task<bool> ConnectAsync(string host, int port)
        {
            try
            {
                TcpClient = new TcpClient();
                await TcpClient.ConnectAsync(host, port);
                new Task(() => SendData()).Start();
                return true;
            }
            catch (SocketException e)
            {
                Console.WriteLine("Error connecting to server:" + e.Message);
                return false;
            }
        }

        public bool IsConnected()
        {
            return TcpClient.Connected;
        }


        public async Task<string> ReadDataAsync()
        {
            NetworkStream stream = TcpClient.GetStream();
            byte[] bytes = new byte[1024];
            string data = null;
            int i;
            while (true)
            {
                if ((i = await stream.ReadAsync(bytes, 0, bytes.Length)) != 0)
                {
                    data = Encoding.ASCII.GetString(bytes, 0, i);
                    data = HandleDataAsync(data);
                    return data;
                }
            }
        }

        public async Task<byte[]> ReadBytesAsync()
        {
            NetworkStream stream = TcpClient.GetStream();
            byte[] bytes = new byte[8096];
            int i;
            while (true)
            {
                if ((i = await stream.ReadAsync(bytes, 0, bytes.Length)) != 0)
                {
                    return bytes;
                }
            }
        }

        private string HandleDataAsync(string data)
        {
            //TODO
            string[] dataArray = data.Split(';');

            if (dataArray[0] == "PUBLICKEYACCEPT")
            {
                byte[] serverPublicKey = Convert.FromBase64String(dataArray[PackageLocation.PUBLICKEYACCEPT.PUBLIC_KEY]);
                GetCommonSecretServer(serverPublicKey);
                return "---Established secure connection with server.";
            }

            string decryptedPackage = diffieHellman.Decrypt(commonSecretServer, 
                Convert.FromBase64String(dataArray[PackageLocation.SECURE_PACKAGE.ENCRYPTED_DATA]), 
                Convert.FromBase64String(dataArray[PackageLocation.SECURE_PACKAGE.IV]));

            string[] decryptedPackageArray = decryptedPackage.Split(';');
            Guid senderId;
            Guid remoteId;
            string remoteUsername;
            byte[] receiverPublicKey;

            switch (decryptedPackageArray[0])
            {
                case "LOGINACCEPT":
                    id = new Guid(decryptedPackageArray[PackageLocation.LOGINACCEPT.ASSIGNED_ID]);
                    return "---Assigned ID: " + decryptedPackageArray[1];

                case "NEWUSER":
                    remoteId = new Guid(decryptedPackageArray[PackageLocation.NEWUSER.REMOTE_ID]);
                    remoteUsername = decryptedPackageArray[PackageLocation.NEWUSER.USERNAME];
                    AddUser(remoteId, remoteUsername);
                    return "---User " + remoteUsername + " has connected.";

                case "LOADUSER":
                    remoteId = new Guid(decryptedPackageArray[PackageLocation.NEWUSER.REMOTE_ID]);
                    remoteUsername = decryptedPackageArray[PackageLocation.NEWUSER.USERNAME];
                    AddUser(remoteId, remoteUsername);
                    sendPublicKey(remoteId);
                    return "---Loaded user " + remoteUsername;

                case "USERLEFT":
                    remoteId = new Guid(decryptedPackageArray[PackageLocation.NEWUSER.REMOTE_ID]);
                    remoteUsername = onlineUsernames[remoteId];
                    RemoveUser(remoteId);
                    return "---User " + remoteUsername + " left.";

                case "FORWARDPUBLICKEYREQUEST":
                    senderId = new Guid(decryptedPackageArray[PackageLocation.FORWARDPUBLICKEYREQUEST.SENDER_ID]);
                    receiverPublicKey = Convert.FromBase64String(decryptedPackageArray[PackageLocation.FORWARDPUBLICKEYREQUEST.PUBLIC_KEY]);
                    GetCommonSecret(senderId, receiverPublicKey);
                    respondToPublicKey(senderId);
                    return "---Received key from " + senderId.ToString();

                case "FORWARDPUBLICKEYACCEPT":
                    senderId = new Guid(decryptedPackageArray[PackageLocation.FORWARDPUBLICKEYACCEPT.SENDER_ID]);
                    receiverPublicKey = Convert.FromBase64String(decryptedPackageArray[PackageLocation.FORWARDPUBLICKEYACCEPT.PUBLIC_KEY]);
                    GetCommonSecret(senderId, receiverPublicKey);
                    return "---Accepted key from " + senderId.ToString();
                case "FORWARD":
                    senderId = new Guid(decryptedPackageArray[PackageLocation.FORWARD.SENDER_ID]);
                    string signature = decryptedPackageArray[PackageLocation.FORWARD.SIGNATURE];
                    string encryptedData = decryptedPackageArray[PackageLocation.FORWARD.ENCRYPTED_DATA];

                    if (!HMACFactory.CheckSignature(encryptedData, commonSecret[senderId], signature))
                    {
                        return "---NOTE: received message with invalid signature.";
                    }

                    string decryptedData = diffieHellman.Decrypt(commonSecret[senderId], 
                        Convert.FromBase64String(encryptedData), 
                        Convert.FromBase64String(decryptedPackageArray[PackageLocation.FORWARD.IV]));

                    string[] decryptedDataArray = decryptedData.Split(';');
                    switch(decryptedDataArray[0])
                    {
                        case "CHATMESSAGE":
                            return FormatChatMessage(decryptedDataArray);
                        case "FILE":
                            string fileName = decryptedDataArray[PackageLocation.FILE.FILE_NAME];
                            string userName = decryptedDataArray[PackageLocation.FILE.USERNAME];
                            byte[] rawFile = Convert.FromBase64String(decryptedDataArray[PackageLocation.FILE.RAW_FILE]);
                            SaveFile(fileName, rawFile);
                            return "---Received file from " + userName + " and saved as " + fileName;
                    }
                    return "...";
            }
            return "...";
        }

        private async void SendData()
        {
            while (true)
            {
                await Task.Delay(100);
                foreach (string data in sendQueue.GetConsumingEnumerable())
                {
                    try
                    {
                        NetworkStream stream = TcpClient.GetStream();
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
            }
        }

        public void SendLoginCredentials()
        {
            //LOGIN
            string message = MessageFactory.CreateLoginMessage(Username);

            //SECURE_PACKAGE
            string securePackage = CreateSecurePackage(commonSecretServer, message);

            sendQueue.Add(securePackage);
        }

        public void SendChatMessage(string message)
        {
            string chatMessage;
            foreach (Guid remoteId in onlineUsersIDs)
            {
                //CHATMESSAGE
                chatMessage = MessageFactory.CreateChatMessage(Username, message);

                //FORWARD
                string forwardMessage = CreateForwardMessage(remoteId, chatMessage);

                //SECURE_PACKAGE
                string securePackage = CreateSecurePackage(commonSecretServer, forwardMessage);

                sendQueue.Add(securePackage);
            }
            //msg = "CHATMESSAGE;" + Username + ";" + message + ";" + id.ToString() + ";";
            //sendQueue.Enqueue(msg);
        }

        public void SendFileMessage(Guid remoteId, string fileName, byte[] rawFile)
        {
            //FILEMESSAGE
            string fileMessage = MessageFactory.CreateFileMessage(Username, fileName, rawFile);

            //FORWARD
            string forwardMessage = CreateForwardMessage(remoteId, fileMessage);

            //SECURE_PACKAGE
            string securePackage = CreateSecurePackage(commonSecretServer, forwardMessage);

            sendQueue.Add(securePackage);
        }

        public void sendPublicKey(Guid receiverID)
        {
            //FORWARDPUBLICKEYREQUEST
            string message = MessageFactory.CreateForwardKeyRequest(id, receiverID, diffieHellman.publicKey);

            //SECURE_PACKAGE
            string securePackage = CreateSecurePackage(commonSecretServer, message);

            sendQueue.Add(securePackage);
        }

        public void sendPublicKeyServer()
        {
            //PUBLICKEYREQUEST
            string message = MessageFactory.CreatePublicKeyRequestMessage(diffieHellman.publicKey);

            sendQueue.Add(message);
        }

        public void respondToPublicKey(Guid receiverID)
        {
            //FORWARDPUBLICKEYACCEPT
            string message = MessageFactory.CreateForwardKeyAccept(id, receiverID, diffieHellman.publicKey);

            //SECURE_PACKAGE
            string securePackage = CreateSecurePackage(commonSecretServer, message);

            sendQueue.Add(securePackage);
        }

        private string CreateSecurePackage(byte[] commonSecret, string message)
        {
            byte[] iv = diffieHellman.GenerateIV();
            byte[] encryptedMessage = diffieHellman.Encrypt(commonSecret, message, iv);
            return MessageFactory.CreateSecurePackage(iv, encryptedMessage);
        }

        private string CreateForwardMessage(Guid remoteId, string message)
        {
            byte[] iv = diffieHellman.GenerateIV();
            byte[] encryptedChatMessage = diffieHellman.Encrypt(commonSecret[remoteId], message, iv);
            string signature = HMACFactory.CreateSignature(Convert.ToBase64String(encryptedChatMessage), commonSecret[remoteId]);
            return MessageFactory.CreateForwardMessage(id, remoteId, iv, signature, encryptedChatMessage);
        }

        public void GetCommonSecret(Guid receiverID, byte[] receiverPublicKey)
        {
            commonSecret[receiverID] = diffieHellman.CalculateCommonSecret(receiverPublicKey);
        }

        public void GetCommonSecretServer(byte[] serverPublicKey)
        {
            commonSecretServer = diffieHellman.CalculateCommonSecret(serverPublicKey);
        }

        private void AddUser(Guid id, string username)
        {
            onlineUsersIDs.Add(id);
            onlineUsernames.Add(id, username);
        }

        private void RemoveUser(Guid id)
        {
            onlineUsersIDs.Remove(id);
            onlineUsernames.Remove(id);
            commonSecret.Remove(id);
        }

        private void SaveFile(string fileName, byte[] rawFile)
        {
            File.WriteAllBytes(fileName, rawFile);
        }

        private string FormatChatMessage(string[] chatMessageArray)
        {
            return "(" + chatMessageArray[PackageLocation.CHATMESSAGE.USERNAME] + "): " 
                + chatMessageArray[PackageLocation.CHATMESSAGE.MESSAGE];
        }
    }
}
