using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureChatLib.crypto
{
    public static class HMACFactory
    {
        public static string CreateSignature(string message, byte[] commonSecret)
        {
            Console.WriteLine(message);
            byte[] messageBytes = Encoding.ASCII.GetBytes(message);
            using (HMACSHA256 hmacscha256 = new HMACSHA256(commonSecret))
            {
                byte[] signature = hmacscha256.ComputeHash(messageBytes);
                return Convert.ToBase64String(signature);
            }
        }

        public static bool CheckSignature(string message, byte[] commonSecret, string signature)
        {
            string messageSignature = CreateSignature(message, commonSecret);
            return messageSignature.Equals(signature);
        }
    }
}
