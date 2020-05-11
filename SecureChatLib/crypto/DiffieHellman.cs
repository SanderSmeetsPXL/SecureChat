using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace SecureChatLib.crypto
{
    //Implementation of the Diffie-Hellman key exchange
    class DiffieHellman
    {
        ECDiffieHellmanCng diffieHellman;
        public byte[] publicKey;

        public DiffieHellman()
        {
            
            diffieHellman = new ECDiffieHellmanCng
            {
                KeyDerivationFunction = ECDiffieHellmanKeyDerivationFunction.Hash,
                HashAlgorithm = CngAlgorithm.Sha256
            };
            publicKey = diffieHellman.PublicKey.ToByteArray();
        }

        public byte[] CalculateCommonSecret(byte[] publicKey)
        {
            CngKey key = CngKey.Import(publicKey, CngKeyBlobFormat.EccPublicBlob);
            byte[] derivedKey = diffieHellman.DeriveKeyMaterial(key);
            return derivedKey;
        }

        public byte[] GenerateIV()
        {
            Aes aes = new AesCryptoServiceProvider();
            aes.GenerateIV();
            return aes.IV;
        }

        public byte[] Encrypt(byte[] derivedKey, string message, byte[] iv)
        {
            Aes aes = new AesCryptoServiceProvider();
            byte[] encryptedMessage;

            aes.Key = derivedKey; //Use common secret for symmetric encryption
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;

            using (MemoryStream cipherText = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(cipherText, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                byte[] plaintextBytes = Encoding.ASCII.GetBytes(message);
                cs.Write(plaintextBytes, 0, plaintextBytes.Length);
                cs.FlushFinalBlock();
                cs.Close();
                encryptedMessage = cipherText.ToArray();
            }

            return encryptedMessage;
        }

        public string Decrypt(byte[] derivedKey, byte[] encryptedMessage, byte[] iv)
        {
            Aes aes = new AesCryptoServiceProvider();
            string decryptedMessage;

            aes.Key = derivedKey;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;

            using (MemoryStream plainText = new MemoryStream())
            using (CryptoStream cs = new CryptoStream(plainText, aes.CreateDecryptor(), CryptoStreamMode.Write))
            {
                cs.Write(encryptedMessage, 0, encryptedMessage.Length);
                cs.Close();
                decryptedMessage = Encoding.ASCII.GetString(plainText.ToArray());
            }

            return decryptedMessage;
        }
    }
}
