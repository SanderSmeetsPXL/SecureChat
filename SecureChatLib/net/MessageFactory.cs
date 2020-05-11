using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureChatLib.net
{
    /*
     * [PACKAGE_TYPE] : [PACKAGE_CONTENT]
     * ---CLIENT TO SERVER---
     * LOGIN : LOGIN;USERNAME;
     * LOGINACCEPT : LOGINACCEPT;ASSIGNED_ID;
     * LOADUSER : LOADUSER;REMOTE_ID;USERNAME;
     * NEWUSER : NEWUSER;REMOTE_ID;USERNAME;
     * USERLEFT : USERLEFT;REMOTE_ID;
     * PUBLICKEYREQUEST : PUBLICKEYREQUEST;PUBLIC_KEY
     * PUBLICKEYACCEPT : PUBLICKEYACCEPT;PUBLIC_KEY
     * SECURE_PACKAGE : IV;ENCRYPTED_DATA;
     * ---CLIENT TO CLIENT---
     * CHATMESSAGE : CHATMESSAGE;USERNAME;MESSAGE;
     * FILE : FILE;USERNAME;FILE_NAME;RAW_FILE
     * ---FORWARDED BY SERVER---
     * FORWARD : FORWARD;SENDER_ID;RECEIVER_ID;IV;ENCRYPTED_DATA
     * FORWARDKEYREQUEST : FORWARDKEYREQUEST;SENDER_ID;RECEIVER_ID;PUBLIC_KEY
     * FORWARDKEYACCEPT : FORWARDKEYACCEPT;SENDER_ID;RECEIVER_ID;PUBLIC_KEY
    */
    class MessageFactory
    {
        public static string CreateLoginMessage(string username)
        {
            return "LOGIN;" + username + ";";
        }

        public static string CreateLoginAcceptMessage(Guid id)
        {
            return "LOGINACCEPT;" + id.ToString() + ";";
        }

        public static string CreateLoadUserMessage(Guid id, string username)
        {
            return "LOADUSER;" + id.ToString() + ";" + username + ";";
        }

        public static string CreateNewUserMessage(Guid id, string username)
        {
            return "NEWUSER;" + id.ToString() + ";" + username + ";";
        }

        public static string CreateUserLeftMessage(Guid id)
        {
            return "USERLEFT;" + id.ToString() + ";";
        }

        public static string CreateChatMessage(string username, string message)
        {
            return "CHATMESSAGE;"
                + username + ";"
                + message + ";";
        }

        public static string CreateFileMessage(string username, string fileName, byte[] fileBytes)
        {
            return "FILE;"
                + username + ";"
                + fileName + ";"
                + Convert.ToBase64String(fileBytes) + ";";
        }

        public static string CreatePublicKeyRequestMessage(byte[] publicKey)
        {
            return "PUBLICKEYREQUEST;" + Convert.ToBase64String(publicKey) + ";";
        }

        public static string CreatePublicKeyAcceptMessage(byte[] publicKey)
        {
            return "PUBLICKEYACCEPT;" + Convert.ToBase64String(publicKey) + ";";
        }

        public static string CreateForwardMessage(Guid senderId, Guid receiverId, byte[] iv, string signature, byte[] encryptedData)
        {
            return "FORWARD;"
                + senderId.ToString() + ";"
                + receiverId.ToString() + ";"
                + Convert.ToBase64String(iv) + ";"
                + signature + ";"
                + Convert.ToBase64String(encryptedData) + ";";
        }

        public static string CreateSecurePackage(byte[] iv, byte[] encryptedData)
        {
            return Convert.ToBase64String(iv) + ";"
                + Convert.ToBase64String(encryptedData) + ";";
        }

        public static string CreateForwardKeyRequest(Guid senderId, Guid receiverId, byte[] publicKey)
        {
            return "FORWARDPUBLICKEYREQUEST;"
                + senderId.ToString() + ";"
                + receiverId.ToString() + ";"
                + Convert.ToBase64String(publicKey) + ";";
        }

        public static string CreateForwardKeyAccept(Guid senderId, Guid receiverId, byte[] publicKey)
        {
            return "FORWARDPUBLICKEYACCEPT;"
                + senderId.ToString() + ";"
                + receiverId.ToString() + ";"
                + Convert.ToBase64String(publicKey) + ";";
        }
    }
}
