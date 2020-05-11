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
    static class PackageLocation
    {
        public static class LOGIN
        {
            public const int USERNAME = 1;
        }

        public static class LOGINACCEPT
        {
            public const int ASSIGNED_ID = 1;
        }

        public static class LOADUSER
        {
            public const int REMOTE_ID = 1;
            public const int USERNAME = 2;
        }

        public static class NEWUSER
        {
            public const int REMOTE_ID = 1;
            public const int USERNAME = 2;
        }

        public static class USERLEFT
        {
            public const int REMOTE_ID = 1;
        }

        public static class CHATMESSAGE
        {
            public const int USERNAME = 1;
            public const int MESSAGE = 2;
        }

        public static class FILE
        {
            public const int USERNAME = 1;
            public const int FILE_NAME = 2;
            public const int RAW_FILE = 3;
        }

        public static class PUBLICKEYREQUEST
        {
            public const int PUBLIC_KEY = 1;
        }

        public static class PUBLICKEYACCEPT
        {
            public const int PUBLIC_KEY = 1;
        }

        public static class FORWARD
        {
            public const int SENDER_ID = 1;
            public const int RECEIVER_ID = 2;
            public const int IV = 3;
            public const int SIGNATURE = 4;
            public const int ENCRYPTED_DATA = 5;
        }

        public static class SECURE_PACKAGE
        {
            public const int IV = 0;
            public const int ENCRYPTED_DATA = 1;
        }

        public static class FORWARDPUBLICKEYREQUEST
        {
            public const int SENDER_ID = 1;
            public const int RECEIVER_ID = 2;
            public const int PUBLIC_KEY = 3;
        }

        public static class FORWARDPUBLICKEYACCEPT
        {
            public const int SENDER_ID = 1;
            public const int RECEIVER_ID = 2;
            public const int PUBLIC_KEY = 3;
        }
    }
}
