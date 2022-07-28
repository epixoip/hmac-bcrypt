using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace bcrypt_hmac
{
     static class HMAC
    {
        public static byte[]? Salt { get; set; }

        public static string GetHash(string bcryptHash)
        {
            if (Salt == null)
                throw new Exception("Null Salt");

            HMACSHA512 hmac = new HMACSHA512(Salt);
            return Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(bcryptHash)));
        }

        public static bool Verify(string finalHash, string bcryptHash)
        {
            string tmp = GetHash(bcryptHash);

            byte[] newHash = Convert.FromBase64String(tmp);
            byte[] hash = Convert.FromBase64String(finalHash);

            bool eq = false;
            if (newHash.Length == hash.Length)
            {
                int i = 0;
                while ((i < newHash.Length) && (newHash[i] == hash[i]))
                    i += 1;
                
                if (i == newHash.Length)
                    eq = true;
            }

            return eq;
        }
    }
}
