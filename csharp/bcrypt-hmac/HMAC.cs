using System.Security.Cryptography;
using System.Text;

namespace bcrypt_hmac
{
    static class HMAC
    {

        public static string BCRYPT_ID  = "2a";
        public static int BCRYPT_COST = 13;
        public static string BCRYPT_PEPPER = "hmac_bcrypt";

        public static string hmac_bcrypt_hash(string password, string? settings = null, string? pepper = null)
        {
            if (pepper == null)
                pepper = BCRYPT_PEPPER;

            string[]? sets = null;

            if (!string.IsNullOrEmpty(settings))
                sets = settings.Split('$');
            
            string id;
            string cost;
            string salt;

            if (sets != null && sets.Length > 0)
            {
                
                id = sets[1];
                cost = sets[2];

                if (sets.Length > 3 && !string.IsNullOrEmpty(sets[3]))
                    salt = sets[3][..22];
                else
                    salt = BCrypt.Net.BCrypt.GenerateSalt().Split("$")[3];
            }
            else
            {
                id = BCRYPT_ID;
                cost = BCRYPT_COST.ToString();
                salt = BCrypt.Net.BCrypt.GenerateSalt().Split("$")[3];
            }

            string cryptAmble = "$" + id + "$" + cost + "$" + salt;
            HMACSHA512 hmac = new HMACSHA512(Encoding.UTF8.GetBytes(pepper));
            string prehash = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(password)));
            string midhash = BCrypt.Net.BCrypt.HashPassword(prehash, cryptAmble);

            hmac = new HMACSHA512(Encoding.UTF8.GetBytes(pepper));
            string final = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(midhash))).Replace("=", string.Empty);

            return cryptAmble + final;
        }

        public static bool hmac_bcrypt_verify(string password, string expectedHash, string pepper)
        {
            string tmp = hmac_bcrypt_hash(password, expectedHash, pepper);

            byte[] newHash = Encoding.UTF8.GetBytes(tmp);
            byte[] hash = Encoding.UTF8.GetBytes(expectedHash);

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
