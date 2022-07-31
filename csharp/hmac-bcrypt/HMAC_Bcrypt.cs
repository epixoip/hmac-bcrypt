using System.Security.Cryptography;
using System.Text;

namespace hmac_bcrypt
{
    static class HMAC_Bcrypt
    {
        private const int    BCRYPT_COST   = 13;
        private const string BCRYPT_PEPPER = "hmac_bcrypt";

        public static string hmac_bcrypt_hash(string password, string? settings = null, string? pepper = null)
        {
            int cost = BCRYPT_COST;
            string? salt = null;

            if (!string.IsNullOrEmpty(settings)) {
                string[] sets = settings.Split('$');

                cost = Int16.Parse(sets[2]);

                if (sets.Length > 3 && !string.IsNullOrEmpty(sets[3])) {
                    salt = sets[3];
                }
            }

            if (string.IsNullOrEmpty(salt)) {
                settings = BCrypt.Net.BCrypt.GenerateSalt(cost);
            } else if (settings != null) {
                settings = settings[..29];
            }

            if (string.IsNullOrEmpty(pepper)) {
                pepper = BCRYPT_PEPPER;
            }

            HMACSHA512 hmac = new HMACSHA512(
                Encoding.UTF8.GetBytes(pepper)
            );

            string pre_hash = Convert.ToBase64String(
                hmac.ComputeHash(
                    Encoding.UTF8.GetBytes(password)
                )
            );

            string mid_hash = BCrypt.Net.BCrypt.HashPassword(pre_hash, settings);

            string post_hash = Convert.ToBase64String(
                hmac.ComputeHash(
                    Encoding.UTF8.GetBytes(mid_hash)
                )
            ).Replace("=", string.Empty);

            return settings + post_hash;
        }

        public static bool hmac_bcrypt_verify(string password, string valid, string? pepper = null)
        {
            if (string.IsNullOrEmpty(pepper)) {
                pepper = BCRYPT_PEPPER;
            }

            byte[] a = Encoding.UTF8.GetBytes(
                hmac_bcrypt_hash(password, valid, pepper)
            );

            byte[] b = Encoding.UTF8.GetBytes(valid);

            uint diff = (uint) a.Length ^ (uint) b.Length;

            for (int i = 0; i < a.Length && i < b.Length; i++) {
                diff |= (uint)(a[i] ^ b[i]);
            }

            return diff == 0;
        }
    }
}
