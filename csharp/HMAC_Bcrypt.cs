namespace HMAC_Bcrypt
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;
    using BCrypt.Net;

    const string BCRYPT_PEPPER = "hmac_bcrypt";
    const int    BCRYPT_COST   = 13;

    string hmac_bcrypt_hash(string password, string? settings = null, string? pepper = BCRYPT_PEPPER) {
        int cost = BCRYPT_COST;
        string? salt = null;

        if (settings) {
            string[] parts = settings.Split('$');

            if (parts.Length > 2) {
                cost = Int16.Parse(parts[2]);
            }

            if (parts.Length > 3) {
                salt = parts[3];
            }
        }

        if (!salt) {
            settings = BCrypt.Net.BCrypt.GenerateSalt(cost);
        } else {
            settings = settings.Substring(0, 29);
        }

        HMACSHA512 hmac = new HMACSHA512(
            Encoding.UTF8.GetBytes(pepper)
        );

        string pre_hash = Convert.ToBase64String(
            hmac.ComputeHash(
                Encoding.UTF8.GetBytes(password)
            )
        );

        string mid_hash = BCrypt.Net.BCrypt.HashPassword(pre_hash, salt);

        hmac.Clear();

        string post_hash = Convert.ToBase64String(
            hmac.ComputeHash(
                Encoding.UTF8.GetBytes(mid_hash)
            )
        ).Replace("=", "");

        return settings + post_hash;
    }

    bool bcrypt_hmac_verify(string password, string valid, string? pepper = BCRYPT_PEPPER) {
        byte[] a = Convert.FromBase64String(
            hmac_bcrypt_hash(password, valid, pepper)
        );

        byte[] b = Convert.FromBase64String(valid);

        uint diff = (uint) a.Length ^ (uint) b.Length;

        for (int i = 0; i < a.Length && i < b.Length; i++) {
            diff |= (uint)(a[i] ^ b[i]);
        }

        return diff == 0;
    }
}
