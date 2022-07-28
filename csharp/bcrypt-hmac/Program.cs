// See https://aka.ms/new-console-template for more information
using bcrypt_hmac;
using System.Text;

string password = "hello";
string hmacPepper = "jalapeno";
string bcryptSalt = "$2a$13$iCfKmVhHwj1cuZMISQWnMO";
string final = "PnuwTMt3LN1KMhTW8yaujkyEyk5Li3GYSh7Cp9sR7kYYw5CLPqqEf7V+RaPztiivg2uhh8ugNwKpcy3bc0ZnJg==";

HMAC.Salt = Encoding.UTF8.GetBytes(hmacPepper);

Console.WriteLine("BCrypt Salt: " + bcryptSalt);
string prehash = HMAC.GetHash(password);

Console.WriteLine("Prehash: " + prehash);

string midhash = BCrypt.Net.BCrypt.HashPassword(prehash, bcryptSalt);

//Ensure that the midhash contains that salt and workfactor
Console.WriteLine("Midhash: " + midhash);

string phash = HMAC.GetHash(midhash);

Console.WriteLine("Final: " + phash);

if (HMAC.Verify(final, midhash))
    Console.WriteLine("Verified with Time Safety");
else
    Console.WriteLine("Not verified");
