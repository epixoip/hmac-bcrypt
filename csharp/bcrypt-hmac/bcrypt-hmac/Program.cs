// See https://aka.ms/new-console-template for more information
using bcrypt_hmac;
using System.Text;

string password = "test-pass";
string hmacPepper = "test-pepper";
string bcryptSalt = "$2a$13$v.vnO5oVlX/5zJM9TTXSz.";
string final = "JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ==";

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
