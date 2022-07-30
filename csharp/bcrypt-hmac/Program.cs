// See https://aka.ms/new-console-template for more information
using bcrypt_hmac;
using System.Text;

string password = "test-pass";
string hmacPepper = "test-pepper";
string final = "$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ";


if (HMAC.hmac_bcrypt_verify(password, final, hmacPepper))
    Console.WriteLine("Verified with Time Safety");
else
    Console.WriteLine("Not verified");
