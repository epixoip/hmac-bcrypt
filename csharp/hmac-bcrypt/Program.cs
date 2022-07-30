using hmac_bcrypt;
using System.Text;

const string password = "test-pass";
const string pepper   = "test-pepper";
const string expected = "$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ";

string test = string.Empty;

test = HMAC_Bcrypt.hmac_bcrypt_hash(password);

if (!System.Text.RegularExpressions.Regex.IsMatch(test, @"^\$2a\$[0-9]{2}\$[.\\/+A-Za-z0-9]{108}$"))
    throw new Exception("Only password test failed");

Console.WriteLine("Verified password-only hashing");


test = HMAC_Bcrypt.hmac_bcrypt_hash(password, "$2a$10$");

if (!System.Text.RegularExpressions.Regex.IsMatch(test, @"^\$2a\$10\$[.\\/+A-Za-z0-9]{108}$"))
    throw new Exception("Password + cost test failed");

Console.WriteLine("Verified password + cost hashing");


test = HMAC_Bcrypt.hmac_bcrypt_hash(password, "$2a$10$v.vnO5oVlX/5zJM9TTXSz.");

if (!System.Text.RegularExpressions.Regex.IsMatch(test, @"^\$2a\$10\$v\.vnO5oVlX/5zJM9TTXSz\.[.\\/+A-Za-z0-9]{86}$"))
    throw new Exception("Password + cost + salt test failed");

Console.WriteLine("Verified password + cost + salt hashing");

if (HMAC_Bcrypt.hmac_bcrypt_verify(password, expected, pepper))
    Console.WriteLine("Verified with Time Safety");
else
    Console.WriteLine("Not verified");