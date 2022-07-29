using HMAC_Bcrypt;
using System.Text;

string password = "test-pass";
string pepper   = "test-pepper";
string expected = "$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ";

string hash = HMAC_Bcrypt.hmac_bcrypt_hash(password, expected, pepper);
Console.WriteLine(hash);


bool valid = HMAC_Bcrypt.bcrypt_hmac_verify(password, expected, pepper);
Console.WriteLine(valid);
