use Test;

BEGIN {
    push @INC, '../lib';
    plan tests => 1
}

use HMAC_Bcrypt;

my $pass     = 'test-pass';
my $pepper   = 'test-pepper';
my $expected = '$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ';

ok(hmac_bcrypt_verify($pass, $expected, $pepper), 1);
