from hmac_bcrypt import hmac_bcrypt_hash, hmac_bcrypt_verify
import unittest


class TestHmacBcrypt(unittest.TestCase):
    def test_password_cost_only(self):
        output = hmac_bcrypt_hash('test-pass', '$2a$10$')
        self.assertRegex(output, r'^\$2a\$10\$[.\/+A-Za-z0-9]{108}$')

    def test_password_salt_cost(self):
        output = hmac_bcrypt_hash('test-pass', '$2a$10$v.vnO5oVlX/5zJM9TTXSz.')
        self.assertRegex(output, r'^\$2a\$10\$v\.vnO5oVlX\/5zJM9TTXSz\.[.\/+A-Za-z0-9]{86}$')

    def test_password_salt_cost_pepper(self):
        expected = '$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ'
        output = hmac_bcrypt_verify('test-pass', expected, 'test-pepper')
        self.assertEqual(output, True)


if __name__ == '__main__':
    unittest.main()
