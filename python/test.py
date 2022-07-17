from hmac_bcrypt import hmac_bcrypt_verify

password = 'test-pass'
pepper   = 'test-pepper'
expected = '$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ'


print(
    hmac_bcrypt_verify(password, expected, pepper)
)
