import assert from "assert"
import { hmac_bcrypt_hash, hmac_bcrypt_verify } from "../libs/hmac_bcrypt.js"

describe('hmac-bcrypt', function () {
    describe('supply password only', function () {
        it('should generate salt, use default cost and default pepper', function () {
            let hash = hmac_bcrypt_hash('test-pass')
            assert.match(hash,  /^\$2a\$[0-9]{2}\$[.\/+A-Za-z0-9]{108}$/)
        });
    });

    describe('supply password and cost only', function () {
        it('should generate salt, use supplied cost and default pepper', function () {
            let hash = hmac_bcrypt_hash('test-pass', '$2a$10$')
            assert.match(hash,  /^\$2a\$10\$[.\/+A-Za-z0-9]{108}$/)
        });
    });

    describe('supply password and cost + salt', function () {
        it('should use supplied cost and salt, with default pepper', function () {
            let hash = hmac_bcrypt_hash('test-pass', '$2a$10$v.vnO5oVlX/5zJM9TTXSz.')
            assert.match(hash,  /^\$2a\$10\$v\.vnO5oVlX\/5zJM9TTXSz\.[.\/+A-Za-z0-9]{86}$/)
        });
    });

    describe('supply password and cost + salt + pepper', function () {
        it('should use supplied cost, salt, and pepper', function () {
            let expected = '$2a$13$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ'
            let ret = hmac_bcrypt_verify('test-pass', expected, 'test-pepper')
            assert.strictEqual(ret,  true)
        });
    });
});
