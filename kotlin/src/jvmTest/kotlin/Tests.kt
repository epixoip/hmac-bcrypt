import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertTrue

class HmacBcryptTests {
    val pass     = "test-pass"
    val pepper   = "test-pepper"
    val expected = "\$2a\$13\$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ"

    @Test
    fun `supply password only`() {
        val regex = Regex("""^\$2a\$[0-9]{2}\$[.\\/+A-Za-z0-9]{108}$""")
        assertTrue(regex matches hmac_bcrypt_hash(pass))
    }

    @Test
    fun `supply password and cost only`() {
        val regex = Regex("""^\$2a\$10\$[.\\/+A-Za-z0-9]{108}$""")
        assertTrue(regex matches hmac_bcrypt_hash(pass, "$2a$10$"))
    }

    @Test
    fun `supply password and cost + salt`() {
        assertContains(
            hmac_bcrypt_hash(pass, "\$2a\$10\$v.vnO5oVlX/5zJM9TTXSz."),
            "\$2a\$10\$v.vnO5oVlX/5zJM9TTXSz."

        )
    }

    @Test
    fun `supply password and cost + salt + pepper`() {
        assertTrue(hmac_bcrypt_verify(pass, expected, pepper))
    }
}
