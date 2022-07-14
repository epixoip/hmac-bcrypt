package HMAC_Bcrypt

object Main {
    @JvmStatic
    fun main(args: Array<String>) {
        val pass     = "test-pass"
        val pepper   = "test-pepper"
        val expected = "\$2a\$13\$v.vnO5oVlX/5zJM9TTXSz.JMdh9WwErhl6x9XMOEBs5x1R1FxuPC29TMJSMeAEnUlkEgbZw6r0FFZ9jFN07eykXAMgNZH3WrZSqxQkj4qKEQ"

        println(hmac_bcrypt_verify(pass, expected, pepper))
    }
}
