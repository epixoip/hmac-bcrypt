package HMAC_Bcrypt

import java.util.*

const val HMAC_SHA512       = "HmacSHA512"
const val BCRYPT_COST       = 13
const val BCRYPT_SALT_BYTES = 16
const val BCRYPT_PEPPER     = "hmac_bcrypt"

/**
 * Generates a new hash from a plaintext password
 *
 * @param password  string containing plaintext password
 * @param settings  string containing settings string or null
 * @param pepper    string containing pepper string or null
 * @returns         hashed password
 */
expect fun hmac_bcrypt_hash(
    password : String,
    settings : String? = null,
    pepper   : String? = BCRYPT_PEPPER
) : String

/**
 * Compares password to stored hash value
 *
 * @param password   string containing plaintext password
 * @param valid      string containing stored hash value
 * @param pepper     scalar containing pepper string or undef
 * @returns          boolean
 */
expect fun hmac_bcrypt_verify(
    password : String,
    valid    : String,
    pepper   : String? = BCRYPT_PEPPER
) : Boolean

/**
 * Encodes a byte array as base64
 */
fun ByteArray.toBase64() =
    String(
        Base64.getEncoder()
            .withoutPadding()
            .encode(this)
    )

/**
 * Constant-time string comparison
 */
fun String.isEqual(other: String) : Boolean {
    if (this.length != other.length) {
        return false
    }

    var result = 0

    this.toCharArray()
        .zip(other.toCharArray())
        .forEach { both ->
            result = result or (
                 both.component1().code
                     xor
                 both.component2().code
            )
        }

    return result == 0
}
