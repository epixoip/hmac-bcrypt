@file:JvmName("Common")

const val HMAC_SHA512       = "HmacSHA512"
const val BCRYPT_COST       = 13
const val BCRYPT_SALT_BYTES = 16
const val BCRYPT_PEPPER     = "hmac_bcrypt"

/**
 * Generates a new hash from a plaintext password
 *
 * @param password  string containing plaintext password
 * @param settings  optional settings string (id + cost + salt)
 * @param pepper    optional pepper string
 * @returns         final hashed value
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
 * @param pepper     optional pepper string
 * @returns          boolean
 */
expect fun hmac_bcrypt_verify(
    password : String,
    valid    : String,
    pepper   : String? = BCRYPT_PEPPER
) : Boolean

/**
 * Encodes a bytearray as base64
 */
fun ByteArray.toBase64(): String {
    val itoa64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toByteArray()
    val length = (size + 2) / 3 * 4

    val end = size - size % 3
    var idx = 0
    var i   = 0

    val out = when (size - end) {
        1 -> ByteArray(length - 2)
        2 -> ByteArray(length - 1)
        else -> ByteArray(length)
    }

    while (i < end) {
        val b0 = this[i++].toInt()
        val b1 = this[i++].toInt()
        val b2 = this[i++].toInt()
        out[idx++] = itoa64[(b0 and 0xff shr 2)]
        out[idx++] = itoa64[(b0 and 0x03 shl 4) or (b1 and 0xff shr 4)]
        out[idx++] = itoa64[(b1 and 0x0f shl 2) or (b2 and 0xff shr 6)]
        out[idx++] = itoa64[(b2 and 0x3f)]
    }

    when (size - end) {
        1 -> {
            val b0 = this[i].toInt()
            out[idx++] = itoa64[b0 and 0xff shr 2]
            out[idx]   = itoa64[b0 and 0x03 shl 4]
        }
        2 -> {
            val b0 = this[i++].toInt()
            val b1 = this[i].toInt()
            out[idx++] = itoa64[(b0 and 0xff shr 2)]
            out[idx++] = itoa64[(b0 and 0x03 shl 4) or (b1 and 0xff shr 4)]
            out[idx]   = itoa64[(b1 and 0x0f shl 2)]
        }
    }

    return String(out)
}

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
