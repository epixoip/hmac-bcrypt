@file:JvmName("HMAC_Bcrypt")
package HMAC_Bcrypt

import HMAC_Bcrypt.Radix64.radix64_decode
import at.favre.lib.crypto.bcrypt.BCrypt
import at.favre.lib.crypto.bcrypt.LongPasswordStrategies
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

actual fun hmac_bcrypt_hash(password: String, settings: String?, pepper: String?) : String {
    var cost = BCRYPT_COST
    var salt : ByteArray? = null

    if (settings != null) {
        val expandSettings = settings.split('$')

        if (expandSettings.size > 1) {
            cost = expandSettings[2].toInt()
        }

        if (expandSettings.size > 2) {
            salt = radix64_decode(
                expandSettings[3].substring(0..21),
                BCRYPT_SALT_BYTES
            )
        }
    }

    val preHash = Mac.getInstance(HMAC_SHA512).let { hmac ->
        hmac.init(
            SecretKeySpec(pepper?.toByteArray(), hmac.algorithm)
        )

        hmac.doFinal(password.toByteArray())
            .toBase64()
            .toByteArray()
    }

    val midHash = BCrypt.with(
        LongPasswordStrategies.truncate(
            BCrypt.Version.VERSION_2Y_NO_NULL_TERMINATOR
        )
    ).let { bcrypt ->
        if (salt == null) {
            bcrypt.hash(cost, preHash)
        } else {
            bcrypt.hash(cost, salt, preHash)
        }
    }

    val postHash = Mac.getInstance(HMAC_SHA512).let { hmac ->
        hmac.init(
            SecretKeySpec(pepper?.toByteArray(), hmac.algorithm)
        )

        hmac.doFinal(midHash)
            .toBase64()
    }

    val strSalt =
        String(midHash)
            .substringBeforeLast('$') +
        '$' +
        String(midHash)
            .substringAfterLast('$')
            .substring(0, 22)

    return "${strSalt}${postHash}"
}

actual fun hmac_bcrypt_verify(password: String, valid: String, pepper: String?) : Boolean {
    return hmac_bcrypt_hash(password, valid, pepper).isEqual(valid)
}
