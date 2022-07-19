import bcrypt from "bcrypt"
import crypto from "crypto"

const BCRYPT_ID     = "a"
const BCRYPT_COST   = 13
const BCRYPT_PEPPER = "hmac_bcrypt"

export function hmac_bcrypt_hash(password, settings, pepper) {
    let cost = BCRYPT_COST
    let salt = ""

    if (settings) {
        [, , cost, salt] = settings.split("$")
    }

    if (!cost) {
        cost = BCRYPT_COST
    }

    if (!salt) {
        settings = bcrypt.genSaltSync(parseInt(cost), BCRYPT_ID)
    } else {
        salt = salt.substr(0, 22)
        settings = `\$2${BCRYPT_ID}\$${cost}\$${salt}`
    }

    if (!pepper) {
        pepper = BCRYPT_PEPPER
    }

    let pre_hash = crypto.createHmac("sha512", pepper)
        .update(password)
        .digest("base64")

    let mid_hash = bcrypt.hashSync(pre_hash, settings)

    let post_hash = crypto.createHmac("sha512", pepper)
        .update(mid_hash)
        .digest("base64")
        .replaceAll("=", "")

    return settings + post_hash
}

export function hmac_bcrypt_verify(password, expected, pepper) {
    try {
        return crypto.timingSafeEqual(
            Buffer.from(
                hmac_bcrypt_hash(password, expected, pepper)
            ),
            Buffer.from(expected)
        )
    } catch {
        return false
    }
}