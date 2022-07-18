import bcrypt
import hashlib
import hmac

from base64 import b64encode

BCRYPT_ID     = '2a'
BCRYPT_COST   = 13
BCRYPT_PEPPER = 'hmac_bcrypt'


##
# Generates a new hash from a plaintext password
#
# @param string password    plaintext password
# @param string settings    optional settings string (id + cost + salt)
# @param string pepper      optional pepper string
# @return string            final hashed value
##
def hmac_bcrypt_hash(password: str, settings: str, pepper=BCRYPT_PEPPER) -> str:
    cost = BCRYPT_COST
    salt = ''

    if settings:
        (_, _, cost, salt) = settings.split('$')
        salt = salt[0:22]

    if not cost:
        cost = BCRYPT_COST

    if not salt:
        salt = bcrypt.gensalt(cost)

    settings = f"${BCRYPT_ID}${cost}${salt}"

    pre_hash = b64encode(
        hmac.new(
            bytes(pepper,   encoding='utf-8'),
            bytes(password, encoding='utf-8'),
            hashlib.sha512
        ).digest()
    ).decode()

    mid_hash = bcrypt.hashpw(
        bytes(pre_hash, encoding='utf-8'),
        bytes(settings, encoding='utf-8')
    )

    post_hash = b64encode(
        hmac.new(
            bytes(pepper, encoding='utf-8'),
            mid_hash,
            hashlib.sha512
        ).digest()
    ).decode().replace('=', '')

    return settings + post_hash


##
# Compares password to stored hash value
#
# @param string password    plaintext password
# @param string valid       stored hash value for comparison
# @param string pepper      optional pepper string
# @returns bool
##
def hmac_bcrypt_verify(password: str, expected: str, pepper=BCRYPT_PEPPER) -> bool:
    return hmac.compare_digest(
        hmac_bcrypt_hash(password, expected, pepper),
        expected
    )
