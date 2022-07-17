import bcrypt
import hashlib
import hmac

from .radix64 import Radix64
from base64   import b64encode
from secrets  import token_bytes


BCRYPT_ID     = '2a'
BCRYPT_COST   = 13
BCRYPT_PEPPER = 'hmac_bcrypt'


def hmac_bcrypt_hash(password: str, settings: str, pepper=BCRYPT_PEPPER) -> str:
    cost = BCRYPT_COST
    salt = ''

    if settings:
        (_, _, cost, salt) = settings.split('$')
        salt = salt[0:22]

    if not cost:
        cost = BCRYPT_COST

    if not salt:
        salt = Radix64.encode(
            token_bytes(Radix64.BCRYPT_SALT_BYTES)
        )

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


def hmac_bcrypt_verify(password: str, expected: str, pepper=BCRYPT_PEPPER) -> bool:
    return hmac.compare_digest(
        hmac_bcrypt_hash(password, expected, pepper),
        expected
    )