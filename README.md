# hmac-bcrypt

This repository contains reference implementations of the `hmac-bcrypt` password hashing function in several languages. Each reference implementation attempts to be a 1:1 port of the original C and Perl implementations created by [@epixoip]( https://github.com/epixoip ) where possible, and are fully compatible with each other (i.e., they produce and validate the same hash values.)

## Interfaces

Each reference implementation defines two procedural functions with the following pseudo-prototypes:

`string hmac_bcrypt_hash(password, settings?, pepper?)`
`boolean hmac_bcrypt_verify(password, expected, pepper?)`

Please refer to the test cases provided with each reference implementation for how to integrate and use these functions. 

The `settings` parameter in this context refers to a standard bcrypt settings string containing the hash identifier (`2a`), the log2 cost (e.g., `13`), and optional 22-byte, radix64-encoded salt value (e.g., `LhayLxezLhK1LhWvKxCyLO`). These values are concatenated together in a dollar-delimited string; e.g., `$2a$13$LhayLxezLhK1LhWvKxCyLO`.

The `settings` parameter is optional; it may be null/empty (using default cost of `13` and generated salt), or you wish to specify a manual cost value along with a generated salt by supplying only the id + cost value (e.g., `$2a$10$`). It is *not* recommended to create and supply your own salt values.

The `pepper` parameter defines a global shared secret and is likewise optional; if it is null/blank, the default value of `hmac_bcrypt` is used. 

## Algorithm details

The `hmac-bcrypt` password hashing function employs bcrypt with proper pre-hashing and post-hashing, combined with an optional pepper. In pseduo code, this is fairly straight-forward:

```
pre_hash  = hmac_sha512_base64(password, pepper)
mid_hash  = bcrypt(pre_hash, settings)
post_hash = hmac_sha512_base64(mid_hash, pepper)

return settings + post_hash
```

Pre-hashing is employed to enable input lengths greater than bcrypt's maximum of 72 input bytes. SHA-512 was selected due to its 64-bit word size, which is friendly to CPU defenders but hinders GPU attackers. However, a raw SHA-512 value cannot be used for several reasons:

1. Raw, unsatled hash values input into bcrypt can enable [shucking attacks]( https://superuser.com/questions/1561434/how-do-i-crack-a-double-encrypted-hash/1561612#1561612 ).
2. Some bcrypt implementations treat input as a null-terminated cstring, resulting in truncated input for hash values containing null bytes. 

To mitigate shucking attacks, the pre-hash has to be salted -- or in this case, peppered -- and HMAC provides a convenient vehicle for keying a hash. The resulting HMAC value is then encoded with base64 to mitigate null byte issues. 

Post-hashing is employed largely to differentiate hmac-bcrypt hashes from bcrypt hashes -- i.e., the lengths will differ -- but also to add an extra layer of protection due to the pepper. The post-hashing step could even be performed with the pepper value stored in an HSM (highly recommended!) for further protection. 

## Justification

TBD.
