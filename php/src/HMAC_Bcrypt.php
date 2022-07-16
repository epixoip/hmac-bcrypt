<?php

include "Radix64.php";

const BCRYPT_ID         = '2a';
const BCRYPT_COST       = 13;
const BCRYPT_SALT_BYTES = 16;
const BCRYPT_PEPPER     = 'hmac_bcrypt';
const HMAC_SHA512       = "SHA512";

/**
 * Generates a new hash from a plaintext password
 *
 * @param string $password plaintext password
 * @param string $settings optional settings string (id + cost + salt)
 * @param string $pepper   optional pepper string
 * @return string          final hashed value
 * @throws Exception
 */
function hmac_bcrypt_hash(string $password, string $settings = null, string $pepper = BCRYPT_PEPPER) : string {
    $cost = 0;
    $salt = '';

    if ($settings != null) {
        [, , $cost, $salt] = explode('$', $settings);
        $salt = substr($salt, 0, 22);
    }

    if ($cost == null) {
        $cost = BCRYPT_COST;
    }

    if ($salt == null) {
        $salt = Radix64::encode(
            random_bytes(BCRYPT_SALT_BYTES)
        );
    }

    $settings = sprintf('$%2s$%02d$%s', BCRYPT_ID, $cost, $salt);

    $pre_hash  = base64_encode(
        hash_hmac(HMAC_SHA512, $password, $pepper, true)
    );

    $mid_hash  = crypt($pre_hash, $settings);

    $post_hash = base64_encode(
        hash_hmac(HMAC_SHA512, $mid_hash, $pepper, true)
    );

    return $settings . rtrim($post_hash, '=');
}

/**
 * Compares password to stored hash value
 *
 * @param string $password  plaintext password
 * @param string $valid     stored hash value for comparison
 * @param string $pepper    optional pepper string
 * @returns bool
 * @throws Exception
 */
function hmac_bcrypt_verify(string $password, string $valid, string $pepper = BCRYPT_PEPPER) : bool {
    return hash_equals(
        hmac_bcrypt_hash($password, $valid, $pepper),
        $valid
    );
}
