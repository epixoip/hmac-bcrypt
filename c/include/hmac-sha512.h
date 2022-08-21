
#pragma once

#include <openssl/evp.h>

#define SHA512_SZ  64

char *base64_encode(const unsigned char *input, int len) {
    int   output_len = 4 * ((len + 2) / 3);
    char *output     = (char *) calloc(output_len + 1, sizeof(char));

    EVP_EncodeBlock((unsigned char *) output, input, len);

    for (int i = output_len - 2; i < output_len; i++) {
        if (output[i] == '=') {
            output[i] = 0;
        }
    }

    return output;
}

char *hmac_sha512_base64(const char *key, const char *data) {
    unsigned char hash_raw[SHA512_SZ] = { 0 };

    HMAC(
        EVP_sha512(), 
        (const void *) key, 
        strlen((const char *) key),
        (const unsigned char *) data,
        strlen((const char *) data), 
        hash_raw, 
        NULL
    );

    return base64_encode(hash_raw, SHA512_SZ);
}
