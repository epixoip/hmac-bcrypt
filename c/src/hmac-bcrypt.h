#pragma once

#include <sys/random.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>

#include "util.h"
#include "bcrypt.h"
#include "hmac-sha512.h"

#define BCRYPT_ID           "$2a$"
#define BCRYPT_PEPPER       "hmac_bcrypt"
#define BCRYPT_COST         13
#define BCRYPT_SALT_SZ      16
#define BCRYPT_ENC_SALT_SZ  22
#define BCRYPT_ENC_SETT_SZ  30
#define BCRYPT_SZ           61
#define BCRYPT_HMAC_SZ      116

char *hmac_bcrypt_hash(char *password, char *settings, char *pepper) {
    char *salt = NULL;
    int   cost = 0;

    if (settings) {
        array_t *settings_arr = split('$', settings);

        if (settings_arr->size > 2) {
            cost = atoi(settings_arr->elements[2]);
        }

        if (settings_arr->size > 3) {
            salt = substr(
                settings_arr->elements[3], 
                0, 
                BCRYPT_ENC_SALT_SZ
            );
        }

        free_array(settings_arr);
    }

    if (!cost) {
        cost = BCRYPT_COST;
    }

    if (!salt) {
        char salt_raw[BCRYPT_SALT_SZ] = { 0 };
        getrandom(&salt_raw, BCRYPT_SALT_SZ, 0);

        salt = (char *) calloc(BCRYPT_ENC_SALT_SZ, sizeof(char));
        BF_encode(
            salt, 
            (const BF_word *) salt_raw, 
            BCRYPT_SALT_SZ
        );
    }

    if (!pepper) {
        pepper = BCRYPT_PEPPER;
    }

    char setting_str[BCRYPT_ENC_SETT_SZ + 1] = { 0 };
    snprintf(
        setting_str, 
        BCRYPT_ENC_SETT_SZ, 
        "%s%02d$%s", 
        BCRYPT_ID, 
        cost, 
        salt
    );

    free(salt);

    char *pre_hash = hmac_sha512_base64(pepper, password);
    
    char mid_hash[BCRYPT_SZ] = { 0 };
    BF_crypt(pre_hash, setting_str, mid_hash, BCRYPT_SZ, 16);

    char *post_hash = hmac_sha512_base64(pepper, mid_hash);

    char *final = (char *) calloc(BCRYPT_HMAC_SZ + 1, sizeof(char));
    snprintf(final, BCRYPT_HMAC_SZ, "%s%s", setting_str, post_hash);

    free(pre_hash);
    free(post_hash);

    return final;
}

int hmac_bcrypt_verify(char *password, char *valid, char *pepper) {
    if (!pepper) {
        pepper = BCRYPT_PEPPER;
    }

    char *a = hmac_bcrypt_hash(password, valid, pepper);
    char *b = valid;

    size_t a_len = strlen(a);
    size_t b_len = strlen(b);

    size_t diff = a_len ^ b_len;

    for (int i = 0; i < a_len && i < b_len; i++) {
        diff |= a[i] ^ b[i];
    }

    return diff == 0;
}
