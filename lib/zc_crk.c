/*
 *  zc - zip crack library
 *  Copyright (C) 2013  Marc Ferland
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "crc32.h"
#include "zip.h"
#include "libzc.h"
#include "libzc_private.h"

#define KEY0 0x12345678
#define KEY1 0x23456789
#define KEY2 0x34567890

struct zc_crk_bforce {
    struct zc_pwgen *gen;
    const struct zc_validation_data *vdata;
    size_t vdata_size;
    struct zc_ctx *ctx;
    int refcount;
};

static inline void update_keys(char c, struct zc_key *k)
{
    k->key0 = crc32(k->key0, c);
    k->key1 = (k->key1 + (k->key0 & 0x000000ff)) * MULT + 1;
    k->key2 = crc32(k->key2, k->key1 >> 24);
}

static inline void set_default_encryption_keys(struct zc_key *k)
{
    k->key0 = KEY0;
    k->key1 = KEY1;
    k->key2 = KEY2;
}

static inline void init_encryption_keys(const char *pw, struct zc_key *k)
{
    int i = 0;
    set_default_encryption_keys(k);
    while (pw[i] != '\0') {
        update_keys(pw[i], k);
        ++i;
    }
}

static void init_encryption_keys_from_base(const char *pw, struct zc_key *key_table,
                                           struct zc_key *k, size_t idem_char)
{
    *k = key_table[idem_char];

    /* do {} while() assuming password is never empty */
    do {
        update_keys(pw[idem_char], k);
        key_table[idem_char + 1] = *k;
        ++idem_char;
    } while (pw[idem_char] != '\0');
}

static inline void reset_encryption_keys(const struct zc_key *base, struct zc_key *k)
{
    *k = *base;
}

static inline uint8_t decrypt_byte(uint32_t k)
{
    uint16_t tmp =  k | 2;
    return ((tmp * (tmp ^ 1)) >> 8);
}

static inline uint8_t decrypt_header(const uint8_t *encrypted_header, struct zc_key *k)
{
    int i;
    uint8_t c;

    for (i = 0; i < ZIP_ENCRYPTION_HEADER_LENGTH; ++i) {
        c = encrypted_header[i] ^ decrypt_byte(k->key2);
        update_keys(c, k);
    }

    /* Returns the last byte of the decrypted header */
    return c;
}

ZC_EXPORT bool zc_crk_test_one_pw(const char *pw, const struct zc_validation_data *vdata, size_t nmemb)
{
    struct zc_key key;
    struct zc_key base_key;
    size_t i;

    init_encryption_keys(pw, &base_key);
    for (i = 0; i < nmemb; ++i) {
        reset_encryption_keys(&base_key, &key);
        if (decrypt_header(vdata[i].encryption_header, &key) == vdata[i].magic)
            continue;
        return false;
    }
    return true;
}

ZC_EXPORT int zc_crk_bforce_new(struct zc_ctx *ctx, struct zc_crk_bforce **crk)
{
    struct zc_crk_bforce *tmp;

    tmp = calloc(1, sizeof(struct zc_crk_bforce));
    if (!tmp)
        return -ENOMEM;

    tmp->ctx = ctx;
    tmp->refcount = 1;
    *crk = tmp;
    dbg(ctx, "cracker %p created\n", tmp);
    return 0;
}

ZC_EXPORT struct zc_crk_bforce *zc_crk_bforce_ref(struct zc_crk_bforce *crk)
{
    if (!crk)
        return NULL;
    crk->refcount++;
    return crk;
}

ZC_EXPORT struct zc_crk_bforce *zc_crk_bforce_unref(struct zc_crk_bforce *crk)
{
    if (!crk)
        return NULL;
    crk->refcount--;
    if (crk->refcount > 0)
        return crk;
    dbg(crk->ctx, "cracker %p released\n", crk);
    zc_pwgen_unref(crk->gen);
    free(crk);
    return NULL;
}

ZC_EXPORT int zc_crk_bforce_set_pwgen(struct zc_crk_bforce *crk, struct zc_pwgen *pwgen)
{
    if (!pwgen)
        return -EINVAL;
    crk->gen = zc_pwgen_ref(pwgen);
    return 0;
}

ZC_EXPORT int zc_crk_bforce_set_vdata(struct zc_crk_bforce *crk, const struct zc_validation_data *vdata, size_t nmemb)
{
    if (!vdata)
        return -EINVAL;
    if (nmemb == 0)
        return -EINVAL;
    crk->vdata = vdata;
    crk->vdata_size = nmemb;
    return 0;
}

static bool is_valid_cracker(struct zc_crk_bforce *crk)
{
    /* invalid arguments */
    if (!crk->gen || !crk->vdata)
        return false;

    if (!zc_pwgen_is_initialized(crk->gen))
        return false;
    return true;
}

ZC_EXPORT int zc_crk_bforce_start(struct zc_crk_bforce *crk, char *out_pw, size_t out_pw_size)
{
    struct zc_key key;
    struct zc_key base_key;
    struct zc_key key_table[out_pw_size];
    struct zc_pwgen *gen = crk->gen;
    const char *pw;
    size_t idem_char = 0;
    bool found = false;

    if (!out_pw || !is_valid_cracker(crk))
        return -EINVAL;

    memset(&key_table, 0, out_pw_size * sizeof(struct zc_key));

    set_default_encryption_keys(key_table);

    pw = zc_pwgen_pw(gen);
    do {
        init_encryption_keys_from_base(pw, key_table, &base_key, idem_char);
        found = true;
        for (size_t i = 0; i < crk->vdata_size; ++i) {
            reset_encryption_keys(&base_key, &key);
            if (decrypt_header(crk->vdata[i].encryption_header, &key) == crk->vdata[i].magic)
                continue;
            found = false;
            break;
        }

        if (found) {
            memset(out_pw, 0, out_pw_size);
            strncpy(out_pw, pw, out_pw_size - 1);
            break;
        }

        pw = zc_pwgen_generate(gen, &idem_char);
    } while (pw);

    return found == true ? 0 : -1;
}

ZC_EXPORT int zc_crk_bforce_skip(struct zc_crk_bforce *crk, char *UNUSED(out_pw), size_t UNUSED(out_pw_size))
{
    size_t tmp;
    if (!is_valid_cracker(crk))
        return -EINVAL;
    if (!zc_pwgen_generate(crk->gen, &tmp))
        return -1;
    return 0;
}
