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

struct zc_pwgen {
    char *pw;
    char *char_lut;
    char *char_ascii;
    char *char_indexes;
    size_t max_pw_len;
    size_t char_lut_len;
    int step;
};

static void init_char_ascii(struct zc_pwgen *gen, const char *pw, size_t len)
{
    gen->pw = gen->char_ascii + gen->max_pw_len - len;
    strncpy(gen->pw, pw, len);
}

static void init_char_indexes(struct zc_pwgen *gen, size_t len)
{
    const size_t first_valid_index = gen->max_pw_len - len;
    size_t i, j;

    for (i = 0; i < first_valid_index; ++i)
        gen->char_indexes[i] = -1;

    for (i = first_valid_index, j = 0; j < len; ++i, ++j)
        gen->char_indexes[i] = index(gen->char_lut, gen->pw[j]) - gen->char_lut;
}

static inline const char *pwgen_generate(struct zc_pwgen *gen, size_t *count)
{
    int quotient = gen->step;
    const char *pw_orig = gen->pw;
    char *char_idx = &gen->char_indexes[gen->max_pw_len - 1];
    char *char_ascii = &gen->char_ascii[gen->max_pw_len - 1];
    int iteration = 0;

    while (1) {
        *char_idx += quotient;
        quotient = *char_idx / gen->char_lut_len;
        *char_idx = *char_idx - quotient * gen->char_lut_len;

        *char_ascii = gen->char_lut[(unsigned char) * char_idx];

        if (quotient > 0 && char_ascii == gen->char_ascii) {
            *count = 0;
            return NULL;           /* overflow */
        }

        iteration++;
        if (quotient == 0)
            break;

        --char_idx;
        --char_ascii;

        if (char_ascii < gen->pw)
            gen->pw = char_ascii;
    }

    /* return 0 if the pw len changed, the pw is only one char or the
     * first char changed */
    if (gen->pw != pw_orig ||
        gen->pw == &gen->char_ascii[gen->max_pw_len - 1] ||
        iteration == (&gen->char_ascii[gen->max_pw_len - 1] - gen->pw + 1))
        *count = 0;
    else
        *count = char_ascii - gen->pw;

    return gen->pw;
}

struct zc_crk_bforce {
    const struct zc_validation_data *vdata;
    size_t vdata_size;
    struct zc_ctx *ctx;
    int refcount;
    struct zc_pwgen gen;
};

static inline void update_keys(char c, struct zc_key *ksrc, struct zc_key *kdst)
{
    kdst->key0 = crc32(ksrc->key0, c);
    kdst->key1 = (ksrc->key1 + (kdst->key0 & 0x000000ff)) * MULT + 1;
    kdst->key2 = crc32(ksrc->key2, kdst->key1 >> 24);
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
        update_keys(pw[i], k, k);
        ++i;
    }
}

static inline size_t init_key_table(const char *pw, struct zc_key *key_table,
                                    size_t idem_char)
{
    /* do {} while() assuming password is never empty */
    do {
        update_keys(pw[idem_char], &key_table[idem_char], &key_table[idem_char + 1]);
        ++idem_char;
    } while (pw[idem_char] != '\0');
    return idem_char;
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
        update_keys(c, k, k);
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
    free(crk->gen.char_lut);
    free(crk->gen.char_ascii);
    free(crk->gen.char_indexes);
    free(crk);
    return NULL;
}

ZC_EXPORT int zc_crk_bforce_set_pwgen_cfg(struct zc_crk_bforce *crk, const char *char_lut,
                                          size_t max_pw_len, size_t thread_num, const char *initial, uint32_t step)
{
    const size_t lut_len = strlen(char_lut);
    const size_t len = strlen(initial);
    char *char_lut_tmp = NULL;
    char *char_ascii_tmp = NULL;
    char *char_indexes_tmp = NULL;

    if (lut_len == 0)
        return -EINVAL;

    if (max_pw_len == 0)
        return -EINVAL;

    if (thread_num == 0)
       return -EINVAL;

    if (len > max_pw_len)
       return -EINVAL;

    char_lut_tmp = strdup(char_lut);
    if (!char_lut_tmp)
        return -ENOMEM;

    char_ascii_tmp = calloc(1, max_pw_len + 1);
    if (!char_ascii_tmp)
        goto error1;

    char_indexes_tmp = calloc(1, max_pw_len);
    if (!char_indexes_tmp)
        goto error2;

    crk->gen.char_lut = char_lut_tmp;
    crk->gen.char_lut_len = lut_len;
    crk->gen.char_ascii = char_ascii_tmp;
    crk->gen.char_indexes = char_indexes_tmp;
    crk->gen.max_pw_len = max_pw_len;

    init_char_ascii(&crk->gen, initial, len);
    init_char_indexes(&crk->gen, len);

    /* advance the pwgen to this thread's first pw */
    crk->gen.step = 1;
    for (size_t i = 0; i < thread_num - 1 ; ++i) {
       size_t count;
       if (!pwgen_generate(&crk->gen, &count)) {
          err(crk->ctx, "too many threads for password range.\n");
          goto error2;
       }
    }
    crk->gen.step = step;

    return 0;

error2:
    free(char_ascii_tmp);
error1:
    free(char_lut_tmp);
    return -ENOMEM;
}

ZC_EXPORT void zc_crk_bforce_pwgen_step(struct zc_crk_bforce *crk, uint32_t step)
{
    crk->gen.step = step;
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
    if (!crk->vdata || crk->gen.step <= 0 || !crk->gen.pw)
        return false;
    return true;
}

ZC_EXPORT int zc_crk_bforce_start(struct zc_crk_bforce *crk, char *out_pw, size_t out_pw_size)
{
    struct zc_key key;
    struct zc_key key_table[out_pw_size];
    size_t idem_char = 0;
    bool found = false;

    if (!out_pw || !is_valid_cracker(crk))
        return -EINVAL;

    memset(&key_table, 0, out_pw_size * sizeof(struct zc_key));

    set_default_encryption_keys(key_table);

    do {
        size_t lastidx = init_key_table(crk->gen.pw, key_table, idem_char);
        found = true;
        for (size_t i = 0; i < crk->vdata_size; ++i) {
            /* reset key to last key_table entry */
            key = key_table[lastidx];
            if (decrypt_header(crk->vdata[i].encryption_header, &key) == crk->vdata[i].magic)
                continue;
            found = false;
            break;
        }

        if (found) {
            memset(out_pw, 0, out_pw_size);
            strncpy(out_pw, crk->gen.pw, out_pw_size - 1);
            break;
        }

        pwgen_generate(&crk->gen, &idem_char);
    } while (crk->gen.pw);

    return found == true ? 0 : -1;
}

ZC_EXPORT int zc_crk_bforce_skip(struct zc_crk_bforce *crk, char *UNUSED(out_pw), size_t UNUSED(out_pw_size))
{
    size_t tmp;
    if (!is_valid_cracker(crk))
        return -EINVAL;
    if (!pwgen_generate(&crk->gen, &tmp))
        return -1;
    return 0;
}
