/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2017 Marc Ferland
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

#include <string.h>

#include "libzc.h"
#include "libzc_private.h"
#include "crc32.h"

#define PREKEY1 0x57d2770       /* the only key1 value possible before
                                 * 0x12345678, found by exhaustive
                                 * search */
#define PASS_MAX_LEN 13

struct final {
    const uint8_t (*lsbk0_lookup)[2];
    const uint32_t *lsbk0_count;
    char pw[PASS_MAX_LEN];
    struct zc_key k[PASS_MAX_LEN + 1];  /* 14 --> store the internal rep at index 0 */
    struct zc_key saved;
    int len_under_test;
};

static void inplace_reverse(char *str, size_t len)
{
    char *end = str + len - 1;

#   define XOR_SWAP(a,b) do\
    {\
      a ^= b;\
      b ^= a;\
      a ^= b;\
    } while (0)

    while (str < end) {
        XOR_SWAP(*str, *end);
        str++;
        end--;
    }
#   undef XOR_SWAP
}

/**
 * Zero-out pw and keys
 */
static void reset(struct final *f)
{
    memset(f->pw, 0, PASS_MAX_LEN);
    memset(&f->k[1], 0, PASS_MAX_LEN * sizeof(struct zc_key));
}

static void save_internal_rep(struct final *f)
{
    f->saved = f->k[0];
}

static void restore_internal_rep(struct final *f)
{
    f->k[0] = f->saved;
}

/**
 * From 'k' msb and 'km1' lsb (previous key from 'k'), find the key
 * (key being the byte that went through the crc32 function).
 */
static char recover_input_byte_from_crcs(uint32_t km1, uint32_t k)
{
    return (lsb(km1) ^ crc_32_invtab[msb(k)] ^ 0x00) & 0xff;
}

/**
 * From 'pw', calculate the internal representation of the key and
 * compare it with 'k'.
 */
static int compare_pw_with_key(const char *pw, size_t len, const struct zc_key *k)
{
    struct zc_key tmp;

    set_default_encryption_keys(&tmp);

    for (size_t i = 0; i < len; ++i)
        update_keys(pw[i], &tmp, &tmp);

    return (k->key0 == tmp.key0 &&
            k->key1 == tmp.key1 &&
            k->key2 == tmp.key2) ? 0 : -1;
}

static int compare_revpw_with_key(const char *pw, size_t len, const struct zc_key *k)
{
    char revpw[PASS_MAX_LEN];

    for (int i = len - 1, j = 0; i >= 0; --i, ++j)
        revpw[j] = pw[i];

    return compare_pw_with_key(revpw, len, k);
}

/**
 * passwords length 1->4
 */
static int try_key_1_4(struct final *f)
{
    for (int len = 1; len <= 4; ++len) {
        /* recover k0 msb */
        f->k[len].key0 = crc32inv(f->k[len - 1].key0, 0x0);

        /* recover bytes */
        uint32_t prev = KEY0;
        for (int j = 0, k = len - 1; j < len; ++j, --k) {
            f->pw[j] = recover_input_byte_from_crcs(prev, f->k[k].key0);
            prev = crc32(prev, f->pw[j]);
        }

        if (compare_pw_with_key(f->pw, len, f->k) == 0)
            return len;
    }
    return -1;
}

/**
 * From k1 MSBs found earlier, recover full k1 and k0 LSBs. For
 * example, from:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x???????? key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x???????? key1 = 0x1c?????? key2 = 0x3d945e94
 * key0 = 0x???????? key1 = 0x2b?????? key2 = 0x4ccb4379
 * key0 = 0x???????? key1 = 0xb3?????? key2 = 0xa253270a
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 *
 * recover:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x??????97 key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x??????a2 key1 = 0x1cd05dd7 key2 = 0x3d945e94
 * key0 = 0x??????23 key1 = 0x2b7993bc key2 = 0x4ccb4379
 * key0 = 0x??????96 key1 = 0xb303049c key2 = 0xa253270a
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 */
static bool recover_key1_key0lsb(struct zc_key *k,
                                 const uint8_t (*lsbk0_lookup)[2],
                                 const uint32_t *lsbk0_count,
                                 uint32_t level)
{
    if (level == 0)
        return k->key1 == KEY1;

    uint32_t key1 = k->key1;
    uint32_t key1m1 = (k + 1)->key1;
    uint32_t key1m2 = (k + 2)->key1;
    uint32_t rhs_step1 = (key1 - 1) * MULTINV;
    uint32_t rhs_step2 = (rhs_step1 - 1) * MULTINV;
    uint8_t diff = msb(rhs_step2 - mask_msb(key1m2));

    for (uint32_t c = 2; c != 0; --c, --diff) {
        for (uint32_t i = 0; i < lsbk0_count[diff]; ++i) {
            uint32_t lsbkey0i = lsbk0_lookup[diff][i];
            if (mask_msb(rhs_step1 - lsbkey0i) == mask_msb(key1m1)) {
                (k + 1)->key1 = rhs_step1 - lsbkey0i;
                k->key0 = (k->key0 & 0xffffff00) | lsbkey0i; /* set LSB */
                if (recover_key1_key0lsb(k + 1, lsbk0_lookup, lsbk0_count, level - 1))
                    return true;
            }
        }
    }
    return false;
}

/**
 * From the internal representation, we can calculate key1_0, key2_0,
 * and key2_-1. See equation 2 in Biham & Kocher.
 */
static void key_56_step1(struct zc_key *k)
{
    /* recover full key2_0 */
    k[1].key2 = crc32inv(k[0].key2, msb(k[0].key1));

    /* recover full key1_0 */
    k[1].key1 = ((k[0].key1 - 1) * MULTINV) - lsb(k[0].key0);

    /* recover full key2_-1 */
    k[2].key2 = crc32inv(k[1].key2, msb(k[1].key1));
}

/**
 * From full key2_0, key1_0 and key2_-1 recover the other full key2
 * values and k1 MSBs.
 *
 * For example, from:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x???????? key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x3d945e94
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x????????
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x????????
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 *
 * recover key2 MSBs:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x???????? key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x3d945e94
 * key0 = 0x???????? key1 = 0x???????? key2 = 0x4ccb43?? <--
 * key0 = 0x???????? key1 = 0x???????? key2 = 0xa253???? <--
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 *
 * then recover k1 MSBs and the full key2 values:
 *
 * key0 = 0x54dca24b key1 = 0x1b079a3b key2 = 0x120a6936 --> Initial
 * key0 = 0x???????? key1 = 0x64329027 key2 = 0xbd806642
 * key0 = 0x???????? key1 = 0x1c?????? key2 = 0x3d945e94 <--
 * key0 = 0x???????? key1 = 0x2b?????? key2 = 0x4ccb4379 <--
 * key0 = 0x???????? key1 = 0xb3?????? key2 = 0xa253270a <--
 * key0 = 0x12345678 key1 = 0x23456789 key2 = 0x34567890
 *
 */
static void key_56_step2(struct zc_key *k, int start)
{
    uint32_t prev = KEY2;

    /* recover key2_-2 (24 bits msb) */
    k[3].key2 = crc32inv(k[2].key2, 0x0);

    /* recover key2_-3 (16 bits msb) */
    k[4].key2 = crc32inv(k[3].key2, 0x0);

    /* recover key2_-4 (8 bits msb) */
    k[5].key2 = crc32inv(k[4].key2, 0x0); /* TODO: k[5] is already known if key is only 5 chars */

    /* recover full key1 values */
    for (int i = start; i >= 2; --i) {
        k[i].key1 = recover_input_byte_from_crcs(prev, k[i].key2) << 24;
        prev = crc32(prev, msb(k[i].key1));
        /* do not overwrite key2_-1, since we know the full value */
        if (i > 2)
            k[i].key2 = prev;
    }
}

static bool verify_against_key2m1(const struct zc_key *k)
{
    return crc32(k[3].key2, msb(k[2].key1)) == k[2].key2;
}

static int try_key_5_6(struct final *f)
{
    struct zc_key *k = f->k;

    key_56_step1(k);

    for (int i = 4; i <= 5; ++i) {
        key_56_step2(k, i);

        if (!verify_against_key2m1(k))
            continue;

        set_default_encryption_keys(&k[i + 1]);
        k[i + 2].key1 = PREKEY1;

        if (!recover_key1_key0lsb(&k[1], f->lsbk0_lookup, f->lsbk0_count, i))
            continue;

        /* recover bytes */
        for (int j = 0; j < i + 1; ++j) {
            f->pw[j] = recover_input_byte_from_crcs(k[j + 1].key0, k[j].key0);
            k[j + 1].key0 = crc32inv(k[j].key0, f->pw[j]);
        }

        if (compare_revpw_with_key(f->pw, i + 1, &f->k[0]) < 0)
            continue;

        inplace_reverse(f->pw, i + 1);
        return i + 1;
    }

    return -1;
}

static void recover_prev_key(const struct zc_key *k, char c, struct zc_key *prev)
{
    prev->key2 = crc32inv(k->key2, msb(k->key1));
    prev->key1 = ((k->key1 - 1) * MULTINV) - lsb(k->key0);
    prev->key0 = crc32inv(k->key0, c);
}

static int recurse_key_7_13(struct final *f, size_t level, struct zc_key current, char *pw)
{
    /*
     * Try all the possible values at position key_0, key_-1, up to
     * key_l-6 basically offsetting the internal representation by one
     * byte at each recursion level.
     */
    if (level > 0) {
        struct zc_key prev;
        for (int i = 0; i < 256; ++i) {
            *pw = i;
            recover_prev_key(&current, i, &prev);
            int ret = recurse_key_7_13(f, level - 1, prev, pw + 1);
            if (ret > 0)
                return ret + 1;
        }
        return -1;
    }

    /*
     * Try to recover the remaining 6 key bytes by using the same
     * algorithm as try_key_5_6 (l=6).
     */
    struct zc_key *k = f->k;
    *k = current;
    key_56_step1(k);
    key_56_step2(k, 5);

    /* verify against key2_-1 */
    if (!verify_against_key2m1(k))
        goto next;

    set_default_encryption_keys(&k[6]);
    k[7].key1 = PREKEY1;
    if (!recover_key1_key0lsb(&k[1], f->lsbk0_lookup, f->lsbk0_count, 5))
        goto next;

    for (int j = 0; j < 6; ++j) {
        pw[j] = recover_input_byte_from_crcs(k[j + 1].key0, k[j].key0);
        k[j + 1].key0 = crc32inv(k[j].key0, pw[j]);
    }

    if (compare_revpw_with_key(f->pw, f->len_under_test, &f->saved) < 0)
        goto next;

    /* got it! */
    inplace_reverse(f->pw, f->len_under_test);
    return 6;

next:
    restore_internal_rep(f);
    return -1;
}

static int try_key_7_13(struct final *f)
{
    save_internal_rep(f);
    for (int i = 1, len = 7; i <= 7; ++i, ++len) {
        f->len_under_test = len;
        if (recurse_key_7_13(f, i, f->k[0], f->pw) == len) {
            restore_internal_rep(f);
            return len;
        }
    }
    restore_internal_rep(f);
    return -1;
}

int find_password(const uint8_t (*lsbk0_lookup)[2],
                  const uint32_t *lsbk0_count,
                  const struct zc_key *int_rep,
                  char *out,
                  size_t len)
{
    struct final f;
    int ret;

    if (len < PASS_MAX_LEN)
        return -1;

    if (int_rep->key0 == KEY0 &&
        int_rep->key1 == KEY1 &&
        int_rep->key2 == KEY2)
        return 0;               /* password has 0 bytes */

    /* initialise final structure */
    f.lsbk0_lookup = lsbk0_lookup;
    f.lsbk0_count = lsbk0_count;
    f.k[0] = *int_rep;

    ret = try_key_1_4(&f);
    if (ret > 0)
        goto found;

    reset(&f);
    ret = try_key_5_6(&f);
    if (ret > 0)
        goto found;

    reset(&f);
    ret = try_key_7_13(&f);
    if (ret > 0)
        goto found;

    /* password not found */
    return -1;

found:
    memset(out, 0, len);
    memcpy(out, f.pw, ret);
    return ret;
}
