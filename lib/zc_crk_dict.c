/*
 *  zc - zip crack library
 *  Copyright (C) 2017  Marc Ferland
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

#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "libzc.h"
#include "libzc_private.h"

#define PW_BUF_LEN 64

struct zc_crk_dict {
    struct zc_ctx *ctx;
    int refcount;
    char *filename;
    struct validation_data vdata[VDATA_MAX];
    size_t vdata_size;
    unsigned char *cipher;
    unsigned char *plaintext;
    unsigned char *inflate;
    size_t cipher_size;
    bool cipher_is_deflated;
    uint32_t original_crc;
    FILE *fd;
};

static inline void remove_trailing_newline(char *line)
{
    while (*line) {
        if (*line == '\n' || *line == '\r') {
            *line = '\0';
            return;
        }
        ++line;
    }
    return;
}

ZC_EXPORT struct zc_crk_dict *zc_crk_dict_ref(struct zc_crk_dict *crk)
{
    if (!crk)
        return NULL;
    crk->refcount++;
    return crk;
}

ZC_EXPORT struct zc_crk_dict *zc_crk_dict_unref(struct zc_crk_dict *crk)
{
    if (!crk)
        return NULL;
    crk->refcount--;
    if (crk->refcount > 0)
        return crk;
    free(crk->filename);
    free(crk->cipher);
    free(crk->plaintext);
    free(crk->inflate);
    free(crk);
    return NULL;
}

ZC_EXPORT int zc_crk_dict_new(struct zc_ctx *ctx, struct zc_crk_dict **crk)
{
    struct zc_crk_dict *tmp;

    tmp = calloc(1, sizeof(struct zc_crk_dict));
    if (!tmp)
        return -1;

    tmp->ctx = ctx;
    tmp->refcount = 1;

    *crk = tmp;

    return 0;
}

ZC_EXPORT int zc_crk_dict_init(struct zc_crk_dict *crk, const char *filename)
{
    int err;

    crk->inflate = malloc(INFLATE_CHUNK);
    if (!crk->inflate) {
        err(crk->ctx, "failed to allocate memory\n");
        return -1;
    }

    err = fill_vdata(crk->ctx, filename, crk->vdata, VDATA_MAX);
    if (err < 1) {
        err(crk->ctx, "failed to read validation data\n");
        return -1;
    }

    crk->vdata_size = err;

    err = fill_test_cipher(crk->ctx,
                           filename,
                           &crk->cipher,
                           &crk->cipher_size,
                           &crk->original_crc,
                           &crk->cipher_is_deflated);
    if (err) {
        err(crk->ctx, "failed to read cipher data\n");
        return -1;
    }

    crk->plaintext = malloc(crk->cipher_size);
    if (!crk->plaintext) {
        free(crk->inflate);
        free(crk->cipher);
        return -1;
    }
    crk->filename = strdup(filename);

    return 0;
}

static bool test_password(struct zc_crk_dict *crk, const char *pw)
{
    struct zc_key key, base;
    size_t i = 0;

    set_default_encryption_keys(&base);

    while(pw[i] != '\0') {
        update_keys(pw[i], &base, &base);
        ++i;
    }

    for (i = 0; i < crk->vdata_size; ++i) {
        reset_encryption_keys(&base, &key);
        if (decrypt_header(crk->vdata[i].encryption_header,
                           &key,
                           crk->vdata[i].magic))
            return false;
    }

    decrypt(crk->cipher, crk->plaintext, crk->cipher_size, &base);
    int err;
    if (crk->cipher_is_deflated)
        err = inflate_buffer(&crk->plaintext[12],
                             crk->cipher_size - 12,
                             crk->inflate,
                             INFLATE_CHUNK,
                             crk->original_crc);
    else
        err = test_buffer_crc(&crk->plaintext[12],
                              crk->cipher_size - 12,
                              crk->original_crc);

    return err ? false : true;
}

ZC_EXPORT int zc_crk_dict_start(struct zc_crk_dict *crk, const char *dict, char *pw, size_t len)
{
    FILE *f;
    char pwbuf[PW_BUF_LEN];
    int err = 1;

    if (len > PW_BUF_LEN || !crk->vdata_size)
        return -1;

    if (dict) {
        f = fopen(dict, "r");
        if (!f) {
            err(crk->ctx, "fopen() failed: %s\n", strerror(errno));
            return -1;
        }
    } else
        f = stdin;

    while (1) {
        char *s = fgets(pwbuf, PW_BUF_LEN, f);
        if (!s) {
            err = -1;
            break;
        }

        remove_trailing_newline(s);

        if (test_password(crk, s)) {
            err = 0;
            memset(pw, 0, len);
            strncpy(pw, s, len);
            break;
        }
    }

    fclose(f);
    return err;
}
