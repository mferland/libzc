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
    if (crk->filename)
        free(crk->filename);
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

    err = fill_vdata(crk->ctx, filename, crk->vdata, VDATA_MAX);
    if (err < 1) {
        err(crk->ctx, "failed to read validation data\n");
        return -1;
    }

    crk->vdata_size = err;
    crk->filename = strdup(filename);

    return 0;
}

ZC_EXPORT int zc_crk_dict_start(struct zc_crk_dict *crk, const char *dict, char *pw, size_t len)
{
    FILE *f;
    char pwbuf[PW_BUF_LEN];
    int err = 1;

    if (len > PW_BUF_LEN || !crk->vdata_size)
        return -1;

    f = fopen(dict, "r");
    if (!f) {
        err(crk->ctx, "fopen() failed: %s\n", strerror(errno));
        return -1;
    }

    while (1) {
        char *s = fgets(pwbuf, PW_BUF_LEN, f);
        if (!s) {
            err = -1;
            break;
        }

        remove_trailing_newline(s);

        if (test_one_pw(s, crk->vdata, crk->vdata_size)) {
            if (test_password_ext(crk->filename, s)) {
                err = 0;
                memset(pw, 0, len);
                strncpy(pw, s, len);
                break;
            }
        }
    }

    fclose(f);
    return err;
}
