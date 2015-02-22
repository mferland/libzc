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

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "libzc.h"
#include "libzc_private.h"

struct zc_pwdict {
    struct zc_ctx *ctx;
    int refcount;
    FILE *fd;
    char *filename;
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

ZC_EXPORT int zc_pwdict_new_from_filename(struct zc_ctx *ctx, const char *filename, struct zc_pwdict **dict)
{
    struct zc_pwdict *newpwdict;

    newpwdict = calloc(1, sizeof(struct zc_pwdict));
    if (!newpwdict)
        return -ENOMEM;

    newpwdict->ctx = ctx;
    newpwdict->refcount = 1;
    if (filename)
        newpwdict->filename = strdup(filename);
    *dict = newpwdict;
    dbg(ctx, "pwdict %p created\n", newpwdict);
    return 0;
}

ZC_EXPORT struct zc_pwdict *zc_pwdict_unref(struct zc_pwdict *dict)
{
    if (!dict)
        return NULL;
    dict->refcount--;
    if (dict->refcount > 0)
        return dict;
    dbg(dict->ctx, "pwdict %p released\n", dict);
    if (dict->filename)
        free(dict->filename);
    free(dict);
    return NULL;
}

ZC_EXPORT int zc_pwdict_open(struct zc_pwdict *dict)
{
    if (!dict->filename) {
        dict->fd = stdin;
        return 0;
    }

    FILE *fd = fopen(dict->filename, "r");
    if (!fd) {
        err(dict->ctx, "fopen() failed: %s\n", strerror(errno));
        return -1;
    }

    dbg(dict->ctx, "dict %p fopen() returned: %p\n", dict, fd);

    dict->fd = fd;
    return 0;
}

ZC_EXPORT int zc_pwdict_close(struct zc_pwdict *dict)
{
    if (!dict->filename) {
        dict->fd = NULL;
        return 0;
    }

    if (fclose(dict->fd)) {
        err(dict->ctx, "fclose() failed: %s\n", strerror(errno));
        return -1;
    }

    dbg(dict->ctx, "dict %p fclose() successfull\n", dict);

    dict->fd = NULL;
    return 0;
}

ZC_EXPORT int zc_pwdict_read_one_pw(struct zc_pwdict *dict, char *str, size_t len)
{
    char *str_ret;

    if (dict->fd == 0 || len == 0)
        return -EINVAL;

    str_ret = fgets(str, len, dict->fd);
    if (!str_ret)
        return -1;

    remove_trailing_newline(str_ret);
    return 0;
}
