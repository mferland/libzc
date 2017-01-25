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

#include "libzc_private.h"
#include "decrypt_byte.h"

#include <zlib.h>

int fill_vdata(struct zc_ctx *ctx, const char *filename,
               struct zc_validation_data *vdata,
               size_t nmemb)
{
    struct zc_file *file;
    int err;

    err = zc_file_new_from_filename(ctx, filename, &file);
    if (err)
        return -1;

    err = zc_file_open(file);
    if (err) {
        zc_file_unref(file);
        return -1;
    }

    int size = zc_file_read_validation_data(file, vdata, nmemb);

    zc_file_close(file);
    zc_file_unref(file);

    return size;
}

int fill_test_cipher(struct zc_ctx *ctx, const char *filename,
                     unsigned char **buf, size_t *len)
{
    struct zc_file *file;
    int err;

    err = zc_file_new_from_filename(ctx, filename, &file);
    if (err)
        return -1;

    err = zc_file_open(file);
    if (err) {
        zc_file_unref(file);
        return -1;
    }

    size_t tmp = zc_file_read_crypt_data(file, buf);
    if (!tmp) {
        zc_file_unref(file);
        return -1;
    }

    *len = tmp;
    zc_file_close(file);
    zc_file_unref(file);

    return 0;
}

void decrypt(const unsigned char *in, unsigned char *out, size_t len, const char *pw)
{
    struct zc_key k;

    set_default_encryption_keys(&k);

    /* initialize keys with password */
    while (*pw)
        update_keys(*pw++, &k, &k);

    /* decrypt */
    for (size_t i = 0; i < len; ++i) {
        out[i] = in[i] ^ decrypt_byte_tab[(k.key2 & 0xffff) >> 2];
        update_keys(out[i], &k, &k);
    }
}

int inflate_buffer(const unsigned char *in, size_t inlen,
                   unsigned char *out, size_t outlen)
{
    int ret;
    z_stream strm;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = inlen;
    strm.next_in = in;
    ret = inflateInit2(&strm, -MAX_WBITS);
    if (ret != Z_OK)
        return ret;

    do {
        strm.avail_out = outlen;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        switch (ret) {
        case Z_NEED_DICT:
            ret = Z_DATA_ERROR;
        case Z_DATA_ERROR:
        case Z_MEM_ERROR:
            inflateEnd(&strm);
            return ret;
        }
    } while (strm.avail_out == 0);

    /* TODO: test crc? */

    inflateEnd(&strm);
    return ret == Z_STREAM_END ? 0 : -1;
}
