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

#include <zlib.h>
#include <stdint.h>

int inflate_buffer(unsigned char *in, size_t inlen,
                   unsigned char *out, size_t outlen,
                   uint32_t original_crc)
{
    int ret;
    z_stream strm;
    uint32_t crc;

    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = inlen;
    strm.next_in = in;

    ret = inflateInit2(&strm, -MAX_WBITS);
    if (ret != Z_OK)
        return ret;

    crc = crc32(0L, Z_NULL, 0);

    do {
        strm.avail_out = outlen;
        strm.next_out = out;
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret < 0) {
            inflateEnd(&strm);
            return -1;
        }
        crc = crc32(crc, out, outlen - strm.avail_out);
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);

    return crc == original_crc ? 0 : -1;
}

int test_buffer_crc(unsigned char *in, size_t inlen,
                    uint32_t original_crc)
{
    uint32_t crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, in, inlen);
    return crc == original_crc ? 0 : -1;
}
