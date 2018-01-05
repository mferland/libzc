/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2018 Marc Ferland
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
#include <string.h>
#include <stdlib.h>

struct zlib_state {
	z_stream s;
};

/* to silence compiler warnings about missing prototypes */
int inflate_new(struct zlib_state **zlib);
void inflate_destroy(struct zlib_state *zlib);
int inflate_buffer(struct zlib_state *zlib,
		   unsigned char *in, size_t inlen,
		   unsigned char *out, size_t outlen,
		   uint32_t original_crc);
int test_buffer_crc(unsigned char *in, size_t inlen,
		    uint32_t original_crc);

int inflate_new(struct zlib_state **zlib)
{
	struct zlib_state *tmp;

	tmp = calloc(1, sizeof(struct zlib_state));
	if (!tmp)
		return -1;

	tmp->s.zalloc = Z_NULL;
	tmp->s.zfree = Z_NULL;
	tmp->s.opaque = Z_NULL;
	if (inflateInit2(&tmp->s, -MAX_WBITS) != Z_OK) {
		free(tmp);
		return -1;
	}

	*zlib = tmp;
	return 0;
}

void inflate_destroy(struct zlib_state *zlib)
{
	inflateEnd(&zlib->s);
	free(zlib);
}

int inflate_buffer(struct zlib_state *zlib,
		   unsigned char *in, size_t inlen,
		   unsigned char *out, size_t outlen,
		   uint32_t original_crc)
{
	int ret;
	uint32_t crc;

	zlib->s.avail_in = inlen;
	zlib->s.next_in = in;

	crc = crc32(0L, Z_NULL, 0);

	do {
		zlib->s.avail_out = outlen;
		zlib->s.next_out = out;
		ret = inflate(&zlib->s, Z_NO_FLUSH);
		if (ret < 0) {
			inflateReset(&zlib->s);
			return -1;
		}
		crc = crc32(crc, out, outlen - zlib->s.avail_out);
	} while (ret != Z_STREAM_END);

	inflateReset(&zlib->s);

	return crc == original_crc ? 0 : -1;
}

int test_buffer_crc(unsigned char *in, size_t inlen,
		    uint32_t original_crc)
{
	uint32_t crc = crc32(0L, Z_NULL, 0);
	crc = crc32(crc, in, inlen);
	return crc == original_crc ? 0 : -1;
}
