/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2021 Marc Ferland
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

#ifndef _INFLATE_H_
#define _INFLATE_H_

#include <stddef.h>
#include <stdint.h>

struct zlib_state;

int inflate_new(struct zlib_state **zlib);

void inflate_destroy(struct zlib_state *zlib);

int inflate_buffer(struct zlib_state *zlib, const unsigned char *in,
		   size_t inlen, unsigned char *out, size_t outlen,
		   uint32_t original_crc);

int test_buffer_crc(const unsigned char *in, size_t inlen,
		    uint32_t original_crc);

#endif /* _INFLATE_H_ */
