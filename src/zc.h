/*
 *  yazc - ZIP password recovery application
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

#ifndef ZC_H
#define ZC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "crc32.h"

#define MULT           134775813u
#define MULTINV        3645876429u /* modular multiplicative inverse mod2^32 */
#define KEY0           0x12345678
#define KEY1           0x23456789
#define KEY2           0x34567890
#define ENC_HEADER_LEN 12
#define HEADER_MAX     5
#define INFLATE_CHUNK  16384
#define POW2_16        (1 << 16)
#define POW2_24        (1 << 24)

struct zc_header {
	uint8_t buf[ENC_HEADER_LEN];
	uint8_t magic;
};

struct zc_key {
	uint32_t key0;
	uint32_t key1;
	uint32_t key2;
};

static inline uint32_t mask_msb(uint32_t v)
{
	return v & 0xff000000;
}

static inline uint32_t mask_lsb(uint32_t v)
{
	return v & 0x000000ff;
}

static inline uint8_t msb(uint32_t v)
{
	return v >> 24;
}

static inline uint8_t lsb(uint32_t v)
{
	return v & 0xff;
}

static inline void update_keys(uint8_t c, const struct zc_key *ksrc,
			       struct zc_key *kdst)
{
	kdst->key0 = crc32(ksrc->key0, c);
	kdst->key1 = (ksrc->key1 + (kdst->key0 & 0xff)) * MULT + 1;
	kdst->key2 = crc32(ksrc->key2, kdst->key1 >> 24);
}

static inline void set_default_encryption_keys(struct zc_key *k)
{
	k->key0 = KEY0;
	k->key1 = KEY1;
	k->key2 = KEY2;
}

static inline void update_default_keys_from_array(struct zc_key *out,
						  const uint8_t *s, size_t len)
{
	set_default_encryption_keys(out);

	for (size_t i = 0; i < len; ++i)
		update_keys(s[i], out, out);
}

static inline void reset_encryption_keys(const struct zc_key *base,
					 struct zc_key *k)
{
	*k = *base;
}

static inline uint8_t decrypt_byte(uint32_t k)
{
	k |= 2;
	return ((k * (k ^ 1)) >> 8) & 0xff;
}

uint8_t decrypt_header(const uint8_t *buf, struct zc_key *k, uint8_t magic);

bool decrypt_headers(const struct zc_key *k, const struct zc_header *h,
		     size_t len);

void decrypt(const unsigned char *in, unsigned char *out, size_t len,
	     const struct zc_key *key);

size_t threads_to_create(long forced);

#endif /* ZC_H */
