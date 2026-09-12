/*
 *  yazc - ZIP password recovery application
 *  Copyright (C) 2012-2020 Marc Ferland
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

#include <stddef.h>
#include "decrypt_byte.h"
#include "zc.h"

void decrypt(const unsigned char *in, unsigned char *out, size_t len,
	     const struct zc_key *key)
{
	struct zc_key k = *key;

	for (size_t i = 0; i < len - 1; ++i) {
		out[i] = in[i] ^ decrypt_byte_lookup(k.key2);
		update_keys(out[i], &k, &k);
	}

	out[len - 1] = in[len - 1] ^ decrypt_byte_lookup(k.key2);
}

uint8_t decrypt_header(const uint8_t *buf, struct zc_key *k, uint8_t magic)
{
	for (size_t i = 0; i < ENC_HEADER_LEN - 1; ++i) {
		uint8_t c = buf[i] ^ decrypt_byte_lookup(k->key2);
		update_keys(c, k, k);
	}

	/* Returns the last byte of the decrypted header */
	return buf[ENC_HEADER_LEN - 1] ^ decrypt_byte_lookup(k->key2) ^ magic;
}

bool decrypt_headers(const struct zc_key *k, const struct zc_header *h,
		     size_t len)
{
	struct zc_key tmp;

	for (size_t i = 0; i < len; ++i) {
		reset_encryption_keys(k, &tmp);
		if (decrypt_header(h[i].buf, &tmp, h[i].magic))
			return false;
	}

	return true;
}

#ifdef WIN32

size_t threads_to_create(long forced)
{
	if (forced > 0)
		return forced;
	return 1; /* best effort on windows */
}

#else

#include <unistd.h>

size_t threads_to_create(long forced)
{
	if (forced > 0)
		return forced;
	long n = sysconf(_SC_NPROCESSORS_ONLN);
	if (n < 1)
		return 1;
	return n;
}

#endif
