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

#ifndef _LIBZC_PRIVATE_H_
#define _LIBZC_PRIVATE_H_

#include "zc.h"

uint8_t decrypt_header(const uint8_t *buf, struct zc_key *k, uint8_t magic);

bool decrypt_headers(const struct zc_key *k, const struct zc_header *h,
		     size_t len);

size_t threads_to_create(long forced);

void decrypt(const unsigned char *in, unsigned char *out, size_t len,
	     const struct zc_key *key);

#if defined(__AVX2__)
void uint32_qsort_avx2(uint32_t *x, long long n);
#else
void uint32_qsort_portable(uint32_t *x, long long n);
#endif

static inline void uint32_qsort(uint32_t *x, long long n)
{
#if defined(__AVX2__)
	uint32_qsort_avx2(x, n);
#else
	uint32_qsort_portable(x, n);
#endif
}

#endif /* _LIBZC_PRIVATE_H_ */
