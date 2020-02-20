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

#ifndef _PTEXT_PRIVATE_H_
#define _PTEXT_PRIVATE_H_

#include <pthread.h>
#include <stdint.h>

#include "libzc.h"
#include "libzc_private.h"

#define KEY2_MASK_6BITS 0xfc00
#define KEY2_MASK_8BITS 0xff00

struct zc_crk_ptext {
	struct zc_ctx *ctx;
	int refcount;

	/* plain and cipher text buffers, both have the same size */
	const uint8_t *plaintext;
	const uint8_t *ciphertext;
	size_t text_size;

	uint16_t *bits_15_2;
	uint8_t lsbk0_lookup[256][4];
	uint8_t lsbk0_count[256];
	bool found;
	pthread_t found_by;
	long force_threads;

	/* reduced key2 buffer */
	uint32_t *key2;
	size_t key2_size;
};

#define generate_key3(s, i) (s->plaintext[i] ^ s->ciphertext[i])
#define get_bits_15_2(bits_15_2, k3) (&bits_15_2[k3 * 64])

void uniq(uint32_t *buf, size_t *n);

size_t key2r_compute_single(uint32_t key2i_plus_1,
			    uint32_t *key2i,
			    const uint16_t *key2i_bits_15_2,
			    const uint16_t *key2im1_bits_15_2,
			    uint32_t common_bits_mask);

#endif  /* _PTEXT_PRIVATE_H_ */
