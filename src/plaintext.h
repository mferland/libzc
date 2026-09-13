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

#ifndef PLAINTEXT_H
#define PLAINTEXT_H

#include <stddef.h>
#include <stdint.h>

#include "zc.h"

#define KEY2_MASK_6BITS 0xfc00
#define KEY2_MASK_8BITS 0xff00
#define KEY2_ARRAY_LEN (1 << 22)

struct threadpool;

struct zc_plaintext {
	/* plain and cipher text buffers, both have the same size */
	const uint8_t *plaintext;
	const uint8_t *ciphertext;
	size_t text_size;

	/* key2 bits 15-2 cache */
	const uint16_t *bits_15_2;

	/* key0 LSB lookup table */
	uint8_t lsbk0_lookup[256][4];
	uint8_t lsbk0_count[256];

	struct threadpool *pool;

	/* final reduced key2 buffer */
	uint32_t key2[KEY2_ARRAY_LEN];
	size_t key2_size;
};

#define generate_key3(s, i)	     (s->plaintext[i] ^ s->ciphertext[i])
#define get_bits_15_2(bits_15_2, k3) (&bits_15_2[k3 * 64])

void zc_plaintext_destroy(struct zc_plaintext *ctx);
int zc_plaintext_new(struct zc_plaintext **ctx, long force_threads);
int zc_plaintext_set_text(struct zc_plaintext *ctx, const uint8_t *plaintext,
			  const uint8_t *ciphertext, size_t size);
int zc_plaintext_key2_reduction(struct zc_plaintext *ctx);
size_t zc_plaintext_key2_count(const struct zc_plaintext *ctx);
int zc_plaintext_attack(struct zc_plaintext *ctx, struct zc_key *out_key);
int zc_plaintext_find_internal_rep(const struct zc_key *start_key,
				   const uint8_t *ciphertext, size_t size,
				   struct zc_key *internal_rep);
int zc_plaintext_find_password(struct zc_plaintext *ctx,
			       const struct zc_key *internal_rep, char *out,
			       size_t len);

void uniq(uint32_t *buf, size_t *n);

size_t key2r_compute_single(uint32_t key2i_plus_1, uint32_t *key2i,
			    const uint16_t *key2i_bits_15_2,
			    const uint16_t *key2im1_bits_15_2,
			    uint32_t common_bits_mask);

#endif /* PLAINTEXT_H */
