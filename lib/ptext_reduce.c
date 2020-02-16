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

#include <stdlib.h>

#include "ptext_private.h"

#define KEY2_ARRAY_LEN (1 << 22)

static void generate_all_key2_bits_31_2(uint32_t *key2, const uint16_t *key2_bits_15_2)
{
	uint32_t i, j;
	for (i = 0; i < pow2(16); ++i)
		for (j = 0; j < 64; ++j)
			key2[i * 64 + j] = (i << 16) | key2_bits_15_2[j];
}

static uint32_t bits_1_0_key2i(uint32_t key2im1, uint32_t key2i)
{
	uint32_t tmp = key2im1 ^ crc_32_invtab[msb(key2i)];
	tmp = (tmp >> 8) & 0x3;      /* keep only bit 9 and 8 */
	return tmp;
}

static size_t generate_all_key2i_with_bits_1_0(uint32_t *key2i,
					       uint32_t key2i_frag,
					       const uint16_t *key2im1_bits_15_2)

{
	const uint32_t key2im1_bits_31_10 = (key2i_frag << 8) ^ crc_32_invtab[key2i_frag >> 24];
	const uint32_t key2im1_bits_15_10_rhs = key2im1_bits_31_10 & 0xfc00;
	size_t total = 0;

	for (int j = 0; j < 64; ++j) {
		const uint32_t key2im1_bits_15_10_lhs = key2im1_bits_15_2[j] & 0xfc00;

		/* the left and right hand side share 6 bits in position
		   [15..10]. See biham & kocher 3.1. */
		if (key2im1_bits_15_10_rhs == key2im1_bits_15_10_lhs) {
			uint32_t key2im1;
			key2im1 = key2im1_bits_31_10 & 0xfffffc00;
			key2im1 |= key2im1_bits_15_2[j];
			key2i[total++] = key2i_frag | bits_1_0_key2i(key2im1, key2i_frag);
		}
	}

	return total;
}

size_t key2r_compute_single(uint32_t key2i_plus_1,
			    uint32_t *key2i,
			    const uint16_t *key2i_bits_15_2,
			    const uint16_t *key2im1_bits_15_2,
			    uint32_t common_bits_mask)
{
	const uint32_t key2i_bits31_8 = (key2i_plus_1 << 8) ^ crc_32_invtab[key2i_plus_1 >> 24];
	const uint32_t key2i_bits15_10_rhs = key2i_bits31_8 & common_bits_mask;
	size_t total = 0;

	for (uint32_t i = 0; i < 64; ++i) {
		const uint32_t key2i_bits15_10_lhs = key2i_bits_15_2[i] & common_bits_mask;

		/* the left and right hand side share the same 6 bits in
		   position [15..10]. See biham & kocher 3.1. */
		if (key2i_bits15_10_rhs == key2i_bits15_10_lhs) {
			uint32_t key2i_frag;

			/* save 22 most significant bits [31..10] */
			key2i_frag = key2i_bits31_8 & 0xfffffc00;

			/* save bits [15..2] with common 6 bits */
			key2i_frag |= key2i_bits_15_2[i];

			/* save bits [1..0] */
			total += generate_all_key2i_with_bits_1_0(&key2i[total],
								  key2i_frag,
								  key2im1_bits_15_2);
		}
	}

	return total;
}

static size_t key2r_compute_next_array(const uint32_t *key2i_plus_1,
				       size_t key2i_plus_1_size,
				       uint32_t *key2i,
				       const uint16_t *key2i_bits_15_2,
				       const uint16_t *key2im1_bits_15_2,
				       uint32_t common_bits_mask)
{
	size_t total = 0;

	for (size_t i = 0; i < key2i_plus_1_size; ++i)
		total += key2r_compute_single(key2i_plus_1[i],
					      &key2i[total],
					      key2i_bits_15_2,
					      key2im1_bits_15_2,
					      common_bits_mask);

	return total;
}

#define SWAP(x, y) do { typeof(x) SWAP = x; x = y; y = SWAP; } while (0)

ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
	uint8_t key3i, key3im1;
	uint32_t *key2i, *key2ip1;
	size_t key2i_size, key2ip1_size;

	/* first gen key2 (key2ip1) */
	key3i = generate_key3(ptext, ptext->text_size - 1);
	key2ip1 = calloc(KEY2_ARRAY_LEN, sizeof(uint32_t));
	if (!key2ip1)
		return -1;

	generate_all_key2_bits_31_2(key2ip1, get_bits_15_2(ptext->bits_15_2, key3i));
	key2ip1_size = KEY2_ARRAY_LEN;

	/* allocate space for second array (key2i) */
	key2i = calloc(KEY2_ARRAY_LEN, sizeof(uint32_t));
	if (!key2i) {
		free(key2ip1);
		return -1;
	}
	key2i_size = 0;

	/* perform reduction */
	const size_t start_index = ptext->text_size - 2;
	for (size_t i = start_index; i >= 12; --i) {
		key3i = generate_key3(ptext, i);
		key3im1 = generate_key3(ptext, i - 1);
		key2i_size = key2r_compute_next_array(key2ip1,
						      key2ip1_size,
						      key2i,
						      get_bits_15_2(ptext->bits_15_2, key3i),
						      get_bits_15_2(ptext->bits_15_2, key3im1),
						      i == start_index ? KEY2_MASK_6BITS : KEY2_MASK_8BITS);
		uniq(key2i, &key2i_size);
		SWAP(key2i, key2ip1);
		SWAP(key2i_size, key2ip1_size);
	}

	/* note: we swapped key2i and key2i+1 */
	/* resize final array */
	ptext->key2 = realloc(key2ip1, key2ip1_size * sizeof(uint32_t));
	ptext->key2_size = key2ip1_size;
	free(key2i);
	return 0;
}
