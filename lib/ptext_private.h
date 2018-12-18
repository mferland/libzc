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
	const uint8_t *plaintext;
	const uint8_t *ciphertext;
	size_t size;
	struct kvector *key2;
	struct key2r *k2r;
	uint8_t lsbk0_lookup[256][2];
	uint32_t lsbk0_count[256];
	bool found;
	pthread_t found_by;
	long force_threads;
};

#define generate_key3(s, i) (s->plaintext[i] ^ s->ciphertext[i])

/* key dynamic vector helper */
struct kvector {
	uint32_t *buf;
	size_t size;
	size_t capacity;
};
int kalloc(struct kvector **v, size_t init);
void kfree(struct kvector *v);
int kappend(struct kvector *v, uint32_t key);
void kuniq(struct kvector *v);
void ksqueeze(struct kvector *v);
void kempty(struct kvector *v);

#ifdef ENABLE_DEBUG
#include <stdio.h>
void kprint(struct kvector *v, FILE *stream);
#endif

static inline
uint32_t kat(const struct kvector *v, uint32_t index)
{
	return v->buf[index];
}

static inline
void kswap(struct kvector **v1, struct kvector **v2)
{
	struct kvector *t = *v1;
	*v1 = *v2;
	*v2 = t;
}

/* key2 reduction */
struct key2r;
int key2r_new(struct key2r **key2r);
void key2r_free(struct key2r *key2r);
uint16_t *key2r_get_bits_15_2(const struct key2r *key2r, uint8_t key3);
struct kvector *key2r_compute_first_gen(const uint16_t *key2_bits_15_2);
int key2r_compute_single(uint32_t key2i_plus_1,
			 struct kvector *key2i,
			 const uint16_t *key2i_bits_15_2,
			 const uint16_t *key2im1_bits_15_2,
			 uint32_t common_bits_mask);

#endif  /* _PTEXT_PRIVATE_H_ */
