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

#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crc32.h"
#include "libzc_private.h"
#include "list.h"
#include "ptext_private.h"
#include "pool.h"

#define k2(index) priv->key2_final[index]
#define k1(index) priv->key1_final[index]
#define k0(index) priv->key0_final[index]
#define plaintext(index) priv->ptext->plaintext[index]
#define cipher(index) priv->ptext->ciphertext[index]
#define lsbk0_lookup(index) priv->ptext->lsbk0_lookup[index]
#define lsbk0_count(index) priv->ptext->lsbk0_count[index]

#define KEY2_GEN_MAX 64		/* The maximum number of keys we could
				 * generate from a single key2 */

struct attack_private {
	uint32_t key2_final[13];
	uint32_t key1_final[13];
	uint32_t key0_final[13];
	uint32_t key2[12][KEY2_GEN_MAX];
	size_t key2_size[12];
	const struct zc_crk_ptext *ptext;
	bool found;
	pthread_t found_by;
	struct zc_key *inter_rep;
};

struct attack_work_unit {
	const uint32_t *key2_final;
	size_t key2_final_size;
	struct zc_key inter_rep;
	bool found;
	struct list_head list;
};

static void key2_uniq(struct attack_private *priv, size_t i)
{
	uniq(priv->key2[i], &priv->key2_size[i]);
}

static void key2_reset(struct attack_private *priv, size_t i)
{
	priv->key2_size[i] = 0;
}

static uint32_t *key2_get_arr(struct attack_private *priv, size_t i)
{
	return priv->key2[i];
}

static uint32_t key2_get_key(struct attack_private *priv, size_t i, size_t j)
{
	return priv->key2[i][j];
}

static void key2_set_size(struct attack_private *priv, size_t i, size_t size)
{
	priv->key2_size[i] = size;
}

static size_t key2_get_size(struct attack_private *priv, size_t i)
{
	return priv->key2_size[i];
}

static void compute_one_intermediate_int_rep(uint8_t cipher, uint8_t *plaintext,
					     struct zc_key *k)
{
	k->key2 = crc32inv(k->key2, msb(k->key1));
	k->key1 = ((k->key1 - 1) * MULTINV) - lsb(k->key0);
	uint32_t tmp = k->key2 | 3;
	uint32_t key3 = lsb((tmp * (tmp ^ 1)) >> 8);
	*plaintext = cipher ^ key3;
	k->key0 = crc32inv(k->key0, *plaintext);
}

static int compute_intermediate_internal_rep(struct attack_private *priv,
					     struct zc_key *k)
{
	uint32_t i = 4;

	k->key2 = k2(i);
	k->key1 = k1(i);
	/* key0 is already set */

	do {
		uint8_t p;
		compute_one_intermediate_int_rep(cipher(i - 1), &p, k);
		if (p != plaintext(i - 1))
			break;
		--i;
	} while (i > 0);

	if (i == 0) {
		*priv->inter_rep = *k;
		return 0;
	}
	return -1;
}

static bool verify_key0(const struct attack_private *priv, uint32_t key0,
			uint32_t start, uint32_t stop)
{
	for (uint32_t i = start; i < stop; ++i) {
		key0 = crc32(key0, plaintext(i));
		if (mask_lsb(key0) != k0(i + 1))
			return false;
	}
	return true;
}

static void key_found(struct attack_private *priv)
{
	priv->found = true;
	priv->found_by = pthread_self();
}

static void compute_key0(struct attack_private *priv)
{
	struct zc_key k = { .key0 = 0x0, .key1 = 0x0, .key2 = 0x0 };

	/* calculate key0_6{0..15} */
	k.key0 = (k0(7) ^ crc_32_tab[k0(6) ^ plaintext(6)]) << 8;
	k.key0 = (k.key0 | k0(6)) & 0x0000ffff;

	/* calculate key0_5{0..23} */
	k.key0 = (k.key0 ^ crc_32_tab[k0(5) ^ plaintext(5)]) << 8;
	k.key0 = (k.key0 | k0(5)) & 0x00ffffff;

	/* calculate key0_4{0..31} */
	k.key0 = (k.key0 ^ crc_32_tab[k0(4) ^ plaintext(4)]) << 8;
	k.key0 = (k.key0 | k0(4));

	/* verify against known bytes */
	if (!verify_key0(priv, k.key0, 4, 12))
		return;

	if (compute_intermediate_internal_rep(priv, &k) == 0)
		key_found(priv);
}

static void recurse_key1(struct attack_private *priv, uint32_t current_idx)
{
	if (current_idx == 3) {
		compute_key0(priv);
		return;
	}

	uint32_t key1i = k1(current_idx);
	uint32_t rhs_step1 = (key1i - 1) * MULTINV;
	uint32_t rhs_step2 = (rhs_step1 - 1) * MULTINV;
	uint8_t diff = msb(rhs_step2 - (mask_msb(k1(current_idx - 2))));

	/*
	 * The difference between rhs_step2 and k1(current_idx - 2)
	 * (which has a valid msb) is a multiple (between 0 and 255,
	 * the value of lsb(key0)) of MULTINV.
	 *
	 * Use the lookup table with the difference of MSBs to find
	 * the actual multiple (the value of lsb(key0)). Also note
	 * that the difference between the MSBs has two possible
	 * values. For example:
	 *
	 * key1i: 0xa067359a
	 * rhs_step1: 0x69095385
	 * rhs_step2: 0xe50280b4
	 * diff: 0x12
	 * mask_msb(k1(current_idx - 2)): 0xd2000000
	 *
	 * 0xe50280b4 - 0xd2000000 = 0x130280b4 --> msb --> 0x13 (lsb0: 0xc6)
	 * 0xe50280b4 - 0xd2ffffff = 0x120280B5 --> msb --> 0x12 (lsb0: 0x1a, 0x70)
	 *
	 * LSBs to test: 0xc6, 0x1a, 0x70
	 *
	 * rhs_step1 - 0xc6 = 0x690952bf
	 * rhs_step1 - 0x1a = 0x6909536b
	 * rhs_step1 - 0x70 = 0x69095315
	 *
	 * 0x69095315 + 0x70 = (0xa067359a - 1) * 3645876429u
	 *
	 */

	for (uint8_t i = 0; i < lsbk0_count(diff); ++i) {
		uint32_t lsbkey0i = lsbk0_lookup(diff)[i];
		if (mask_msb(rhs_step1 - lsbkey0i) == mask_msb(k1(current_idx - 1))) {
			priv->key1_final[current_idx - 1] = rhs_step1 - lsbkey0i;
			priv->key0_final[current_idx] = lsbkey0i;
			recurse_key1(priv, current_idx - 1);
		}
	}
}

static void compute_key1(struct attack_private *priv)
{
	/* find matching msb, section 3.3 from Biham & Kocher */
	for (uint32_t i = 0; i < POW2_24; ++i) {
		const uint32_t key1_12_tmp = mask_msb(k1(12)) | i;
		const uint32_t key1_11_tmp = (key1_12_tmp - 1) * MULTINV;
		if (mask_msb(key1_11_tmp) == mask_msb(k1(11))) {
			priv->key1_final[12] = key1_12_tmp;
			recurse_key1(priv, 12);
		}
	}
}

static uint32_t compute_key1_msb(struct attack_private *priv,
				 uint32_t current_idx)
{
	const uint32_t key2i = k2(current_idx);
	const uint32_t key2im1 = k2(current_idx - 1);
	return (key2i << 8) ^ crc_32_invtab[key2i >> 24] ^ key2im1;
}

static void recurse_key2(struct attack_private *priv, uint32_t current_idx)
{
	uint8_t key3im1;
	uint8_t key3im2;

	if (current_idx == 1) {
		compute_key1(priv);
		return;
	}

	key3im1 = generate_key3(priv->ptext, current_idx - 1);
	key3im2 = generate_key3(priv->ptext, current_idx - 2);

	/* empty array before appending new keys */
	key2_reset(priv, current_idx - 1);

	size_t s = key2r_compute_single(k2(current_idx),
					key2_get_arr(priv, current_idx - 1),
					get_bits_15_2(priv->ptext->bits_15_2, key3im1),
					get_bits_15_2(priv->ptext->bits_15_2, key3im2),
					KEY2_MASK_8BITS);
	key2_set_size(priv, current_idx - 1, s);

	assert(s <= 64);

	key2_uniq(priv, current_idx - 1);

	for (size_t i = 0; i < key2_get_size(priv, current_idx - 1); ++i) {
		priv->key2_final[current_idx - 1] = key2_get_key(priv, current_idx - 1, i);
		priv->key1_final[current_idx] = compute_key1_msb(priv, current_idx) << 24;
		recurse_key2(priv, current_idx - 1);
	}
}

static int do_work_attack(void *in, struct list_head *list, int id)
{
	struct attack_work_unit *unit = list_entry(list, struct attack_work_unit, list);
	struct attack_private priv;
	(void)id;

	priv.ptext = in;
	priv.inter_rep = &unit->inter_rep;
	priv.found = false;

	for (size_t i = 0; i < unit->key2_final_size; ++i) {
		priv.key2_final[12] = unit->key2_final[i];
		recurse_key2(&priv, 12);
		if (priv.found) {
			unit->found = true;
			/* key found cancel siblings */
			return TPECANCELSIBLINGS;
		}
	}

	/* all units processed, key not found */
	return TPEEXIT;
}

ZC_EXPORT int zc_crk_ptext_attack(struct zc_crk_ptext *ptext,
				  struct zc_key *out_key)
{
	size_t nbthreads = threadpool_get_nbthreads(ptext->pool);
	size_t nbunits = ptext->key2_size < nbthreads ? ptext->key2_size : nbthreads;
	size_t nbkeys_per_thread = ptext->key2_size / nbunits;
	size_t rem = ptext->key2_size % nbunits;
	struct threadpool_ops ops;
	int err = -1;

	ops.in = ptext;
	ops.do_work = do_work_attack;
	threadpool_set_ops(ptext->pool, &ops);

	struct attack_work_unit *u = calloc(nbunits, sizeof(struct attack_work_unit));
	if (!u) {
		perror("calloc() failed");
		return -1;
	}

	if (!rem) {
		for (size_t i = 0; i < nbunits; ++i) {
			u[i].key2_final = &ptext->key2[i * nbkeys_per_thread];
			u[i].key2_final_size = nbkeys_per_thread;
		}
	} else {
		size_t total = 0;
		for (size_t i = 0; i < nbunits; ++i) {
			u[i].key2_final = &ptext->key2[total];
			u[i].key2_final_size = nbkeys_per_thread;
			total += nbkeys_per_thread;
			if (rem) {
				u[i].key2_final_size++;
				total++;
				rem--;
			}
		}
	}

	threadpool_submit_start(ptext->pool, true);
	for (size_t i = 0; i < nbunits; ++i)
		threadpool_submit_work(ptext->pool, &u[i].list);
	threadpool_submit_wait(ptext->pool);

	for (size_t i = 0; i < nbunits; ++i) {
		if (u[i].found) {
			*out_key = u[i].inter_rep;
			err = 0;
			break;
		}
	}

	free(u);

	return err;
}

ZC_EXPORT int zc_crk_ptext_find_internal_rep(const struct zc_key *start_key,
					     const uint8_t *ciphertext,
					     size_t size,
					     struct zc_key *internal_rep)
{
	struct zc_key k;
	uint32_t i;

	/* the cipher text also includes the 12 prepended bytes */
	if (size < 12)
		return -1;

	i = size - 1;
	k = *start_key;
	do {
		uint8_t p;
		compute_one_intermediate_int_rep(ciphertext[i], &p, &k);
	} while (i--);

	*internal_rep = k;
	return 0;
}
