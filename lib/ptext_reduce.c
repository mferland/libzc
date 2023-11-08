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

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>

#include "libzc_private.h"
#include "ptext_private.h"
#include "pool.h"

#define swap(x, y)                  \
	do {                        \
		typeof(x) SWAP = x; \
		x = y;              \
		y = SWAP;           \
	} while (0)

struct reduce_private {
	/* key2 buffer to accumulate final results */
	uint32_t *key2;
	size_t key2_size;
	pthread_mutex_t	mutex;
	const struct zc_crk_ptext *ptext;
};

struct reduc_work_unit {
	uint32_t *key2ip1;
	size_t key2ip1_size;
	uint32_t *key2i;
	size_t key2i_size;
	struct list_head list;
};

static void generate_all_key2_bits_31_2(uint32_t *key2, const uint16_t *key2_bits_15_2)
{
	for (uint32_t i = 0; i < pow2(16); ++i)
		for (uint32_t j = 0; j < 64; ++j)
			key2[i * 64 + j] = (i << 16) | key2_bits_15_2[j];
}

static inline uint32_t bits_1_0_key2i(uint32_t key2im1, uint32_t key2i_frag_msb)
{
	uint32_t tmp = key2im1 ^ crc_32_invtab[key2i_frag_msb];
	return (tmp >> 8) & 0x3;      /* keep only bit 9 and 8 */
}

static size_t generate_all_key2i_with_bits_1_0(uint32_t *key2i,
					       uint32_t key2i_frag,
					       const uint16_t *key2im1_bits_15_2)
{
	const uint32_t key2i_frag_msb = msb(key2i_frag);
	const uint32_t key2im1_bits_31_10 = (key2i_frag << 8) ^ crc_32_invtab[key2i_frag_msb];
	const uint32_t key2im1_bits_15_10_rhs = key2im1_bits_31_10 & 0xfc00;
	size_t total = 0;

	for (int j = 0; j < 64; ++j) {
		const uint32_t key2im1_bits_15_10_lhs = key2im1_bits_15_2[j] & 0xfc00;

		/*
		 * the left and right hand side share 6 bits in position
		 * [15..10]. See biham & kocher 3.1.
		 */
		if (key2im1_bits_15_10_rhs == key2im1_bits_15_10_lhs) {
			uint32_t key2im1;
			key2im1 = key2im1_bits_31_10 & 0xfffffc00;
			key2im1 |= key2im1_bits_15_2[j];
			key2i[total++] = key2i_frag | bits_1_0_key2i(key2im1, key2i_frag_msb);
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

static void key2r_compute_next_array(const uint32_t *key2ip1,
				     size_t key2ip1_size,
				     uint32_t *key2i,
				     size_t *key2i_size,
				     const uint16_t *key2i_bits_15_2,
				     const uint16_t *key2im1_bits_15_2,
				     uint32_t common_bits_mask)
{
	size_t total = 0;

	for (size_t i = 0; i < key2ip1_size; ++i)
		total += key2r_compute_single(key2ip1[i],
					      &key2i[total],
					      key2i_bits_15_2,
					      key2im1_bits_15_2,
					      common_bits_mask);

	*key2i_size = total;
}

static int do_work_reduce(void *in, struct list_head *list, int id)
{
	struct reduce_private *priv = (struct reduce_private *)in;
	struct reduc_work_unit *unit = list_entry(list, struct reduc_work_unit, list);
	size_t start_index = priv->ptext->text_size - 2, current;

	(void) id;

	for (size_t i = start_index; i >= 12; --i) {
		uint8_t key3i = generate_key3(priv->ptext, i);
		uint8_t key3im1 = generate_key3(priv->ptext, i - 1);
		key2r_compute_next_array(unit->key2ip1,
					 unit->key2ip1_size,
					 unit->key2i,
					 &unit->key2i_size,
					 get_bits_15_2(priv->ptext->bits_15_2, key3i),
					 get_bits_15_2(priv->ptext->bits_15_2, key3im1),
					 i == start_index ? KEY2_MASK_6BITS : KEY2_MASK_8BITS);
		uniq(unit->key2i, &unit->key2i_size);
		swap(unit->key2i, unit->key2ip1);
		unit->key2ip1_size = unit->key2i_size;
		unit->key2i_size = 0;
	}

	/* copy final results to shared buffer */
	pthread_mutex_lock(&priv->mutex);
	current = priv->key2_size;
	priv->key2_size += unit->key2ip1_size;
	pthread_mutex_unlock(&priv->mutex);

	memcpy(&priv->key2[current],
	       unit->key2ip1,
	       unit->key2ip1_size * sizeof(uint32_t));

	return TPEMORE;
}

static int reduce_private_alloc(struct zc_crk_ptext *ptext,
				struct reduce_private **priv)
{
	struct reduce_private *tmp;

	tmp = calloc(1, sizeof(struct reduce_private));
	if (!tmp)
		return -1;

	tmp->ptext = ptext;

	tmp->key2 = calloc(KEY2_ARRAY_LEN, sizeof(uint32_t));
	if (!tmp->key2) {
		free(tmp);
		return -1;
	}

	pthread_mutex_init(&tmp->mutex, NULL);

	*priv = tmp;

	return 0;
}

static void reduce_private_dealloc(struct reduce_private *priv)
{
	pthread_mutex_destroy(&priv->mutex);
	free(priv->key2);
	free(priv);
}

ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
	uint8_t key3i;
	struct threadpool_ops ops;
	struct reduce_private *priv;
	struct reduc_work_unit *u;
	size_t nbthreads, nbkeys_per_thread, rem;
	int err = 0;

	nbthreads = threadpool_get_nbthreads(ptext->pool);
	nbkeys_per_thread = KEY2_ARRAY_LEN / nbthreads;
	rem = KEY2_ARRAY_LEN % nbthreads;

	err = reduce_private_alloc(ptext, &priv);
	if (err)
		return err;

	/* first gen key2 (key2ip1) */
	key3i = generate_key3(ptext, ptext->text_size - 1);

	/* store in priv->key2 temporarily */
	generate_all_key2_bits_31_2(priv->key2,
				    get_bits_15_2(ptext->bits_15_2, key3i));

	u = calloc(nbthreads, sizeof(struct reduc_work_unit));
	if (!u) {
		perror("calloc() failed");
		return -1;
	}

	for (size_t i = 0; i < nbthreads; ++i) {
		u[i].key2i = malloc(KEY2_ARRAY_LEN * sizeof(uint32_t));
		u[i].key2ip1 = malloc(KEY2_ARRAY_LEN * sizeof(uint32_t));
	}

	if (!rem) {
		for (size_t i = 0; i < nbthreads; ++i) {
			memcpy(u[i].key2ip1,
			       &priv->key2[i * nbkeys_per_thread],
			       nbkeys_per_thread * sizeof(uint32_t));
			u[i].key2ip1_size = nbkeys_per_thread;
		}
	} else {
		size_t total = 0;
		for (size_t i = 0; i < nbthreads; ++i) {
			if (rem) {
				memcpy(u[i].key2ip1,
				       &priv->key2[total],
				       (nbkeys_per_thread + 1) * sizeof(uint32_t));
				u[i].key2ip1_size = nbkeys_per_thread + 1;
				total++;
				rem--;
			} else {
				memcpy(u[i].key2ip1,
				       &priv->key2[total],
				       nbkeys_per_thread * sizeof(uint32_t));
				u[i].key2ip1_size = nbkeys_per_thread;
			}
			total += nbkeys_per_thread;
		}
	}

	ops.in = priv;
	ops.do_work = do_work_reduce;
	threadpool_set_ops(ptext->pool, &ops);

	threadpool_submit_start(ptext->pool, false);
	for (size_t i = 0; i < nbthreads; ++i)
		threadpool_submit_work(ptext->pool, &u[i].list);
	threadpool_submit_wait(ptext->pool);

	uniq(priv->key2, &priv->key2_size);
	memcpy(&ptext->key2,
	       priv->key2,
	       priv->key2_size * sizeof(uint32_t));
	ptext->key2_size = priv->key2_size;

	for (size_t i = 0; i < nbthreads; ++i) {
		free(u[i].key2i);
		free(u[i].key2ip1);
	}
	free(u);

	reduce_private_dealloc(priv);

	return err;
}
