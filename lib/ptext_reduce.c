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

struct reduc_work_unit {
	uint32_t *key2ip1;
	size_t key2ip1_size;
	uint32_t *key2i;
	size_t key2i_size;
	struct list_head list;
};

struct reduce_private {
	uint32_t *key2;
	size_t key2_size;
	pthread_mutex_t mutex;
	pthread_barrier_t barrier;
	size_t nbthreads;
	const struct zc_crk_ptext *ptext;
	struct reduc_work_unit *unit;
};

static void generate_all_key2_bits_31_2(uint32_t *key2, const uint16_t *key2_bits_15_2)
{
	for (int i = 0; i < POW2_16; ++i)
		for (int j = 0; j < 64; ++j)
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
	uint32_t key2i_frag_msb = msb(key2i_frag);
	uint32_t key2im1_bits_31_10 = (key2i_frag << 8) ^ crc_32_invtab[key2i_frag_msb];
	uint32_t key2im1_bits_15_10_rhs = key2im1_bits_31_10 & 0xfc00;
	size_t total = 0;

	for (int i = 0; i < 64; ++i) {
		uint32_t key2im1_bits_15_10_lhs = key2im1_bits_15_2[i] & 0xfc00;

		/*
		 * the left and right hand side share 6 bits in position
		 * [15..10]. See biham & kocher 3.1.
		 */
		if (key2im1_bits_15_10_rhs == key2im1_bits_15_10_lhs) {
			uint32_t key2im1;
			key2im1 = key2im1_bits_31_10 & 0xfffffc00;
			key2im1 |= key2im1_bits_15_2[i];
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
	uint32_t key2i_bits31_8 = (key2i_plus_1 << 8) ^ crc_32_invtab[key2i_plus_1 >> 24];
	uint32_t key2i_bits15_10_rhs = key2i_bits31_8 & common_bits_mask;
	size_t total = 0;

	for (int i = 0; i < 64; ++i) {
		uint32_t key2i_bits15_10_lhs = key2i_bits_15_2[i] & common_bits_mask;

		/*
		 * the left and right hand side share the same 6 bits
		 * in position [15..10]. See biham & kocher 3.1.
		 */
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

static size_t distribute_key2(size_t keys, size_t rem, uint32_t *dst, size_t id,
			      const uint32_t *src)
{
	size_t idx;

	if (!rem)
		idx = keys * id;
	else if (id < rem) {
		keys++;
		idx = keys * id;
	} else
		idx = (keys + 1) * rem + keys * (id - rem);

	memcpy(dst, &src[idx], keys * sizeof(uint32_t));

	return keys;
}

static int do_work_reduce(void *in, struct list_head *list, int id)
{
	struct reduce_private *priv = (struct reduce_private *)in;
	struct reduc_work_unit *unit = list_entry(list, struct reduc_work_unit, list);
	size_t start_index = priv->ptext->text_size - 2, current;

	unit->key2ip1_size =
		distribute_key2(KEY2_ARRAY_LEN / priv->nbthreads,
				KEY2_ARRAY_LEN % priv->nbthreads,
				unit->key2ip1,
				id,
				priv->key2);

	for (size_t i = start_index; ; --i) {
		uint8_t key3i = generate_key3(priv->ptext, i);
		uint8_t key3im1 = generate_key3(priv->ptext, i - 1);
		key2r_compute_next_array(unit->key2ip1,
					 unit->key2ip1_size,
					 unit->key2i,
					 &unit->key2i_size,
					 get_bits_15_2(priv->ptext->bits_15_2, key3i),
					 get_bits_15_2(priv->ptext->bits_15_2, key3im1),
					 i == start_index ? KEY2_MASK_6BITS : KEY2_MASK_8BITS);

		pthread_mutex_lock(&priv->mutex);
		current = priv->key2_size;
		priv->key2_size += unit->key2i_size;
		pthread_mutex_unlock(&priv->mutex);

		memcpy(&priv->key2[current],
		       unit->key2i,
		       unit->key2i_size * sizeof(uint32_t));

		/* wait for results to be available */
		if (pthread_barrier_wait(&priv->barrier) ==
		    PTHREAD_BARRIER_SERIAL_THREAD) {
			/* a single thread will process the key2 array
			   and redistribute results */
			uniq(priv->key2, &priv->key2_size);
			if (i == 12)
				break; /* reduction is done no more bytes to process */
			for (size_t j = 0; j < priv->nbthreads; ++j) {
				priv->unit[j].key2ip1_size =
					distribute_key2(priv->key2_size / priv->nbthreads,
							priv->key2_size % priv->nbthreads,
							priv->unit[j].key2ip1,
							j,
							priv->key2);
			}
			priv->key2_size = 0;
		}

		if (i == 12)
			break; /* reduction is done no more bytes to process */

		/* wait for duplicates to be removed */
		pthread_barrier_wait(&priv->barrier);
	}

	return TPEMORE;
}

static int reduce_private_alloc(struct zc_crk_ptext *ptext,
				struct reduce_private **priv,
				size_t nbthreads)
{
	struct reduce_private *tmp;

	tmp = calloc(1, sizeof(struct reduce_private));
	if (!tmp)
		return -1;

	tmp->ptext = ptext;

	/*
	 * Allocate enough space for the 1st generation of keys along
	 * with the extra keys found for the first plaintext byte
	 * (before calling uniq()).
	 */
	tmp->key2 = calloc(KEY2_ARRAY_LEN * 2, sizeof(uint32_t));
	if (!tmp->key2) {
		free(tmp);
		return -1;
	}

	tmp->unit = calloc(nbthreads, sizeof(struct reduc_work_unit));
	if (!tmp->unit) {
		free(tmp->key2);
		free(tmp);
		return -1;
	}

	pthread_mutex_init(&tmp->mutex, NULL);
	pthread_barrier_init(&tmp->barrier, NULL, nbthreads);
	tmp->nbthreads = nbthreads;

	*priv = tmp;

	return 0;
}

static void reduce_private_dealloc(struct reduce_private *priv)
{
	pthread_barrier_destroy(&priv->barrier);
	pthread_mutex_destroy(&priv->mutex);
	free(priv->unit);
	free(priv->key2);
	free(priv);
}

ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
	uint8_t key3i;
	struct threadpool_ops ops;
	struct reduce_private *priv;
	size_t nbthreads;
	int err = 0;

	nbthreads = threadpool_get_nbthreads(ptext->pool);

	err = reduce_private_alloc(ptext, &priv, nbthreads);
	if (err)
		return err;

	/* first gen key2 (key2ip1) */
	key3i = generate_key3(ptext, ptext->text_size - 1);

	/* store in priv->key2 temporarily */
	generate_all_key2_bits_31_2(priv->key2,
				    get_bits_15_2(ptext->bits_15_2, key3i));

	for (size_t i = 0; i < nbthreads; ++i) {
		priv->unit[i].key2i = calloc(KEY2_ARRAY_LEN, sizeof(uint32_t));
		priv->unit[i].key2ip1 = calloc(KEY2_ARRAY_LEN, sizeof(uint32_t));
	}

	ops.in = priv;
	ops.do_work = do_work_reduce;
	threadpool_set_ops(ptext->pool, &ops);

	threadpool_submit_start(ptext->pool, false);
	for (size_t i = 0; i < nbthreads; ++i)
		threadpool_submit_work(ptext->pool, &priv->unit[i].list);
	threadpool_submit_wait(ptext->pool);

	/*
	 * from here priv->key2 and priv->key2_size contain the final
	 * reduced array of key2 keys.
	 */

	memcpy(&ptext->key2,
	       priv->key2,
	       priv->key2_size * sizeof(uint32_t));
	ptext->key2_size = priv->key2_size;

	for (size_t i = 0; i < nbthreads; ++i) {
		free(priv->unit[i].key2i);
		free(priv->unit[i].key2ip1);
	}

	reduce_private_dealloc(priv);

	return err;
}
