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

#include "libzc_private.h"
#include "ptext_private.h"
#include "pool.h"

#define KEY2_ARRAY_LEN (1 << 22)
#define swap(x, y)                  \
	do {                        \
		typeof(x) SWAP = x; \
		x = y;              \
		y = SWAP;           \
	} while (0)

struct reduce_private {
	/*
	 * pointer to raw key2 buffer, multiple pointers to different
	 * part of this buffer are defined below.
	 */
	uint32_t *key2_raw;

	/* key2i buffer used in main loop */
	uint32_t *key2i;
	size_t key2i_size;

	/* key2ip1 buffer used in main loop */
	uint32_t *key2ip1;
	size_t key2ip1_size;

	pthread_mutex_t mutex;

	const struct zc_crk_ptext *ptext;

	/*
	 * key2i worker buffers, each worker uses one buffer. A worker
	 * will use the buffer at index 'id' (see do_work_reduc()).
	 */
	uint32_t **key2i_worker;
};

struct reduc_work_unit {
	const uint16_t *key2i_bits_15_2;
	const uint16_t *key2im1_bits_15_2;
	const uint32_t *key2ip1;	/* keys to process */
	size_t key2ip1_size;		/* number of keys to process */
	uint32_t common_bits_mask;
	struct list_head list;
};

static void generate_all_key2_bits_31_2(uint32_t *key2, const uint16_t *key2_bits_15_2)
{
	for (uint32_t i = 0; i < pow2(16); ++i)
		for (uint32_t j = 0; j < 64; ++j)
			key2[i * 64 + j] = (i << 16) | key2_bits_15_2[j];
}

static uint32_t bits_1_0_key2i(uint32_t key2im1, uint32_t key2i_frag_msb)
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

static int key2r_compute_next_array(struct zc_crk_ptext *ptext,
				    const uint32_t *key2ip1,
				    size_t key2ip1_size,
				    const uint16_t *key2i_bits_15_2,
				    const uint16_t *key2im1_bits_15_2,
				    uint32_t common_bits_mask)
{
	struct reduc_work_unit *u;
	size_t nbthreads = threadpool_get_nbthreads(ptext->pool);
	size_t nbunits = key2ip1_size < nbthreads ? key2ip1_size : nbthreads;
	size_t nbkeys_per_thread = key2ip1_size / nbunits;
	size_t rem = key2ip1_size % nbunits;

	u = calloc(nbunits, sizeof(struct reduc_work_unit));
	if (!u) {
		perror("calloc() failed");
		return -1;
	}

	/* set constants */
	for (size_t i = 0; i < nbunits; ++i) {
		u[i].key2i_bits_15_2 = key2i_bits_15_2;
		u[i].key2im1_bits_15_2 = key2im1_bits_15_2;
		u[i].common_bits_mask = common_bits_mask;
	}

	if (!rem) {
		for (size_t i = 0; i < nbunits; ++i) {
			u[i].key2ip1 = &key2ip1[i * nbkeys_per_thread];
			u[i].key2ip1_size = nbkeys_per_thread;
		}
	} else {
		/* evenly distribute keys to work units */
		size_t total = 0;
		for (size_t i = 0; i < nbunits; ++i) {
			u[i].key2ip1 = &key2ip1[total];
			u[i].key2ip1_size = nbkeys_per_thread;
			total += nbkeys_per_thread;
			if (rem) {
				u[i].key2ip1_size++;
				total++;
				rem--;
			}
		}
	}

	/* submit work */
	threadpool_submit_start(ptext->pool, false);
	for (size_t i = 0; i < nbunits; ++i)
		threadpool_submit_work(ptext->pool, &u[i].list);
	threadpool_submit_wait_idle(ptext->pool);

	free(u);

	return 0;
}

static int do_work_reduc(void *in, struct list_head *list, int id)
{
	struct reduce_private *priv = (struct reduce_private *)in;
	struct reduc_work_unit *unit = list_entry(list, struct reduc_work_unit, list);
	size_t total = 0;

	for (size_t i = 0; i < unit->key2ip1_size; ++i)
		total += key2r_compute_single(unit->key2ip1[i],
					      &priv->key2i_worker[id][total],
					      unit->key2i_bits_15_2,
					      unit->key2im1_bits_15_2,
					      unit->common_bits_mask);

	/*
	 * copy back results to final shared buffer
	 */
	pthread_mutex_lock(&priv->mutex);
	size_t current = priv->key2i_size;
	priv->key2i_size += total;
	pthread_mutex_unlock(&priv->mutex);

	memcpy(&priv->key2i[current], priv->key2i_worker[id], total * sizeof(uint32_t));

	return TPEMORE;
}

static size_t compute_worker_buf_size(size_t nbthreads)
{
	if (nbthreads == 1)
		return KEY2_ARRAY_LEN;
	/*
	 * From B&K: The number of possible values of key2i (i= n-1,
	 * n-2, etc.) remains about 2^22.
	 *
	 * Let's play it safe here and round at the next 4096 multiple
	 * (nice page size number).
	 */
	return ((KEY2_ARRAY_LEN / nbthreads + 1) / 4096 + 2) * 4096;
}

static int reduce_private_alloc(struct zc_crk_ptext *ptext,
				size_t nbthreads,
				struct reduce_private **priv)
{
	/*
	 * key2_raw:
	 * +--------------+
	 * | i |   use    |
	 * |---+----------|
	 * | 0 | key2i    |
	 * | 1 | key2ip1  |
	 * | 2 | key2i_w0 |
	 * | 3 | key2i_w1 |
	 * |...| ...      |
	 * |   | key2i_wn |
	 * +--------------+
	 */
	struct reduce_private *tmp;
	size_t worker_buf_size;

	tmp = calloc(1, sizeof(struct reduce_private));
	if (!tmp)
		return -1;

	worker_buf_size = compute_worker_buf_size(nbthreads);
	tmp->key2_raw = calloc(nbthreads * worker_buf_size + KEY2_ARRAY_LEN * 2,
			       sizeof(uint32_t));
	if (!tmp->key2_raw)
		goto err1;

	tmp->key2i_worker = calloc(nbthreads, sizeof(uint32_t *));
	if (!tmp->key2i_worker)
		goto err2;

	tmp->key2i = &tmp->key2_raw[0];
	tmp->key2ip1 = &tmp->key2_raw[KEY2_ARRAY_LEN];
	tmp->ptext = ptext;

	for (size_t i = 0, j = KEY2_ARRAY_LEN * 2; i < nbthreads; ++i, j += worker_buf_size)
		tmp->key2i_worker[i] = &tmp->key2_raw[j];

	pthread_mutex_init(&tmp->mutex, NULL);

	*priv = tmp;

	return 0;
err2:
	free(tmp->key2_raw);
err1:
	free(tmp);
	return -1;
}

static void reduce_private_dealloc(struct reduce_private *priv)
{
	pthread_mutex_destroy(&priv->mutex);
	free(priv->key2i_worker);
	free(priv->key2_raw);
	free(priv);
}

static int save_final_key2(struct zc_crk_ptext *ptext,
			   struct reduce_private *priv)
{
	/*
	 * save final key2 array -- not using realloc since key2ip1 is
	 * inside a larder malloced block.
	 */
	uint32_t *k = calloc(priv->key2ip1_size, sizeof(uint32_t));
	if (!k)
		return -1;
	memcpy(k, priv->key2ip1, priv->key2ip1_size * sizeof(uint32_t));
	ptext->key2 = k;
	ptext->key2_size = priv->key2ip1_size;
	return 0;
}

ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
	uint8_t key3i;
	struct threadpool_ops ops;
	struct reduce_private *priv;
	size_t nbthreads = threadpool_get_nbthreads(ptext->pool);
	int err = 0;

	err = reduce_private_alloc(ptext, nbthreads, &priv);
	if (err)
		return err;

	/* first gen key2 (key2ip1) */
	key3i = generate_key3(ptext, ptext->text_size - 1);

	generate_all_key2_bits_31_2(priv->key2ip1,
				    get_bits_15_2(ptext->bits_15_2, key3i));
	priv->key2ip1_size = KEY2_ARRAY_LEN;

	ops.in = priv;
	ops.do_work = do_work_reduc;
	threadpool_set_ops(ptext->pool, &ops);

	size_t start_index = ptext->text_size - 2;
	for (size_t i = start_index; i >= 12; --i) {
		key3i = generate_key3(ptext, i);
		uint8_t key3im1 = generate_key3(ptext, i - 1);
		key2r_compute_next_array(ptext,
					 priv->key2ip1,
					 priv->key2ip1_size,
					 get_bits_15_2(ptext->bits_15_2, key3i),
					 get_bits_15_2(ptext->bits_15_2, key3im1),
					 i == start_index ? KEY2_MASK_6BITS : KEY2_MASK_8BITS);
		uniq(priv->key2i, &priv->key2i_size);
		swap(priv->key2i, priv->key2ip1);
		priv->key2ip1_size = priv->key2i_size;
		priv->key2i_size = 0;
	}

	err = save_final_key2(ptext, priv);

	reduce_private_dealloc(priv);

	return err;
}
