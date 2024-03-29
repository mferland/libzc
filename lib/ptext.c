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

/*
 * References:
 * http://en.wikipedia.org/wiki/Modular_multiplicative_inverse
 * http://ca.wiley.com/WileyCDA/WileyTitle/productCd-047011486X.html
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libzc_private.h"
#include "ptext_private.h"
#include "pool.h"

static inline void lsbk0_set(struct zc_crk_ptext *p, uint8_t msb, uint8_t mul)
{
	/*    \  List of multiples (up to 4) that
	 * msb \ match with the msb or (msb - 1)
	 *      +-----+-----+-----+-----+
	 * 00   | mul | mul | mul | mul |
	 * 01   | mul | mul | mul | mul |
	 * 02   | mul | mul | mul | mul |
	 * 03   | mul | mul | mul | mul |
	 * ..   | ... | ... | ... | ... |
	 * ff   | mul | mul | mul | mul |
	 *      +-----+-----+-----+-----+
	 *
	 * See Biham & Kocher section 3.3
	 */
	uint8_t nextmsb = (msb + 1) % 256;
	p->lsbk0_lookup[msb][p->lsbk0_count[msb]++] = mul;
	p->lsbk0_lookup[nextmsb][p->lsbk0_count[nextmsb]++] = mul;
}

static void generate_key0_lsb(struct zc_crk_ptext *ptext)
{
	/* reset lookup and counters to 0 */
	memset(ptext->lsbk0_count, 0, 256 * sizeof(uint8_t));
	memset(ptext->lsbk0_lookup, 0, 256 * 4 * sizeof(uint8_t));

	for (int i = 0, p = 0; i < 256; ++i, p += MULTINV)
		lsbk0_set(ptext, msb(p), i);
}

static void bits_15_2_from_key3(uint16_t *value, uint8_t key3)
{
	uint32_t valuei = 0;
	for (uint32_t i = 0; i < POW2_16; i += 4) {
		uint8_t key3tmp = ((i | 2) * (i | 3)) >> 8;
		if (key3 == key3tmp) {
			value[valuei] = i;
			++valuei;
		}
	}
}

static int generate_key2_bits_15_2(struct zc_crk_ptext *ptext)
{
	uint16_t *tmp = malloc(256 * 64 * sizeof(uint16_t));
	if (!tmp)
		return -1;

	for (size_t key3 = 0; key3 < 256; ++key3)
		bits_15_2_from_key3(&tmp[key3 * 64], key3);

	ptext->bits_15_2 = tmp;

	return 0;
}

ZC_EXPORT struct zc_crk_ptext *zc_crk_ptext_ref(struct zc_crk_ptext *ptext)
{
	if (!ptext)
		return NULL;
	ptext->refcount++;
	return ptext;
}

ZC_EXPORT struct zc_crk_ptext *zc_crk_ptext_unref(struct zc_crk_ptext *ptext)
{
	if (!ptext)
		return NULL;
	ptext->refcount--;
	if (ptext->refcount > 0)
		return ptext;
	dbg(ptext->ctx, "ptext %p released\n", ptext);
	threadpool_destroy(ptext->pool);
	free((void *)ptext->bits_15_2);
	free(ptext);
	return NULL;
}

ZC_EXPORT int zc_crk_ptext_new(struct zc_ctx *ctx, struct zc_crk_ptext **ptext,
			       long force_threads)
{
	struct zc_crk_ptext *new;

	new = calloc(1, sizeof(struct zc_crk_ptext));
	if (!new)
		return -1;

	if (threadpool_new(&new->pool, force_threads))
		goto err1;

	if (generate_key2_bits_15_2(new))
		goto err2;

	generate_key0_lsb(new);
	new->ctx = ctx;
	new->refcount = 1;

	*ptext = new;

	dbg(ctx, "ptext %p created\n", new);

	return 0;

err2:
	threadpool_destroy(new->pool);
err1:
	free(new);
	return -1;
}

ZC_EXPORT int zc_crk_ptext_set_text(struct zc_crk_ptext *ptext,
				    const uint8_t *plaintext,
				    const uint8_t *ciphertext, size_t size)
{
	if (size < 13)
		return -1;

	ptext->plaintext = plaintext;
	ptext->ciphertext = ciphertext;
	ptext->text_size = size;

	return 0;
}

ZC_EXPORT size_t zc_crk_ptext_key2_count(const struct zc_crk_ptext *ptext)
{
	return ptext->key2_size;
}
