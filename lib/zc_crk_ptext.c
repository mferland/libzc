/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2017 Marc Ferland
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

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include "ptext_private.h"

static void generate_key0lsb(struct zc_crk_ptext *ptext)
{
	/* reset lsb counters to 0 */
	memset(ptext->lsbk0_count, 0, 256 * sizeof(uint32_t));

	for (uint32_t i = 0, p = 0; i < 256; ++i, p += MULTINV) {
		uint8_t msbp = msb(p);
		ptext->lsbk0_lookup[msbp][ptext->lsbk0_count[msbp]++] = i;
	}
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
	ka_free(ptext->key2);
	key2r_free(ptext->k2r);
	free(ptext);
	return NULL;
}

ZC_EXPORT int zc_crk_ptext_new(struct zc_ctx *ctx, struct zc_crk_ptext **ptext)
{
	struct zc_crk_ptext *new;

	new = calloc(1, sizeof(struct zc_crk_ptext));
	if (!new)
		return -1;

	if (key2r_new(&new->k2r)) {
		free(new);
		return -1;
	}

	generate_key0lsb(new);
	new->ctx = ctx;
	new->refcount = 1;
	new->found = false;
	new->force_threads = -1;
	*ptext = new;

	dbg(ctx, "ptext %p created\n", new);

	return 0;
}

ZC_EXPORT int zc_crk_ptext_set_text(struct zc_crk_ptext *ptext,
				    const uint8_t *plaintext,
				    const uint8_t *ciphertext,
				    size_t size)
{
	if (size < 13)
		return -1;

	ptext->plaintext = plaintext;
	ptext->ciphertext = ciphertext;
	ptext->size = size;

	return 0;
}

ZC_EXPORT size_t zc_crk_ptext_key2_count(const struct zc_crk_ptext *ptext)
{
	if (ptext->key2)
		return ptext->key2->size;
	return 0;
}
