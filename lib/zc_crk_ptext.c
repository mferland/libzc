/*
 *  zc - zip crack library
 *  Copyright (C) 2013  Marc Ferland
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
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

#include "libzc.h"
#include "libzc_private.h"
#include "crc32.h"
#include "key_table.h"
#include "key2_reduce.h"

#define k2(index) ptext->key2_final[index]
#define k1(index) ptext->key1_final[index]
#define k0(index) ptext->key0_final[index]
#define cipher(index) ptext->ciphertext[index]
#define plaintext(index) ptext->plaintext[index]

struct zc_crk_ptext
{
   struct zc_ctx *ctx;
   int refcount;
   uint8_t *plaintext;
   uint8_t *ciphertext;
   size_t size;
   struct key_table *key2;
   struct key2r *k2r;
   uint32_t key2_final[13];
   uint32_t key1_final[13];
   uint32_t key0_final[13];
   uint32_t key1_lookup[65538];
   uint32_t key1_lookup_size;
   uint8_t lsbk0_lookup[256][2];
   uint32_t lsbk0_count[256];
   bool key_found;
};

static uint8_t generate_key3(const struct zc_crk_ptext *ptext, uint32_t i)
{
   return (plaintext(i) ^ cipher(i));
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
   free(ptext->plaintext);
   free(ptext->ciphertext);
   key_table_free(ptext->key2);
   key2r_free(ptext->k2r);
   free(ptext);
   return NULL;
}

ZC_EXPORT int zc_crk_ptext_new(struct zc_ctx *ctx, struct zc_crk_ptext **ptext)
{
   struct zc_crk_ptext *new;
   int err;

   new = calloc(1, sizeof(struct zc_crk_ptext));
   if (!new)
      return ENOMEM;

   err = key2r_new(&new->k2r);
   if (err)
   {
      free(new);
      return ENOMEM;
   }

   new->ctx = ctx;
   new->refcount = 1;
   new->key_found = false;
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
      return EINVAL;

   if (ptext->plaintext)
   {
      free(ptext->plaintext);
      ptext->plaintext = NULL;
   }

   if (ptext->ciphertext)
   {
      free(ptext->ciphertext);
      ptext->plaintext = NULL;
   }

   ptext->plaintext = malloc(size);
   if (ptext->plaintext == NULL)
      return ENOMEM;

   ptext->ciphertext = malloc(size);
   if (ptext->ciphertext == NULL)
   {
      free(ptext->plaintext);
      ptext->plaintext = NULL;
      return ENOMEM;
   }

   memcpy(ptext->plaintext, plaintext, size);
   memcpy(ptext->ciphertext, ciphertext, size);
   ptext->size = size;

   return 0;
}

ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
   struct key_table *key2i_plus_1;
   struct key_table *key2i;
   uint8_t key3i;
   uint8_t key3im1;
   int err;

   /* first gen key2 */
   key3i = generate_key3(ptext, ptext->size - 1);
   key2i_plus_1 = key2r_compute_first_gen(key2r_get_bits_15_2(ptext->k2r, key3i));
   if (key2i_plus_1 == NULL)
      return ENOMEM;

   /* allocate space for second table */
   err = key_table_new(&key2i, pow2(22));
   if (err)
   {
      key_table_free(key2i_plus_1);
      return ENOMEM;
   }

   /* perform reduction */
   const uint32_t start_index = ptext->size - 2;
   for (uint32_t i = start_index; i >= 12; --i)
   {
      key3i = generate_key3(ptext, i);
      key3im1 = generate_key3(ptext, i - 1);
      key2r_compute_next_table(key2i_plus_1,
                               key2i,
                               key2r_get_bits_15_2(ptext->k2r, key3i),
                               key2r_get_bits_15_2(ptext->k2r, key3im1),
                               i == start_index ? KEY2_MASK_6BITS : KEY2_MASK_8BITS);
      key_table_uniq(key2i);
      printf("reducing to: %zu\n", key2i->size);
      key_table_swap(&key2i, &key2i_plus_1);
   }

   key_table_squeeze(key2i_plus_1); /* note: we swapped key2i and key2i+1 */

   ptext->key2 = key2i_plus_1;  /* here, key2i_plus_1, is the table at
                                 * index 13 (n=14) this leaves 13
                                 * bytes for the actual attack */
   key_table_free(key2i);
   return 0;
}

static void ptext_final_deinit(struct key_table **key2)
{
   for (uint32_t i = 0; i < 12; ++i)
   {
      if (key2[i] != NULL)
      {
         key_table_free(key2[i]);
         key2[i] = NULL;
      }
   }
}

static int ptext_final_init(struct key_table **key2)
{
   int err;
   
   for (uint32_t i = 0; i < 12; ++i)
   {
      err = key_table_new(&key2[i], 64); /* FIXME: 64 ? */
      if (err)
      {
         ptext_final_deinit(key2);
         return ENOMEM;
      }
   }
   
   return 0;
}

inline static uint32_t compute_key1im1_plus_lsbkey0i(uint32_t key1i)
{
   return (key1i - 1) * MULTINV;
}

static uint32_t compute_key1_msb(struct zc_crk_ptext *ptext, uint32_t current_idx)
{
   const uint32_t key2i = k2(current_idx);
   const uint32_t key2im1 = k2(current_idx - 1);
   return (key2i << 8) ^ crc_32_invtab[key2i >> 24] ^ key2im1;
}

static bool verify_key0(struct zc_crk_ptext *ptext, uint32_t key0,
                        uint32_t start, uint32_t stop)
{
   for (uint32_t i = start; i < stop; ++i)
   {
      key0 = crc32(key0, plaintext(i));
      if (mask_lsb(key0) != k0(i + 1))
         return false;
   }
   return true;
}

static void compute_internal_rep(struct zc_crk_ptext *ptext,
                                 uint32_t *key0, uint32_t *key1, uint32_t *key2)
{
   uint32_t i = 4, key3 = 0;

   *key2 = k2(i);
   *key1 = k1(i);
   /* key0 is already set */
   
   do
   {
      *key2 = crc32inv(*key2, msb(*key1));
      *key1 = ((*key1 - 1) * MULTINV) - lsb(*key0);
      uint32_t tmp = *key2 | 3;
      key3 = lsb((tmp * (tmp ^ 1)) >> 8);
      uint8_t p = cipher(i - 1) ^ key3;
      *key0 = crc32inv(*key0, p);
      if (p != plaintext(i - 1))
         break;
      --i;
   } while (i > 0);

   if (i == 0)
      printf("Key at i==0: key0:%8x, key1:%8x, key2:%8x\n", *key0, *key1, *key2);
   else
      printf("False hit!\n");
}

static void compute_key0(struct zc_crk_ptext *ptext)
{
   uint32_t key0, key1, key2;

   /* calculate key0_6{0..15} */
   key0 = (k0(7) ^ crc_32_tab[k0(6) ^ plaintext(6)]) << 8;
   key0 = (key0 | k0(6)) & 0x0000ffff;

   /* calculate key0_5{0..23} */
   key0 = (key0 ^ crc_32_tab[k0(5) ^ plaintext(5)]) << 8;
   key0 = (key0 | k0(5)) & 0x00ffffff;

   /* calculate key0_4{0..31} */
   key0 = (key0 ^ crc_32_tab[k0(4) ^ plaintext(4)]) << 8;
   key0 = (key0 | k0(4));

   /* verify against known bytes */
   if (!verify_key0(ptext, key0, 4, 12))
      return;

   compute_internal_rep(ptext, &key0, &key1, &key2);
   
   ptext->key_found = true;
}

static void recurse_key1(struct zc_crk_ptext *ptext, uint32_t current_idx)
{
   if (current_idx == 3)
   {
      compute_key0(ptext);
      return;
   }

   uint32_t key1i = k1(current_idx);
   uint32_t rhs_step1 = (key1i - 1) * MULTINV;
   uint32_t rhs_step2 = (rhs_step1 - 1) * MULTINV;
   uint8_t diff = msb(rhs_step2 - (mask_msb(k1(current_idx - 2))));

   for (uint32_t c = 2; c != 0; --c, --diff)
   {
      for (uint32_t i = 0; i < ptext->lsbk0_count[diff]; ++i)
      {
         uint32_t lsbkey0i = ptext->lsbk0_lookup[diff][i];
         if (mask_msb(rhs_step1 - lsbkey0i) == mask_msb(k1(current_idx - 1)))
         {
            ptext->key1_final[current_idx - 1] = rhs_step1 - lsbkey0i;
            ptext->key0_final[current_idx] = lsbkey0i;
            recurse_key1(ptext, current_idx - 1);
         }
      }
   }
}

static void compute_key1(struct zc_crk_ptext *ptext)
{
   for (uint32_t i = 0; i < ptext->key1_lookup_size; ++i)
   {
      ptext->key1_final[12] = ptext->key1_lookup[i];
      recurse_key1(ptext, 12);
   }
}

static void generate_key1_lookup(struct zc_crk_ptext *ptext,
                                 uint32_t key1_11_msb, uint32_t key1_12_msb)
{
   uint32_t key1idx = 0;

   /* find matching msb, section 3.3 from Biham & Kocher */
   for (uint32_t i = 0; i < pow2(24); ++i)
   {
      const uint32_t key1_12_tmp = mask_msb(key1_12_msb) | i;
      const uint32_t key1_11_tmp = (key1_12_tmp - 1) * MULTINV;
      if (mask_msb(key1_11_tmp) == mask_msb(key1_11_msb))
         ptext->key1_lookup[key1idx++] = key1_12_tmp;
   }

   ptext->key1_lookup_size = key1idx;
}

static void recurse_key2(struct zc_crk_ptext *ptext, struct key_table **table, uint32_t current_idx)
{
   uint8_t key3im1;
   uint8_t key3im2;

   if (current_idx == 1)
   {
      compute_key1(ptext);
      return;
   }

   key3im1 = generate_key3(ptext, current_idx - 1);
   key3im2 = generate_key3(ptext, current_idx - 2);

   /* empty table before appending new keys */
   key_table_empty(table[current_idx - 1]);
   
   key2r_compute_single(k2(current_idx),
                        table[current_idx - 1],
                        key2r_get_bits_15_2(ptext->k2r, key3im1),
                        key2r_get_bits_15_2(ptext->k2r, key3im2),
                        KEY2_MASK_8BITS);

   key_table_uniq(table[current_idx - 1]);

   for (uint32_t i = 0; i < table[current_idx - 1]->size; ++i)
   {
      ptext->key2_final[current_idx - 1] = key_table_at(table[current_idx - 1], i);
      ptext->key1_final[current_idx] = compute_key1_msb(ptext, current_idx) << 24;
      if (current_idx == 11)
         generate_key1_lookup(ptext, ptext->key1_final[11], ptext->key1_final[12]);
      recurse_key2(ptext, table, current_idx - 1);
   }
}

static void generate_key0lsb(struct zc_crk_ptext *ptext)
{
   /* reset lsb counters to 0 */
   memset(ptext->lsbk0_count, 0, 256 * sizeof(uint32_t));
   
   for (uint32_t i = 0, p = 0; i < 256; ++i, p += MULTINV)
   {
      uint8_t msbp = msb(p);
      ptext->lsbk0_lookup[msbp][ptext->lsbk0_count[msbp]++] = i;
   }
}

ZC_EXPORT int zc_crk_ptext_final(struct zc_crk_ptext *ptext)
{
   struct key_table *table[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
   int err;
   
   err = ptext_final_init(table);
   if (err)
      return -1;

   generate_key0lsb(ptext);

   for (uint32_t i = 0; i < ptext->key2->size; ++i)
   {
      printf("Processing key2 no: %d\n", i + 1);
      ptext->key2_final[12] = ptext->key2->array[i];
      recurse_key2(ptext, table, 12);
      if (ptext->key_found)
         break;
   }

   ptext_final_deinit(table);
   
   return (ptext->key_found == true ? 0 : -1);
}
