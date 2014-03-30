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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "libzc.h"
#include "libzc_private.h"
#include "crc32.h"
#include "key_table.h"
#include "key2_reduce.h"

struct zc_crk_ptext
{
   struct zc_ctx *ctx;
   int refcount;
   unsigned char *plaintext;
   unsigned char *ciphertext;
   size_t size;
   struct key_table *key2;
   struct key2r *k2r;
   unsigned int key2_final[13];
};

static unsigned char generate_key3(const struct zc_crk_ptext *ptext, unsigned int i)
{
   return (ptext->plaintext[i] ^ ptext->ciphertext[i]);
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
   *ptext = new;
   dbg(ctx, "ptext %p created\n", new);
   return 0;
}

ZC_EXPORT int zc_crk_ptext_set_text(struct zc_crk_ptext *ptext,
                                    const unsigned char *plaintext,
                                    const unsigned char *ciphertext,
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

/*
  TODO:
  * remember the _best_ offset key2i only (not necessarely key2_13)
  * check minimal byte count for reduction
 */
ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
   struct key_table *key2i_plus_1;
   struct key_table *key2i;
   unsigned char key3i;
   unsigned char key3im1;
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
   const unsigned int start_index = ptext->size - 2;
   for (unsigned int i = start_index; i >= 13; --i)
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

static int ptext_final_init(struct key_table **key2)
{
   for (unsigned int i = 0; i < 12; ++i)
   {
      err = key_table_new(&key2[i], 64); /* FIXME: 64 ? */
      if (err)
      {
         ptext_final_deinit(struct key_table **key2);
         return ENOMEM;
      }
   }
   return 0;
}

static void ptext_final_deinit(struct key_table **key2)
{
   for (unsigned int i = 0; i < 12; ++i)
   {
      if (key2[i] != NULL)
      {
         key_table_free(key2[i]);
         key2[i] = NULL;
      }
   }
}

static int compute_key1(struct zc_crk_ptext *ptext)
{
   // RENDU CICIIC
   /*
     - calculer le tableau de key1_12 .. key1_1 (MSB seulement)
     - calculer le reste de bits (24)
     - appeler recurse_key1
    */
}

static int recurse_key2(struct zc_crk_ptext *ptext, struct key_table **table, unsigned int index)
{
   unsigned char key3i;
   unsigned char key3im1;

   if (index == 1)
   {
      compute_key1(ptext);      /* FIXME: return ? */
      return 0;
   }

   key3i = generate_key3(ptext, index);
   key3im1 = generate_key3(ptext, index - 1);

   /* empty table before appending new keys */
   key_table_empty(table[index - 1]);
   
   key2r_compute_single(ptext->key2_final[index],
                        table[index - 1],
                        key2r_get_bits_15_2(ptext->k2r, key3i),
                        key2r_get_bits_15_2(ptext->k2r, key3im1),
                        KEY2_MASK_8BITS);

   for (unsigned int i = 0; i < table[index - 1]->size; ++i)
   {
      ptext->key2_final[index - 1] = key_table_at(table[index - 1], i);
      recurse_key2(ptext, table, index - 1); /* FIXME: return ? */
   }
}

ZC_EXPORT int zc_crk_ptext_final(struct zc_crk_ptext *ptext)
{
   struct key_table *table[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
   int err;
   
   err = ptext_final_init(&key2);
   if (err)
      return -1;
   
   for (unsigned int i = 0; i < ptext->size; ++i)
   {
      ptext->key2_final[12] = ptext->key2[i];
      recurse_key2(ptext->key2_final, table, 12);
   }

   ptext_final_deinit(&key2);
   
   return 0;
}
