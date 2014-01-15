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

struct zc_crk_ptext
{
   struct zc_ctx *ctx;
   int refcount;
   unsigned char *plaintext;
   unsigned char *ciphertext;
   size_t size;
   struct key_table *key2;
};

static inline unsigned int pow2(unsigned int power)
{
   return (1 << power);
}

static void swap_key_table(struct key_table **table1, struct key_table **table2)
{
   struct key_table *tmp = *table1;
   *table1 = *table2;
   *table2 = tmp;
}

static unsigned char generate_key3(const struct zc_crk_ptext *ptext, unsigned int i)
{
   return (ptext->plaintext[i] ^ ptext->ciphertext[i]);
}

static unsigned short *key2_bits_15_2_from_key3(unsigned short *key2_bits_15_2, unsigned char key3)
{
   return &key2_bits_15_2[key3 * 64];
}

static void generate_key2_bits_15_2(unsigned short *value, unsigned char key3)
{
   unsigned char key3tmp;
   unsigned int i = pow2(16);
   unsigned int valuei = 0;
   do {
      key3tmp = ((i | 2) * ((i | 3))) >> 8;
      if (key3 == key3tmp)
      {
         value[valuei] = i;
         ++valuei;
      }
   } while (i -= 4);
}

static unsigned short *generate_all_key2_bits_15_2(void)
{
   unsigned int key3;
   unsigned short *table;

   table = malloc(256 * 64 * sizeof(unsigned short));
   
   for (key3 = 0; key3 < 256; ++key3)
      generate_key2_bits_15_2(key2_bits_15_2_from_key3(table, key3), key3);

   return table;
}

static void generate_all_key2_bits_31_2(unsigned int *key2, const unsigned short *key2_bits_15_2)
{
   unsigned int i, j;
   for (i = 0; i < pow2(16); ++i)
      for (j = 0; j < 64; ++j)
         key2[i * 64 + j] = (i << 16) | key2_bits_15_2[j];
}

static struct key_table *generate_first_gen_key2(const unsigned short *key2_bits_15_2)
{
   struct key_table *table;
   int err;

   err = key_table_new(&table, pow2(22));
   if (err)
      return NULL;

   generate_all_key2_bits_31_2(table->array, key2_bits_15_2);
   return table;
}

static unsigned int bits_1_0_key2i(unsigned int key2im1, unsigned int key2i)
{
   unsigned char key2i_msb = key2i >> 24;
   unsigned int tmp = key2im1 ^ crc_32_invtab[key2i_msb];
   tmp = (tmp >> 8) & 0x3;      /* keep only bit 9 and 8 */
   return tmp;
}

static void generate_all_key2i_with_bits_1_0(struct key_table *key2i_table, unsigned int key2i,
                                             const unsigned short *key2im1_bits_15_2)
                                             
{
   /* receive key2ip1 bits [31..2] and calculate every possible
    * key2ip1[31..0]. result is returned in 'result'. */
   const unsigned int key2im1_bits_31_10 = (key2i << 8) ^ crc_32_invtab[key2i >> 24];
   const unsigned int key2im1_bits_15_10_rhs = key2im1_bits_31_10 & 0xfc00;
   
   for (int j = 0; j < 64; ++j)
   {
      unsigned int key2im1_bits_15_10_lhs = (unsigned int)key2im1_bits_15_2[j] & 0xfc00;

      /* the left and right hand side share 6 bits in position
         [15..10]. See biham & kocher 3.1. */
      if (key2im1_bits_15_10_rhs == key2im1_bits_15_10_lhs)
      {
         unsigned int key2im1;
         key2im1 = key2im1_bits_31_10 & 0xfffffc00;
         key2im1 |= key2im1_bits_15_2[j];
         key_table_append(key2i_table, key2i | bits_1_0_key2i(key2im1, key2i));
      }
   }
}

static void generate_key2i_table(const struct key_table *key2i_plus_1,
                                 struct key_table *key2i,
                                 const unsigned short *key2i_bits_15_2,
                                 const unsigned short *key2im1_bits_15_2,
                                 unsigned int iteration)
{
   /* On the first iteration, use 6 common bits since the first table
    * is missing the last 2 bits. The subsequent calls use 8 common
    * bits for comparaison. */
   const unsigned int common_bits_mask = iteration == 0 ? 0xfc00 : 0xff00;

   key_table_empty(key2i);
   
   for (unsigned int i = 0; i < key2i_plus_1->size; ++i)
   {
      const unsigned int key2ip1_tmp = key_table_at(key2i_plus_1, i);
      const unsigned int key2i_bits31_8 = (key2ip1_tmp << 8) ^ crc_32_invtab[key2ip1_tmp >> 24];
      const unsigned int key2i_bits15_10_rhs = key2i_bits31_8 & common_bits_mask;

      for (unsigned int j = 0; j < 64; ++j)
      {
         const unsigned int key2i_bits15_10_lhs = key2i_bits_15_2[j] & common_bits_mask;
         
         /* the left and right hand side share the same 6 bits in
            position [15..10]. See biham & kocher 3.1. */
         if (key2i_bits15_10_rhs == key2i_bits15_10_lhs)
         {
            unsigned int key2i_tmp;
            
            /* save bits [31..8] */
            key2i_tmp = key2i_bits31_8 & 0xffffff00;

            /* save bits [7..2] */
            key2i_tmp |= key2i_bits_15_2[j];

            /* save bits [1..0] */
            generate_all_key2i_with_bits_1_0(key2i, key2i_tmp, key2im1_bits_15_2);
         }
      }
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
   free(ptext->plaintext);
   free(ptext->ciphertext);
   key_table_free(ptext->key2);
   free(ptext);
   return NULL;
}

ZC_EXPORT int zc_crk_ptext_new(struct zc_ctx *ctx, struct zc_crk_ptext **ptext)
{
   struct zc_crk_ptext *new;

   new = calloc(1, sizeof(struct zc_crk_ptext));
   if (!new)
      return ENOMEM;

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
   unsigned short *key2_bits_15_2;
   unsigned char key3i;
   unsigned char key3im1;
   unsigned int iter = 0;
   int err;

   key2_bits_15_2 = generate_all_key2_bits_15_2();

   key3i = generate_key3(ptext, ptext->size - 1);
   key2i_plus_1 = generate_first_gen_key2(key2_bits_15_2_from_key3(key2_bits_15_2, key3i));
   if (key2i_plus_1 == NULL)
   {
      free(key2_bits_15_2);
      return -1;
   }

   err = key_table_new(&key2i, pow2(22));
   if (err != 0)
   {
      key_table_free(key2i_plus_1);
      free(key2_bits_15_2);
      return err;
   }

   /* reduce the number of key2 using extra plaintext bytes. */
   for (int i = ptext->size - 2; i >= 13; --i)
   {
      key3i = generate_key3(ptext, i);
      key3im1 = generate_key3(ptext, i - 1);
      generate_key2i_table(key2i_plus_1,
                           key2i,
                           key2_bits_15_2_from_key3(key2_bits_15_2, key3i),
                           key2_bits_15_2_from_key3(key2_bits_15_2, key3im1),
                           iter++);
      key_table_uniq(key2i);
      printf("reducing to: %zu\n", key2i->size);
      swap_key_table(&key2i, &key2i_plus_1);
   }

   key_table_squeeze(key2i_plus_1); /* note: we swapped key2i and key2i+1 */

   ptext->key2 = key2i_plus_1;  /* here, key2i_plus_1, is the table at
                                 * index 13 (n=14) this leaves 13
                                 * bytes for the actual attack */
   key_table_free(key2i);
   free(key2_bits_15_2);
   return 0;
}

ZC_EXPORT int zc_crk_ptext_crack(struct zc_crk_ptext *ptext)
{
   /* struct key_table *key2i_table; */
   /* struct key_table *key1i_table; */
   /* unsigned char key3; */
   /* int err; */

   /* /\* ptext contains the key2 table at index 13 (n=14) *\/ */

   /* err = new_key_tables(&key2i_table, ptext->size, 13); /\* 13 tables of size ptext->size *\/ */
   /* if (err != 0) */
   /*    return -1; */

   /* /\* generate key2[13..2]. Note: we cannot fully generate key2_1, see */
   /*  * eq. 1 from biham & kocher *\/ */
   /* key3 = generate_key3(ptext, 12); */
   /* generate_key2i_table(ptext->key2, &key2i_table[12], key3); */
   /* for (int i = 11; i >= 0; ++i) */
   /* { */
   /*    key3 = generate_key3(ptext, i); */
   /*    generate_key2i_table(&key2i_table[i + 1], &key2i_table[i], key3); */
   /* } */

   /* /\* calculate the MSB of key1[13..3] using key2[13..2] *\/ */
   /* err = new_key_tables(&key1i_table, ptext->size, 11); */
   /* for (int i = 12; i >= 1; ++i) */
   /* { */
   /*    //generate_key1_msb(&key2i_table[i]); */
   /* } */

   return 0;
}
