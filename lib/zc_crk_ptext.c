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
#include "qsort.h"

static inline unsigned int pow2(unsigned int power)
{
   return (1 << power);
}

static void uint_qsort(unsigned int *arr, unsigned int n)
{
#define uint_lt(a,b) ((*a)<(*b))
   QSORT(unsigned int, arr, n, uint_lt);
}

struct key_table
{
   unsigned int *array;
   size_t size;
};

struct zc_crk_ptext
{
   struct zc_ctx *ctx;
   int refcount;
   unsigned char *plaintext;
   unsigned char *ciphertext;
   size_t size;
   struct key_table *key2;
};

#define KEY2(key2, index)                      \
   key2->array[index]

static void free_key_table(struct key_table *table)
{
   free(table->array);
   free(table);
}

static void free_key_tables(struct key_table *table, size_t count)
{
   for (size_t i = 0; i < count; ++i)
   {
      if (table[i].array == NULL)
         continue;
      free(table[i].array);
   }
   free(table);
}

static int new_key_table(struct key_table **table, size_t size)
{
   struct key_table *tmp;

   tmp = calloc(1, sizeof(struct key_table));
   if (tmp == NULL)
      return ENOMEM;
   
   tmp->array = calloc(1, size * sizeof(unsigned int));
   if (tmp->array == NULL)
   {
      free(tmp);
      return ENOMEM;
   }
   
   tmp->size = size;
   *table = tmp;
   
   return 0;
}

static int new_key_tables(struct key_table **table, size_t size, size_t count)
{
   struct key_table *tmp;

   tmp = calloc(1, sizeof(struct key_table) * count);
   if (tmp == NULL)
      return ENOMEM;

   for (size_t i = 0; i < count; ++i)
   {
      tmp[i].array = calloc(1, size * sizeof(unsigned int));
      if (tmp[i].array == NULL)
      {
         free_key_tables(tmp, count);
         return ENOMEM;
      }
   
      tmp[i].size = size;
   }

   *table = tmp;
   return 0;
}

static void print_key_table(const struct key_table *table)
{
   for (unsigned int i = 0; i < table->size; ++i)
   {
      fprintf(stderr, "0x%x\n", table->array[i]);
   }
}

static inline void swap_key_table(struct key_table **table1, struct key_table **table2)
{
   struct key_table *tmp = *table1;
   *table1 = *table2;
   *table2 = tmp;
}

static inline void sort_key_table(struct key_table *table)
{
   uint_qsort(table->array, table->size);
}

static inline void resize_key_table(struct key_table *table, size_t new_size)
{
   if (new_size == table->size)
      return;
   table->array = realloc(table->array, new_size * sizeof(unsigned int));
   table->size = new_size;
}

static inline void reduce_key_table(struct key_table *table)
{
   size_t i = 0;
   size_t j;
   
   if (table->size <= 1)
      return;

   /* reduce by removing duplicates */
   for (j = 1; j < table->size; ++j)
   {
      if (table->array[j] != table->array[i])
         table->array[++i] = table->array[j];
   }

   resize_key_table(table, i + 1);
}

static inline unsigned char generate_key3(const struct zc_crk_ptext *ptext, unsigned int i)
{
   return (ptext->plaintext[i] ^ ptext->ciphertext[i]);
}

static inline unsigned int key2at(const struct key_table *table, unsigned int i)
{
   return table->array[i];
}

static void generate_all_key2_bits_15_2(unsigned short *value, unsigned char key3)
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

static void generate_all_key2_bits_31_2(unsigned int *key2, const unsigned short *key2_bits_15_2)
{
   unsigned int i, j;
   for (i = 0; i < pow2(16); ++i)
      for (j = 0; j < 64; ++j)
         key2[i * 64 + j] = (i << 16) | key2_bits_15_2[j];
}

static struct key_table *generate_first_gen_key2(unsigned char key3)
{
   unsigned short key2_bits_15_2[64];
   struct key_table *table;
   int err;

   err = new_key_table(&table, pow2(22));
   if (err)
      return NULL;

   generate_all_key2_bits_15_2(key2_bits_15_2, key3);
   generate_all_key2_bits_31_2(table->array, key2_bits_15_2);

   return table;
}

static unsigned int bits_1_0_key2i_plus_1(unsigned int key2i, unsigned int key2i_plus_1)
{
   unsigned char key2i_plus_1_msb = key2i_plus_1 >> 24;
   unsigned int tmp = key2i ^ crc_32_invtab[key2i_plus_1_msb];
   tmp = (tmp >> 8) & 0x3;   /* keep only bit 9 and 8 */
   return tmp;
}

static void generate_key2i_table(struct key_table *key2i_plus_1,
                                 struct key_table *key2i,
                                 unsigned char key3)
{
   unsigned int key2i_index = 0;
   unsigned short key2i_bits_15_2[64];
   const unsigned int key2i_plus_1_size = key2i_plus_1->size;
   int resize_count = 0;

   generate_all_key2_bits_15_2(key2i_bits_15_2, key3);

   /* for each ~2^22 possible values of bits [31..2] of key2i+1 */
   for (unsigned int i = 0; i < key2i_plus_1_size; ++i)
   {
      const unsigned int key2ip1_tmp = key2at(key2i_plus_1, i);
      const unsigned int key2i_tmp = (key2ip1_tmp << 8) ^ crc_32_invtab[key2ip1_tmp >> 24];
      const unsigned int key2i_bits10_15_rhs = key2i_tmp & 0xfc00;
      for (int j = 0; j < 64; ++j)
      {
         unsigned int key2i_bits10_15_lhs = (unsigned int)key2i_bits_15_2[j] & 0xfc00;

         /* the left and right hand side share the same 6 bits in
            position [15..10]. See biham & kocher 3.1. */
         if (key2i_bits10_15_rhs == key2i_bits10_15_lhs)
         {
            if (key2i_index >= key2i->size)
            {
               resize_key_table(key2i, key2i->size + 1); /* TODO: SLOWWWW */
               ++resize_count;
            }
            
            /* save bits [31..8] */
            key2i->array[key2i_index] = key2i_tmp & 0xffffff00;

            /* save bits [7..2] */
            key2i->array[key2i_index] |= key2i_bits_15_2[j];

            /* save bits [1..0] of key2i_plus_1 */
            key2i_plus_1->array[i] |= bits_1_0_key2i_plus_1(key2i->array[key2i_index],
                                                            key2i_plus_1->array[i]);

            ++key2i_index;
         }
      }
   }

   /* remove unused values from the end of the table */
   resize_key_table(key2i, key2i_index + 1);
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
   free(ptext->key2);
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
  * only reduce every so often to save on overhead
  * use a real dynamic array (do not abuse realloc)
  * remember the _best_ offset key2i only (not necessarely key2_13)
  * check minimal byte count for reduction
 */
ZC_EXPORT int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext)
{
   struct key_table *key2i_plus_1;
   struct key_table *key2i;
   unsigned char key3;

   int err;

   key2i_plus_1 = generate_first_gen_key2(generate_key3(ptext, ptext->size - 1));
   if (key2i_plus_1 == NULL)
      return -1;

   err = new_key_table(&key2i, pow2(22));
   if (err != 0)
   {
      free_key_table(key2i_plus_1);
      return err;
   }

   /* generate key2i from key2i+1 but do not reduce key2i since we do
    * not yet have bits [1..0]. */
   key3 = generate_key3(ptext, ptext->size - 2);
   generate_key2i_table(key2i_plus_1, key2i, key3);
   swap_key_table(&key2i, &key2i_plus_1);
   
   /* reduce the number of key2 using extra plaintext bytes. */
   for (int i = ptext->size - 3; i >= 12; --i)
   {
      /* generate key2i partially (missing bits [1..0]) and complete
       * key2i+1 table. */
      key3 = generate_key3(ptext, i);
      generate_key2i_table(key2i_plus_1, key2i, key3);

      /* key2i+1 table is now complete (full 32 bits have been found),
       * sort and reduce key2i+1 */
      sort_key_table(key2i_plus_1);
      reduce_key_table(key2i_plus_1);
      printf("reducing to: %zu\n", key2i_plus_1->size);

      /* regenerate key2i based on the reduced key2i+1, this gives us
       * a partial key2i (missing bits 0 and 1 ) but this time it
       * should contain less values. */
      generate_key2i_table(key2i_plus_1, key2i, key3);
      
      swap_key_table(&key2i, &key2i_plus_1);
   }

   ptext->key2 = key2i;         /* here, key2i, is the table at index
                                 * 13 (n=14) this leaves 13 bytes for
                                 * the actual attack */
   free_key_table(key2i_plus_1);
   return 0;
}

/* ZC_EXPORT int zc_crk_ptext_crack(struct zc_crk_ptext *ptext) */
/* { */
/*    struct key_table *key2i_table; */
/*    unsigned char key3; */

/*    /\* ptext contains the key2 table at index 13 (n=14) *\/ */

/*    err = new_key_tables(&key2i_table, ptext->size, 12); /\* 12 tables of size ptext->size *\/ */
/*    if (err != 0) */
/*       return -1; */

/*    /\* generate key2[13..2] *\/ */
/*    key3 = generate_key3(ptext, 12); */
/*    generate_key2i_table(ptext->key2, &key2i_table[11], key3); */
   
/*    for (int i = 10; i >= 1; ++i) */
/*    { */
/*       generate_key2i_table(&key2i_table[i + 1], &key2i_table[i]); */

/* } */
