/*
 *  zc - zip crack library
 *  Copyright (C) 2014  Marc Ferland
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

#include "key2_reduce.h"
#include "key_table.h"
#include "libzc_private.h"
#include "crc32.h"

#include <stdlib.h>
#include <errno.h>

struct key2r
{
   unsigned short *bits_15_2_cache;
};

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

static unsigned short *generate_bits_15_2(void)
{
   unsigned short *tmp;

   tmp = malloc(256 * 64 * sizeof(unsigned short));
   if (tmp == NULL)
      return NULL;

   for (unsigned int key3 = 0; key3 < 256; ++key3)
      generate_key2_bits_15_2(&tmp[key3 * 64], key3);

   return tmp;
}

static void generate_all_key2_bits_31_2(unsigned int *key2, const unsigned short *key2_bits_15_2)
{
   unsigned int i, j;
   for (i = 0; i < pow2(16); ++i)
      for (j = 0; j < 64; ++j)
         key2[i * 64 + j] = (i << 16) | key2_bits_15_2[j];
}

int key2r_new(struct key2r **k2r)
{
   struct key2r *tmp;
   unsigned short *bits_15_2_tmp;

   tmp = calloc(1, sizeof(struct key2r));
   if (tmp == NULL)
      return ENOMEM;

   bits_15_2_tmp = generate_bits_15_2();
   if (bits_15_2_tmp == NULL)
   {
      free(tmp);
      return ENOMEM;
   }
   
   tmp->bits_15_2_cache = bits_15_2_tmp;
   *k2r = tmp;

   return 0;
}

void key2r_free(struct key2r *k2r)
{
   free(k2r->bits_15_2_cache);
   free(k2r);
}

unsigned short *key2r_get_bits_15_2(const struct key2r *k2r, unsigned char key3)
{
   return &k2r->bits_15_2_cache[key3 * 64];
}

struct key_table *key2r_compute_first_gen(const unsigned short *key2_bits_15_2)
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
   const unsigned int key2im1_bits_31_10 = (key2i << 8) ^ crc_32_invtab[key2i >> 24];
   const unsigned int key2im1_bits_15_10_rhs = key2im1_bits_31_10 & 0xfc00;

   for (int j = 0; j < 64; ++j)
   {
      const unsigned int key2im1_bits_15_10_lhs = key2im1_bits_15_2[j] & 0xfc00;

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

void k2r_compute_single(unsigned int key2i_plus_1,
                        struct key_table *key2i,
                        const unsigned short *key2i_bits_15_2,
                        const unsigned short *key2im1_bits_15_2,
                        unsigned int common_bits_mask)
{
   const unsigned int key2i_bits31_8 = (key2i_plus_1 << 8) ^ crc_32_invtab[key2i_plus_1 >> 24];
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

void key2r_compute_next_table(struct key_table *key2i_plus_1,
                              struct key_table *key2i,
                              const unsigned short *key2i_bits_15_2,
                              const unsigned short *key2im1_bits_15_2,
                              unsigned int common_bits_mask)
{
   key_table_empty(key2i);

   for (unsigned int i = 0; i < key2i_plus_1->size; ++i)
   {
      generate_key2i_single(key_table_at(key2i_plus_1, i),
                            key2i,
                            key2i_bits_15_2,
                            key2im1_bits_15_2,
                            common_bits_mask);
   }
}
