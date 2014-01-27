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

#ifndef KEY2_REDUCE_H_
#define KEY2_REDUCE_H_

#define KEY2_MASK_6BITS 0xfc00
#define KEY2_MASK_8BITS 0xff00

struct key2r;
int key2r_new(struct key2r **key2r);
void key2r_free(struct key2r *key2r);
unsigned short *key2r_get_bits_15_2(const struct key2r *key2r, unsigned char key3);
struct key_table *key2r_compute_first_gen(const unsigned short *key2_bits_15_2);
void key2r_compute_next_table(struct key_table *key2i_plus_1,
                              struct key_table *key2i,
                              const unsigned short *key2i_bits_15_2,
                              const unsigned short *key2im1_bits_15_2,
                              unsigned int common_bits_mask);

#endif
