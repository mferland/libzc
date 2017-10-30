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

#ifndef _PTEXT_PRIVATE_H_
#define _PTEXT_PRIVATE_H_

#include <pthread.h>
#include <stdint.h>

#include "libzc.h"
#include "libzc_private.h"

#define KEY2_MASK_6BITS 0xfc00
#define KEY2_MASK_8BITS 0xff00

struct zc_crk_ptext {
    struct zc_ctx *ctx;
    int refcount;
    const uint8_t *plaintext;
    const uint8_t *ciphertext;
    size_t size;
    struct ka *key2;
    struct key2r *k2r;
    uint8_t lsbk0_lookup[256][2];
    uint32_t lsbk0_count[256];
    bool found;
    pthread_t found_by;
};

#define generate_key3(s, i) (s->plaintext[i] ^ s->ciphertext[i])

/* key2 reduction */
struct key2r;
int key2r_new(struct key2r **key2r);
void key2r_free(struct key2r *key2r);
uint16_t *key2r_get_bits_15_2(const struct key2r *key2r, uint8_t key3);
struct ka *key2r_compute_first_gen(const uint16_t *key2_bits_15_2);
int key2r_compute_single(uint32_t key2i_plus_1,
                         struct ka *key2i,
                         const uint16_t *key2i_bits_15_2,
                         const uint16_t *key2im1_bits_15_2,
                         uint32_t common_bits_mask);

#endif  /* _PTEXT_PRIVATE_H_ */
