/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2022 Marc Ferland
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

#ifndef _BITMAP_H_
#define _BITMAP_H_

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1 / (d)))
#define BITS_PER_BYTE		8
#define BITS_PER_TYPE(type)	(sizeof(type) * BITS_PER_BYTE)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_TYPE(long))
#define BITS_PER_LONG		BITS_PER_TYPE(long)

static inline void set_bit(unsigned long *bitmap, int nr)
{
	unsigned long mask = 1UL << (nr % BITS_PER_LONG);
	unsigned long *p = ((unsigned long *)bitmap) + (nr / BITS_PER_LONG);
	*p |= mask;
}

static inline void clear_bit(unsigned long *bitmap, int nr)
{
	unsigned long mask = 1UL << (nr % BITS_PER_LONG);
	unsigned long *p = ((unsigned long *)bitmap) + (nr / BITS_PER_LONG);
	*p &= ~mask;
}

static inline int test_bit(const unsigned long *bitmap, int nr)
{
	return 1UL & (bitmap[nr / BITS_PER_LONG] >> (nr & (BITS_PER_LONG - 1)));
}

unsigned long *bitmap_alloc(unsigned int nbits);
void bitmap_free(unsigned long *bitmap);

#endif	/* _BITMAP_H_ */
