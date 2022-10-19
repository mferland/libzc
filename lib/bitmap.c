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

#include <stdlib.h>
#include "bitmap.h"

unsigned long *bitmap_alloc(unsigned int nbits)
{
	return calloc(BITS_TO_LONGS(nbits), sizeof(unsigned long));
}

void bitmap_free(unsigned long *bitmap)
{
	free(bitmap);
}
