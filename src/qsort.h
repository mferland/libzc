/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2021 Marc Ferland
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

#ifndef _QSORT_H_
#define _QSORT_H_

#if defined(__AVX2__)
void uint32_qsort_avx2(uint32_t *x, long long n);
#else
void uint32_qsort_portable(uint32_t *x, long long n);
#endif

static inline void uint32_qsort(uint32_t *x, long long n)
{
#if defined(__AVX2__)
	uint32_qsort_avx2(x, n);
#else
	uint32_qsort_portable(x, n);
#endif
}

#endif /* _QSORT_H_ */
