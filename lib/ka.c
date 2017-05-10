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

#include "libzc_private.h"
#include "qsort.h"

#include <stdlib.h>
#include <stdio.h>

static void uint_qsort(uint32_t *arr, uint32_t n)
{
#define uint_lt(a,b) ((*a)<(*b))
    QSORT(uint32_t, arr, n, uint_lt);
}

static void sort(struct ka *a)
{
    uint_qsort(a->array, a->size);
}

int ka_alloc(struct ka **a, size_t initial_size)
{
    struct ka *tmp;

    if (initial_size == 0)
        return -1;

    tmp = calloc(1, sizeof(struct ka));
    if (!tmp)
        return -1;

    tmp->array = calloc(1, initial_size * sizeof(uint32_t));
    if (!tmp->array) {
        free(tmp);
        return -1;
    }

    tmp->capacity = tmp->size = initial_size;
    *a = tmp;

    return 0;
}

void ka_free(struct ka *a)
{
    if (!a)
        return;
    free(a->array);
    free(a);
}

void ka_append(struct ka *a, uint32_t key)
{
    if (a->size < a->capacity) {
        a->array[a->size] = key;
        ++a->size;
        return;
    }

    a->capacity += 1024;
    a->array = realloc(a->array, a->capacity * sizeof(uint32_t));
    if (!a->array)
        fatal("realloc() failed");

    a->array[a->size] = key;
    ++a->size;
}

void ka_uniq(struct ka *a)
{
    size_t i = 0;
    size_t j;

    if (a->size <= 1)
        return;

    sort(a);

    /* reduce by removing duplicates */
    for (j = 1; j < a->size; ++j) {
        if (a->array[j] != a->array[i])
            a->array[++i] = a->array[j];
    }

    a->size = i + 1;
}

void ka_squeeze(struct ka *a)
{
    if (a->size == a->capacity)
        return;
    a->array = realloc(a->array, a->size * sizeof(uint32_t));
    a->capacity = a->size;
}

void ka_empty(struct ka *a)
{
    /* future append will restart at 0 */
    a->size = 0;
}

#ifdef ENABLE_DEBUG
void ka_print(struct ka *a, FILE *stream)
{
    for (uint32_t i = 0; i < a->size; ++i)
        fprintf(stream, "0x%0x\n", a->array[i]);
}
#endif
