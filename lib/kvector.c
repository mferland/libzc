/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2018 Marc Ferland
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

#include "ptext_private.h"
#include "qsort.h"

#include <stdlib.h>
#include <stdio.h>

static void uint_qsort(uint32_t *buf, size_t n)
{
#define uint_lt(a,b) ((*a)<(*b))
	QSORT(uint32_t, buf, n, uint_lt);
}

static void sort(struct kvector *v)
{
	uint_qsort(v->buf, v->size);
}

int kalloc(struct kvector **v, size_t init)
{
	struct kvector *tmp;

	if (init == 0)
		return -1;

	tmp = calloc(1, sizeof(struct kvector));
	if (!tmp)
		return -1;

	tmp->buf = calloc(1, init * sizeof(uint32_t));
	if (!tmp->buf) {
		free(tmp);
		return -1;
	}

	tmp->capacity = tmp->size = init;
	*v = tmp;

	return 0;
}

void kfree(struct kvector *v)
{
	if (!v)
		return;
	free(v->buf);
	free(v);
}

int kappend(struct kvector *v, uint32_t key)
{
	uint32_t *tmp;

	if (v->size < v->capacity) {
		v->buf[v->size] = key;
		++v->size;
		return 0;
	}

	v->capacity += 4096;
	tmp = realloc(v->buf, v->capacity * sizeof(uint32_t));
	if (!tmp) {
		perror("realloc failed");
		return -1;
	}
	v->buf = tmp;

	v->buf[v->size] = key;
	++v->size;
	return 0;
}

void kuniq(struct kvector *v)
{
	size_t i = 0;
	size_t j;

	if (v->size <= 1)
		return;

	sort(v);

	/* reduce by removing duplicates */
	for (j = 1; j < v->size; ++j) {
		if (v->buf[j] != v->buf[i])
			v->buf[++i] = v->buf[j];
	}

	v->size = i + 1;
}

void ksqueeze(struct kvector *v)
{
	if (v->size == v->capacity)
		return;
	v->buf = realloc(v->buf, v->size * sizeof(uint32_t));
	v->capacity = v->size;
}

void kempty(struct kvector *v)
{
	/* future append will restart at 0 */
	v->size = 0;
}

#ifdef ENABLE_DEBUG
void kprint(struct kvector *v, FILE *stream)
{
	for (uint32_t i = 0; i < v->size; ++i)
		fprintf(stream, "0x%0x\n", v->buf[i]);
}
#endif
