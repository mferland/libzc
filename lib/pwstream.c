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

#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "libzc_private.h"
#include "pwstream.h"

static const struct entry null_entry = { -1, -1, -1 };

typedef __uint128_t u128;
#define UINT128_MAX (( __uint128_t) -1)

/*
 This algorithm distributes a pool of characters to 'n' password
 streams. These streams can then generate passwords that are mutually
 exclusive. For example:

 pool: a,b,c

 Distribute to 4 streams of 3 characters (last character appears first):
 stream0: [a,a] [a,a] [a,c] --> aaa, baa, caa
 stream1: [a,a] [b,c] [a,c] --> aba, aca, bba, bca, cba, cca
 stream2: [b,b] [a,c] [a,c] --> aab, abb, acb, bab, bbb, bcb, cab, cbb, ccb
 stream3: [c,c] [a,c] [a,c] --> aac, abc, acc, bac, bbc, bcc, cac, cbc, ccc

 The output of the algorithm is a table of streams*characters
 entries. Each entry contains a start and end offset to the character
 pool. Using these offsets we can easily loop over all possible
 'strings' using simple for-loops.

 Pseudo-code (again for 3 characters strings):
 for (i = table[stream0, 2].start; i <= table[stream0, 2].stop; ++i)
    str[0] = pool[i];
    for (j = table[stream0, 1].start; j <= table[stream0, 1].stop; ++j)
       str[1] = pool[j];
       for (k = table[stream0, 0].start; k <= table[stream0, 0].stop; ++k)
          str[2] = pool[k];
          do_stuff(str);

 The entry table is divided in the following way:
 +----------------------------------+
 |s0c0|s1c0|s2c0|s0c1|s1c1|s2c1|....|
 +----------------------------------+
 where s0-->stream0 and c0-->character0.
 */

struct pwstream {
	struct entry *entry;
	size_t initial;
	size_t rows;
	size_t cols;
	size_t real_cols;
	size_t *chars_at_idx;
};

static int compare_entries(const void *a, const void *b)
{
	const struct entry *ea = (const struct entry *)a;
	const struct entry *eb = (const struct entry *)b;

	/* since entries are always mutually exclusive, compare only the
	 * 'start' member */
	return (ea->start > eb->start) - (ea->start < eb->start);
}

static void sort(struct entry *e, size_t streams)
{
	qsort(e, streams, sizeof(struct entry), compare_entries);
}

/**
 * Get entry pointer at [row][col].
 */
static struct entry *get(struct pwstream *t, size_t row, size_t col)
{
	return &t->entry[t->cols * row + col];
}

/**
 * Split the given sequence of length 'len' in streams.
 * i.e.: 1,2,3,4,5 in 3 streams ==> [1,2],[3,4],[5]
 */
static void split_less(size_t plen, size_t streams, struct entry *t)
{
	for (size_t i = 0; i < streams; ++i) {
		int start = (i * plen) / streams;
		t[i].start = start;
		t[i].initial = start;
		t[i].stop = ((i + 1) * plen) / streams - 1;
	}
}

/**
 * 1,2,3 in 4 streams ==> [1],[1],[2],[3]
 */
static void split_more(size_t plen, size_t streams, struct entry *e)
{
	for (size_t i = 0; i < streams; ++i) {
		int tmp = i % plen;
		e[i].start = tmp;
		e[i].stop = tmp;
		e[i].initial = tmp;
	}
	sort(e, streams);
}

/**
 * 1,2,3,4 in 4 streams ==> [1],[2],[3],[4]
 */
static void split_equal(size_t plen, struct entry *e)
{
	for (size_t i = 0; i < plen; ++i) {
		e[i].start = i;
		e[i].stop = i;
		e[i].initial = i;
	}
}

/**
 * Distribute sequence @seq in @streams and store the result at @entry.
 */
static void distribute(size_t plen, size_t streams, struct entry *entry)
{
	if (streams == 1) {
		entry->start = 0;
		entry->stop = plen - 1;
		entry->initial = 0;
	} else if (streams == plen) {
		split_equal(plen, entry);
	} else if (streams > plen) {
		split_more(plen, streams, entry);
	} else
		split_less(plen, streams, entry);
}

/**
 * Compares entries e1 and e2.
 */
static bool is_equal_entries(const struct entry *e1, const struct entry *e2)
{
	return (e1->start == e2->start && e1->stop == e2->stop);
}

/**
 * Initialize entry table with default values.
 */
static void entry_table_init(struct pwstream *t, size_t start, const size_t *stop)
{
	/*
	 * The default stop values are taken from the chars_at_idx
	 * array. Each entry in this array corresponds to the number
	 * of characters we have to test.
	 *
	 * Example for a pool of 3 characters:
	 * +---+---+---+---+---+
	 * | 3 | 3 | 3 |...| 3 |
	 * +---+---+---+---+---+
	 *
	 * Example for mask "abc?d":
	 * +---+---+---+----+
	 * | 1 | 1 | 1 | 10 |
	 * +---+---+---+----+
	 *
	 */

	for (size_t row = 0; row < t->rows; ++row) {
		for (size_t col = 0; col < t->cols; ++col) {
			struct entry *entry = get(t, row, col);
			entry->start = start;
			entry->stop = stop[row] - 1;
			entry->initial = start;
		}
	}
}

/**
 * Count the number of entries identical to @e on row @row.
 */
static size_t uniq(struct pwstream *t, size_t row, const struct entry *e)
{
	size_t count = 0;
	struct entry *n = get(t, row, 0);

	for (size_t i = 0; i < t->cols; ++i) {
		if (is_equal_entries(&n[i], e))
			++count;
	}
	return count;
}

/**
 * Count the number of entries identical to @e and consider @len
 * entries.
 */
static size_t uniq_from_entry(const struct entry *e, size_t len)
{
	size_t count = 1; /* first entry is always equal */
	for (size_t i = 1; i < len; ++i) {
		if (is_equal_entries(&e[i], e))
			++count;
	}
	return count;
}

static void recurse(struct pwstream *pws, size_t row, size_t count, struct entry *e)
{
	if (count == 1 || row >= pws->rows)
		return;

	distribute(pws->chars_at_idx[row], count, e);

	size_t u = 0;
	for (size_t i = 0; i < count; i += u) {
		u = uniq_from_entry(&e[i], count - i);
		recurse(pws, row + 1, u, &e[i + pws->cols]);
	}
}

static void generate(struct pwstream *pws)
{
	/* do a first distribution for character 0 */
	distribute(pws->chars_at_idx[0], pws->cols, pws->entry);

	/* generate the remaining entries */
	for (size_t i = 0, u = 0; i < pws->cols; i += u) {
		u = uniq(pws, 0, &pws->entry[i]);
		if (u > 1)
			recurse(pws, 1, u, get(pws, 1, i));
	}
}

static bool is_before(const struct entry *e, int c)
{
	return (c < e->start);
}

static bool is_after(const struct entry *e, int c)
{
	return (c > e->stop);
}

static bool is_enclosed(const struct entry *e, int c)
{
	return !is_before(e, c) && !is_after(e, c);
}

static void generate_initial_indexes(struct pwstream *pws,
				     const size_t *initial)
{
	for (size_t i = 0; i < pws->rows; ++i) {
		for (size_t j = 0; j < pws->cols; ++j) {
			struct entry *e = get(pws, i, j);
			if (is_enclosed(e, initial[i]))
				e->initial = initial[i];
			else if (is_after(e, initial[i]))
				e->initial = e->stop;
			else
				e->initial = e->start;
		}
	}
}

static size_t ceil_streams_pool(size_t pool_len, size_t pw_len, size_t streams)
{
	long double permut = powl((long double)pool_len, (long double)pw_len);
	if (permut == HUGE_VALL)
		/* assume we won't ever have more than HUGE_VAL streams */
		return streams;
	else if (permut < (long double)streams)
		/* more streams than permutations, return the number
		 * of permutations */
		return (size_t)permut;
	return streams;
}

static u128 u128_mul_overflow(u128 a, u128 b)
{
	if (!a || !b)
		return 0;
	if (a > UINT128_MAX / b)
		return UINT128_MAX; /* overflow */
	return (a * b);
}

static size_t ceil_streams_mask(char **parsed_mask, size_t parsed_mask_len, size_t streams)
{
	size_t len, i;
	u128 permut = 1;

	for (i = 0; i < parsed_mask_len; ++i) {
		if (!parsed_mask[i]) {
			printf("ERROR: ceil_streams_mask()\n");
			break;
		}
		len = strlen(parsed_mask[i]);
		permut = u128_mul_overflow(permut, len);
	}

	if (permut == UINT128_MAX)
		/*
		 * assume we won't ever have more than UINT128_MAX
		 * streams.
		 */
		return streams;
	else if (permut < (u128)streams)
		/*
		 * more streams than permutations, return the number
		 * of permutations.
		 */
		return (size_t)permut;
	return streams;
}

int pwstream_new(struct pwstream **pws)
{
	struct pwstream *p = calloc(1, sizeof(struct pwstream));

	if (!p)
		return -1;

	p->entry = NULL;
	p->rows = 0;
	p->cols = 0;
	p->chars_at_idx = NULL;

	*pws = p;

	return 0;
}

void pwstream_free(struct pwstream *pws)
{
	if (pws->entry)
		free(pws->entry);
	if (pws->chars_at_idx)
		free(pws->chars_at_idx);
	free(pws);
}

int pwstream_generate_from_pool(struct pwstream *pws, size_t pool_len, size_t pw_len,
		      size_t streams, const size_t *initial)
{
	if (pws->entry)
		free(pws->entry);
	if (pws->chars_at_idx)
		free(pws->chars_at_idx);

	size_t cstrm = ceil_streams_pool(pool_len, pw_len, streams);

	pws->entry = calloc(cstrm * pw_len, sizeof(struct entry));
	if (!pws->entry)
		return -1;

	pws->chars_at_idx = calloc(pw_len, sizeof(size_t));
	if (!pws->chars_at_idx)
		return -1;

	pws->rows = pw_len;
	pws->cols = cstrm;
	pws->real_cols = streams;

	/* when generating for a pool, all entries are identical */
	for (size_t i = 0; i < pw_len; ++i)
		pws->chars_at_idx[i] = pool_len;

	entry_table_init(pws, 0, pws->chars_at_idx);
	generate(pws);

	if (initial)
		generate_initial_indexes(pws, initial);

	return 0;
}

int pwstream_generate(struct pwstream *pws, size_t pool_len, size_t pw_len,
		      size_t streams, const size_t *initial)
{
	return pwstream_generate_from_pool(pws, pool_len, pw_len, streams, initial);
}

int pwstream_generate_from_mask(struct pwstream *pws, char **parsed_mask, size_t parsed_mask_len,
				size_t streams, const size_t *initial)
{
	(void)initial;

	if (pws->entry)
		free(pws->entry);
	if (pws->chars_at_idx)
		free(pws->chars_at_idx);

	size_t cstrm = ceil_streams_mask(parsed_mask, parsed_mask_len,
					 streams);

	pws->entry = calloc(cstrm * parsed_mask_len, sizeof(struct entry));
	if (!pws->entry)
		return -1;

	pws->chars_at_idx = calloc(parsed_mask_len, sizeof(size_t));
	if (!pws->chars_at_idx)
		return -1;

	pws->rows = parsed_mask_len;
	pws->cols = cstrm;
	pws->real_cols = streams;

	/* The stream table is least-significant-position first. */
	for (size_t i = 0; i < parsed_mask_len; ++i)
		pws->chars_at_idx[i] = strlen(parsed_mask[parsed_mask_len - i - 1]);

	entry_table_init(pws, 0, pws->chars_at_idx);
	generate(pws);

	if (initial)
		generate_initial_indexes(pws, initial); /* rendu iciciciic, faire compiler */

	return 0;
}

const struct entry *pwstream_get_entry(struct pwstream *pws, size_t stream,
				       size_t pos)
{
	if (stream >= pws->cols)
		return &null_entry;
	return get(pws, pos, stream);
}

size_t pwstream_get_pwlen(const struct pwstream *pws)
{
	return pws->rows;
}

size_t pwstream_get_stream_count(const struct pwstream *pws)
{
	return pws->real_cols;
}

bool pwstream_is_empty(const struct pwstream *pws, unsigned int stream)
{
	return stream >= pws->cols;
}
