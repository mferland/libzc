/*
 *  zc - zip crack library
 *  Copyright (C) 2016  Marc Ferland
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
#include <stdbool.h>
#include <math.h>

#include "libzc_private.h"

/*
   TODO:
   - rename first, last --> start, stop
 */

struct entry {
    int first, last;
};

struct pwstream {
    struct entry *entry;
    size_t rows;
    size_t cols;
    size_t real_cols;
    size_t plen;
};

static int compare_entries(const void *a, const void *b)
{
  const struct entry *ea = (const struct entry *)a;
  const struct entry *eb = (const struct entry *)b;

  /* since entries are always mutually exclusive, compare only the
   * 'first' member */
  return (ea->first > eb->first) - (ea->first < eb->first);
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
        t[i].first = (i * plen) / streams;
        t[i].last = ((i + 1) * plen) / streams - 1;
    }
}

/**
 * 1,2,3 in 4 streams ==> [1],[1],[2],[3]
 */
static void split_more(size_t plen, size_t streams, struct entry *e)
{
    for (size_t i = 0; i < streams; ++i) {
        e[i].first = i % plen;
        e[i].last = i % plen;
    }
    sort(e, streams);
}

/**
 * 1,2,3,4 in 4 streams ==> [1],[2],[3],[4]
 */
static void split_equal(size_t plen, struct entry *e)
{
    for (size_t i = 0; i < plen; ++i) {
        e[i].first = i;
        e[i].last = i;
    }
}

/**
 * Distribute sequence @seq in @streams and store the result at @entry.
 */
static void distribute(size_t plen, size_t streams, struct entry *entry)
{
    if (streams == 1) {
        entry->first = 0;
        entry->last = plen - 1;
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
    return (e1->first == e2->first && e1->last == e2->last);
}

/**
 * Initialize entry table with default values.
 */
static void entry_table_init(struct pwstream *t, int first, int last)
{
    for (size_t i = 0; i < t->rows * t->cols; ++i) {
        t->entry[i].first = first;
        t->entry[i].last = last;
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
    size_t count = 1;           /* first entry is always equal */
    for (size_t i = 1; i < len; ++i) {
        if (is_equal_entries(&e[i], e))
            ++count;
    }
    return count;
}

static void recurse(struct pwstream *t, size_t count, struct entry *e)
{
    if (count == 1)
        return;

    distribute(t->plen, count, e);

    size_t u = 0;
    for (size_t i = 0; i < count; i += u) {
        u = uniq_from_entry(&e[i], count);
        recurse(t, u, &e[i + t->cols]);
    }
}

static void generate(struct pwstream *pws)
{
    /* do a first distribution for character 0 */
    distribute(pws->plen, pws->cols, pws->entry);

    /* generate the remaining entries */
    for (size_t i = 0, u = 0; i < pws->cols; i += u) {
        u = uniq(pws, 0, &pws->entry[i]);
        if (u > 1)
            recurse(pws, u, get(pws, 1, i));
    }
}

int pwstream_new(struct pwstream **pws)
{
    struct pwstream *p = malloc(sizeof(struct pwstream));

    if (!p)
        return -1;

    p->entry = NULL;
    p->rows = 0;
    p->cols = 0;
    p->plen = 0;

    *pws = p;

    return 0;
}

void pwstream_free(struct pwstream *pws)
{
    if (pws->entry)
        free(pws->entry);
    free(pws);
}

static size_t ceil_streams(size_t pool_len, size_t pw_len, size_t streams)
{
    long double permut = powl((long double)pool_len, (long double)pw_len);
    if (permut == HUGE_VALL)
        /* assume we won't ever have more than HUGE_VAL streams */
        return streams;
    else if (permut < (long double)streams)
        return (size_t)permut;
    return streams;
}

int pwstream_generate(struct pwstream *pws, size_t pool_len, size_t pw_len, size_t streams)
{
    if (pws->entry)
        free(pws->entry);

    size_t cstrm = ceil_streams(pool_len, pw_len, streams);

    pws->entry = malloc(sizeof(struct entry) * cstrm * pw_len);
    if (!pws->entry) {
        pws->rows = 0;
        pws->cols = 0;
        pws->plen = 0;
        return -1;
    }

    pws->rows = pw_len;
    pws->cols = cstrm;
    pws->plen = pool_len;
    pws->real_cols = streams;

    entry_table_init(pws, 0, pool_len - 1);
    generate(pws);

    return 0;
}

int pwstream_get_start_idx(struct pwstream *pws, unsigned int stream, unsigned int pos)
{
    if (stream >= pws->cols)
        return -1;
    return get(pws, pos, stream)->first;
}

int pwstream_get_stop_idx(struct pwstream *pws, unsigned int stream, unsigned int pos)
{
    if (stream >= pws->cols)
        return -1;
    return get(pws, pos, stream)->last;
}

size_t pwstream_get_pwlen(const struct pwstream *pws)
{
    return pws->rows;
}

size_t pwstream_get_stream_count(const struct pwstream *pws)
{
    return pws->real_cols;
}

bool pwstream_is_empty(struct pwstream *pws, unsigned int stream)
{
    return pwstream_get_start_idx(pws, stream, 0) == -1;
}
