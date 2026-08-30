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
 * OVERVIEW
 * --------
 * A pwstream divides a password search space among independent workers.
 * Every worker receives a rectangular set of index ranges, so it can use
 * ordinary nested loops without coordinating with any other worker.
 * Together, the workers cover every password exactly once.
 *
 * A password position is a digit in a mixed-radix counter.  A traditional
 * character pool uses the same radix at every position.  A mask may use a
 * different radix at each position:
 *
 *     mask:        [ab] [0-2] [XY]
 *     natural pos:   0    1     2
 *     radix:         2    3     2       (2 * 3 * 2 = 12 passwords)
 *
 * Internally, rows are stored least-significant position first.  Therefore
 * row 0 describes the final password character, row 1 the preceding one,
 * and so on:
 *
 *     table row:     2    1     0
 *     password:    [ab] [0-2] [XY]
 *
 * This ordering lets the algorithm partition the fast-changing final
 * character first, then recursively partition earlier characters whenever
 * several workers still have the same range.
 *
 * TABLE LAYOUT
 * ------------
 * Each cell is an inclusive {start, stop, initial} index range.  The table
 * is row-major: all workers for row 0, followed by all workers for row 1.
 *
 *                  worker/column
 *                 0       1       2       ...
 *              +-------+-------+-------+
 * row 0 (last) | e[0]  | e[1]  | e[2]  |
 * row 1        | e[C]  | e[C+1]| e[C+2]|
 * row 2 (first)| e[2C] | e[2C+1] ...   |
 *              +-------+-------+-------+
 *
 * For pool {a,b,c}, length 3, split into 4 workers, the ranges are:
 *
 *     worker  row2(first) row1       row0(last)
 *       0       [a,a]     [a,a]        [a,c]
 *       1       [a,a]     [b,c]        [a,c]
 *       2       [b,b]     [a,c]        [a,c]
 *       3       [c,c]     [a,c]        [a,c]
 *
 * For worker 1, the consumer effectively runs:
 *
 *     for first  in [a,a]
 *       for middle in [b,c]
 *         for last in [a,c]
 *           test(first, middle, last)
 *
 * GENERATION
 * ----------
 * 1. Initialize every cell to the full range for its row.
 * 2. Divide row 0 among all active workers.
 * 3. Workers with identical row-0 ranges form a group.
 * 4. Divide row 1 separately inside each group.
 * 5. Repeat for later rows until every group contains one worker or there
 *    are no rows left.
 *
 * Sorting in split_more() keeps identical ranges adjacent, which is what
 * makes the recursive grouping step possible.
 */

struct pwstream {
	/* Row-major table described above. */
	struct entry *entry;
	size_t initial;
	/* rows=password length; cols=allocated non-empty worker columns. */
	size_t rows;
	size_t cols;
	/* Number of workers requested by the caller; may exceed cols. */
	size_t real_cols;
	/* Character count (radix) for each internal, reversed table row. */
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

/* Fewer streams than values: divide the values into contiguous ranges.
 * Example: five values over three streams -> [0,0], [1,2], [3,4]. */
static void split_less(size_t plen, size_t streams, struct entry *t)
{
	for (size_t i = 0; i < streams; ++i) {
		int start = (i * plen) / streams;
		t[i].start = start;
		t[i].initial = start;
		t[i].stop = ((i + 1) * plen) / streams - 1;
	}
}

/* More streams than values: repeat singleton values, then sort them so all
 * equal entries are adjacent.  Later rows will subdivide those groups.
 * Example: three values over four streams -> [0], [0], [1], [2]. */
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

/* One stream per value: every stream receives one singleton. */
static void split_equal(size_t plen, struct entry *e)
{
	for (size_t i = 0; i < plen; ++i) {
		e[i].start = i;
		e[i].stop = i;
		e[i].initial = i;
	}
}

/* Select the appropriate splitting strategy for one row and one contiguous
 * worker group.  plen is the radix of this row, not the password length. */
/**
 * distribute - partition one row among a contiguous group of workers
 * @plen: number of possible indexes at this password position
 * @streams: number of workers in the current group
 * @entry: first table cell belonging to that group on the current row
 *
 * This is the only function that assigns ranges.  Its result is always a
 * complete cover of [0, plen - 1].  Ranges do not overlap, except when there
 * are more workers than values; in that case singleton ranges are repeated
 * deliberately and the next password row separates those workers.
 *
 * The caller relies on equal results being adjacent after this function.
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

/* Give every worker the complete range for every row.  generate() narrows
 * only the rows needed to distinguish workers from one another. */
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
	 * Example for natural mask "abc?d" (reversed in the table):
	 * +----+---+---+---+
	 * | 10 | 1 | 1 | 1 |
	 * +----+---+---+---+
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

/* Count all workers on row that have the same range as e.  generate() uses
 * this only on row 0, whose equal ranges were sorted into adjacent groups. */
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

/* Count entries equal to the first cell within the remaining portion of a
 * worker group.  Because distribute() sorts equal ranges, the returned count
 * is also the width of the next contiguous subgroup. */
static size_t uniq_from_entry(const struct entry *e, size_t len)
{
	size_t count = 1; /* first entry is always equal */
	for (size_t i = 1; i < len; ++i) {
		if (is_equal_entries(&e[i], e))
			++count;
	}
	return count;
}

/**
 * recurse - subdivide one group using progressively more-significant rows
 * @pws: table being generated
 * @row: row to assign now; row 0 was assigned by generate()
 * @count: number of adjacent workers in this group
 * @e: cell at [row][first worker in the group]
 *
 * Example with radix 2 and four workers:
 *
 *     current row after distribute(): [0] [0] [1] [1]
 *                                      \____/   \____/
 *                                      group A  group B
 *
 * Each two-worker group is still indistinguishable on this row.  The loop
 * calls recurse() for each group at row + 1.  Pointer arithmetic adds
 * pws->cols to move vertically to the same worker in the next table row.
 *
 * Once a group contains one worker, all remaining cells for that worker are
 * already full ranges from entry_table_init(), so no further work is needed.
 */
static void recurse(struct pwstream *pws, size_t row, size_t count, struct entry *e)
{
	/* A one-worker group is already unique.  Its remaining rows keep the
	 * full ranges installed by entry_table_init(). */
	if (count == 1 || row >= pws->rows)
		return;

	/* e points at this row's first cell for the current contiguous group. */
	distribute(pws->chars_at_idx[row], count, e);

	/* distribute() leaves equal ranges adjacent.  Recurse for groups that
	 * still contain multiple workers and only when another row exists.
	 * Adding pws->cols advances one complete table row. */
	size_t u = 0;
	for (size_t i = 0; i < count; i += u) {
		u = uniq_from_entry(&e[i], count - i);
		if (u > 1 && row + 1 < pws->rows)
			recurse(pws, row + 1, u, &e[i + pws->cols]);
	}
}

/**
 * generate - build the complete worker/position range table
 * @pws: initialized stream with rows, cols, radices, and full-range entries
 *
 * This is the algorithm's entry point after allocation:
 *
 *     entry_table_init() -> distribute row 0 -> find equal groups
 *                        -> recurse each group through rows 1..N
 *
 * Row 0 is handled here because it spans every active worker.  recurse()
 * handles later rows because each of those rows is partitioned separately
 * inside the groups produced by the preceding row.
 */
static void generate(struct pwstream *pws)
{
	/* Row 0 is the least-significant (last password) position. */
	distribute(pws->chars_at_idx[0], pws->cols, pws->entry);

	/* Group workers that received the same row-0 range and use subsequent
	 * rows to distinguish the workers inside each group. */
	for (size_t i = 0, u = 0; i < pws->cols; i += u) {
		u = uniq(pws, 0, &pws->entry[i]);
		if (u > 1)
			recurse(pws, 1, u, get(pws, 1, i));
	}
}

/**
 * generate_initial_indexes - choose each worker's first complete password
 * @pws: generated range table
 * @initial: requested indexes in natural left-to-right password order
 *
 * Find the lexicographically smallest password in each worker's rectangular
 * range that is greater than or equal to the requested password.  Natural
 * password order is most-significant position first, while table rows are
 * stored in reverse order.
 *
 * If matching the requested prefix becomes impossible, increment the nearest
 * earlier position that still has room and reset the suffix to its starts.
 * If no earlier position can be incremented, set the most-significant row's
 * initial index past its stop value; the consumer's outer loop then skips
 * this worker entirely.
 *
 * Example: pool "abc", password length 2, two workers.  Row 0 (the final
 * character) is divided first:
 *
 *     worker 0 ranges: [a-c][a]  -> aa, ba, ca
 *     worker 1 ranges: [a-c][b-c] -> ab, ac, bb, bc, cb, cc
 *
 * With requested initial password "bb":
 *
 *     worker 0: "ba" is too small and its final position cannot advance.
 *               Carry into the first position and reset the suffix:
 *               ba -> ca.  Worker 0 starts at "ca".
 *
 *     worker 1: both requested indexes are inside its ranges.
 *               Worker 1 starts exactly at "bb".
 *
 * With requested initial password "cc", worker 0 has no candidate at or
 * after the request.  Its outer initial index is set to stop + 1, while
 * worker 1 starts exactly at "cc".
 */
static void generate_initial_indexes(struct pwstream *pws,
				     const size_t *initial)
{
	/* Each column is an independent rectangular password subspace. */
	for (size_t col = 0; col < pws->cols; ++col) {
		bool found = true;

		/* Compare the requested password from its most-significant (leftmost)
		 * position.  Convert natural position back to the reversed table row. */
		for (size_t pos = 0; pos < pws->rows; ++pos) {
			size_t row = pws->rows - pos - 1;
			size_t requested = initial[pos];
			struct entry *e = get(pws, row, col);

			/* The worker's lowest value is already greater than the request at
			 * this position.  The prefix is now greater, so the smallest valid
			 * suffix is simply the start of every remaining range. */
			if (requested < (size_t)e->start) {
				e->initial = e->start;
				for (++pos; pos < pws->rows; ++pos) {
					row = pws->rows - pos - 1;
					e = get(pws, row, col);
					e->initial = e->start;
				}
				break;
			}

			/* Preserve an equal prefix for as long as the requested value is
			 * contained in this worker's range. */
			if (requested <= (size_t)e->stop) {
				e->initial = requested;
				continue;
			}

			/* The requested value is above this range.  Walk left through the
			 * already matched prefix and find the nearest position that can be
			 * incremented, just like carrying in a mixed-radix counter. */
			found = false;
			while (pos > 0) {
				--pos;
				row = pws->rows - pos - 1;
				requested = initial[pos];
				e = get(pws, row, col);
				if (requested < (size_t)e->stop) {
					e->initial = requested + 1;
					found = true;
					break;
				}
			}

			/* After carrying, reset every less-significant position to the
			 * smallest value owned by this worker. */
			if (found) {
				for (++pos; pos < pws->rows; ++pos) {
					row = pws->rows - pos - 1;
					e = get(pws, row, col);
					e->initial = e->start;
				}
			}
			break;
		}

		/* No prefix position could be incremented: the worker's complete
		 * subspace precedes the requested password.  An initial value beyond
		 * the outermost stop makes the consumer's first loop empty. */
		if (!found) {
			struct entry *e = get(pws, pws->rows - 1, col);
			e->initial = e->stop + 1;
		}
	}
}

/**
 * ceil_streams_pool - determine how many non-empty columns to allocate
 *
 * real_cols retains the caller's requested worker count, but cols should
 * never exceed the number of candidate passwords.  For example, a two-byte
 * pool and a two-character password have four candidates, so a request for
 * eight workers allocates four columns and marks workers 4..7 as empty.
 */
static size_t ceil_streams_pool(size_t pool_len, size_t pw_len, size_t streams)
{
	size_t permutations = 1;

	/* Only the comparison with streams matters.  Stop multiplying as soon
	 * as the search space reaches that count, avoiding both integer overflow
	 * and floating-point rounding for large password spaces. */
	for (size_t i = 0; i < pw_len; ++i) {
		if (permutations >= streams)
			return streams;
		if (pool_len > streams / permutations)
			return streams;
		permutations *= pool_len;
	}

	return permutations;
}

static u128 u128_mul_overflow(u128 a, u128 b)
{
	if (!a || !b)
		return 0;
	if (a > UINT128_MAX / b)
		return UINT128_MAX; /* overflow */
	return (a * b);
}

/* Return true instead of allowing an allocation element count to wrap. */
static bool size_mul_overflow(size_t a, size_t b, size_t *result)
{
	if (a && b > SIZE_MAX / a)
		return true;
	*result = a * b;
	return false;
}

/**
 * ceil_streams_mask - mixed-radix equivalent of ceil_streams_pool
 *
 * For alphabets with lengths [2, 3, 2], the search space contains 12
 * candidates.  Multiplication saturates at UINT128_MAX so a very large mask
 * is treated as having at least as many candidates as requested workers.
 */
static size_t ceil_streams_mask(char **parsed_mask, size_t parsed_mask_len, size_t streams)
{
	size_t len, i;
	u128 permut = 1;

	/* A mask is a mixed-radix space, so its size is the product of the
	 * character counts at all positions.  Saturation is sufficient because
	 * this result is used only to cap the requested worker count. */
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
	if (!pws)
		return -1;

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

/**
 * pwstream_generate_from_pool - generate a uniform-radix stream table
 *
 * Setup sequence:
 *   1. Cap active columns to the number of possible passwords.
 *   2. Allocate rows * active columns cells.
 *   3. Fill every row radix with pool_len.
 *   4. Initialize full ranges and partition them with generate().
 *   5. Apply optional starting indexes in natural password order.
 */
int pwstream_generate_from_pool(struct pwstream *pws, size_t pool_len, size_t pw_len,
		      size_t streams, const size_t *initial)
{
	struct entry *new_entry;
	size_t *new_chars_at_idx;
	size_t tmp_size;
	size_t entry_count;
	size_t cstrm;

	/* Reject invalid dimensions before releasing an existing table. */
	if (!pws || !pool_len || !pw_len || !streams)
		return -1;
	cstrm = ceil_streams_pool(pool_len, pw_len, streams);
	if (size_mul_overflow(cstrm, pw_len, &entry_count))
		return -1;
	if (size_mul_overflow(entry_count, sizeof(struct entry), &tmp_size))
		return -1;
	if (size_mul_overflow(pw_len, sizeof(size_t), &tmp_size))
		return -1;

	/* Allocate the complete replacement before changing the current state. */
	new_entry = calloc(entry_count, sizeof(struct entry));
	if (!new_entry)
		return -1;
	new_chars_at_idx = calloc(pw_len, sizeof(size_t));
	if (!new_chars_at_idx) {
		free(new_entry);
		return -1;
	}

	/* Pool mode is the uniform-radix case: every password position indexes
	 * the same pool and therefore has the same chars_at_idx value. */
	free(pws->entry);
	free(pws->chars_at_idx);
	pws->entry = new_entry;
	pws->chars_at_idx = new_chars_at_idx;

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
	/* Historical name retained for pool-mode callers. */
	return pwstream_generate_from_pool(pws, pool_len, pw_len, streams, initial);
}

/**
 * pwstream_generate_from_mask - generate a mixed-radix stream table
 *
 * parsed_mask contains one alphabet per natural password position.  This
 * function needs only their lengths; character lookup remains the caller's
 * responsibility.  Lengths are reversed into chars_at_idx because table row
 * zero represents the final password character.
 *
 * The remaining setup and partitioning steps are identical to pool mode.
 */
int pwstream_generate_from_mask(struct pwstream *pws, char **parsed_mask, size_t parsed_mask_len,
				size_t streams, const size_t *initial)
{
	struct entry *new_entry;
	size_t *new_chars_at_idx;
	size_t tmp_size;
	size_t entry_count;
	size_t cstrm;

	(void)initial;
	/* parsed_mask is supplied in natural left-to-right password order.  The
	 * table uses the reverse order, so copy only the alphabet lengths and
	 * reverse them while doing so.  The strings remain owned by the caller. */

	/* Every position must provide at least one character.  Validate before
	 * releasing an existing table so a rejected call leaves it usable. */
	if (!pws || !parsed_mask || !parsed_mask_len || !streams)
		return -1;
	for (size_t i = 0; i < parsed_mask_len; ++i) {
		if (!parsed_mask[i] || !parsed_mask[i][0])
			return -1;
	}
	cstrm = ceil_streams_mask(parsed_mask, parsed_mask_len, streams);
	if (size_mul_overflow(cstrm, parsed_mask_len, &entry_count))
		return -1;
	if (size_mul_overflow(entry_count, sizeof(struct entry), &tmp_size))
		return -1;
	if (size_mul_overflow(parsed_mask_len, sizeof(size_t), &tmp_size))
		return -1;

	new_entry = calloc(entry_count, sizeof(struct entry));
	if (!new_entry)
		return -1;
	new_chars_at_idx = calloc(parsed_mask_len, sizeof(size_t));
	if (!new_chars_at_idx) {
		free(new_entry);
		return -1;
	}

	free(pws->entry);
	free(pws->chars_at_idx);
	pws->entry = new_entry;
	pws->chars_at_idx = new_chars_at_idx;

	pws->rows = parsed_mask_len;
	pws->cols = cstrm;
	pws->real_cols = streams;

	/* The stream table is least-significant-position first. */
	for (size_t i = 0; i < parsed_mask_len; ++i)
		pws->chars_at_idx[i] = strlen(parsed_mask[parsed_mask_len - i - 1]);

	entry_table_init(pws, 0, pws->chars_at_idx);
	generate(pws);

	if (initial)
		/* Initial indexes use natural left-to-right password order. */
		generate_initial_indexes(pws, initial);

	return 0;
}

const struct entry *pwstream_get_entry(struct pwstream *pws, size_t stream,
				       size_t pos)
{
	/* pos is an internal table row: pos 0 is the last password character. */
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
	/* Return the requested count so callers can retain one worker object per
	 * request.  pwstream_is_empty() identifies workers beyond active cols. */
	return pws->real_cols;
}

bool pwstream_is_empty(const struct pwstream *pws, unsigned int stream)
{
	return stream >= pws->cols;
}
