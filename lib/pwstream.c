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

static const struct entry null_entry = { SIZE_MAX, SIZE_MAX, SIZE_MAX };

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
 * Sorting in split_repeated() keeps identical ranges adjacent, which is what
 * makes the recursive grouping step possible.
 */

struct pwstream {
	/* Row-major table described above. */
	struct entry *table;
	/* Number of password positions. */
	size_t position_count;
	/* Number of allocated streams with work. */
	size_t active_stream_count;
	/* Number of streams requested by the caller. */
	size_t stream_count;
	/* Character count (radix) for each internal, reversed table row. */
	size_t *radix;
};

static int entry_cmp(const void *a, const void *b)
{
	const struct entry *ea = (const struct entry *)a;
	const struct entry *eb = (const struct entry *)b;

	/* since entries are always mutually exclusive, compare only the
	 * 'start' member */
	return (ea->start > eb->start) - (ea->start < eb->start);
}

static void sort_entries(struct entry *entry, size_t workers)
{
	qsort(entry, workers, sizeof(struct entry), entry_cmp);
}

/**
 * Get entry pointer at [row][col].
 */
static struct entry *entry_at(struct pwstream *pws, size_t row, size_t col)
{
	return &pws->table[pws->active_stream_count * row + col];
}

/* Fewer streams than values: divide the values into contiguous ranges.
 * Example: five values over three streams -> [0,0], [1,2], [3,4]. */
static void split_ranges(size_t values, size_t workers, struct entry *entry)
{
	/* Example: values=5 and workers=3 gives width=1 and remainder=2.
	 * Every worker receives one value, then the accumulated remainder adds
	 * an extra value whenever it reaches one complete group of 3:
	 *
	 *     worker    range    carried remainder after the worker
	 *       0       [0,0]                 2
	 *       1       [1,2]                 1  (2 + 2 passes 3)
	 *       2       [3,4]                 0  (1 + 2 reaches 3)
	 *
	 * This is equivalent to floor(i * values / workers) at each boundary,
	 * but it never evaluates the potentially overflowing multiplication. */
	size_t width = values / workers;
	size_t remainder = values % workers;
	size_t carried = 0;
	size_t start = 0;

	for (size_t i = 0; i < workers; ++i) {
		entry[i].start = start;
		entry[i].initial = start;
		start += width;

		/* Reproduce floor((i + 1) * values / workers) without allowing
		 * either the multiplication or remainder accumulation to wrap. */
		if (remainder && carried >= workers - remainder) {
			++start;
			carried -= workers - remainder;
		} else
			carried += remainder;

		entry[i].stop = start - 1;
	}
}

/* More streams than values: repeat singleton values, then sort them so all
 * equal entries are adjacent.  Later rows will subdivide those groups.
 * Example: three values over four streams -> [0], [0], [1], [2]. */
static void split_repeated(size_t values, size_t workers, struct entry *entry)
{
	for (size_t i = 0; i < workers; ++i) {
		size_t value = i % values;
		entry[i].start = value;
		entry[i].stop = value;
		entry[i].initial = value;
	}

	sort_entries(entry, workers);
}

/* One stream per value: every stream receives one singleton. */
static void split_singletons(size_t values, struct entry *entry)
{
	for (size_t i = 0; i < values; ++i) {
		entry[i].start = i;
		entry[i].stop = i;
		entry[i].initial = i;
	}
}

/* Select the appropriate splitting strategy for one row and one contiguous
 * worker group.  values is the radix, not the password length. */
/**
 * split_group - partition one row among a contiguous group of workers
 * @values: number of possible indexes at this password position
 * @workers: number of workers in the current group
 * @entry: first table cell belonging to that group on the current row
 *
 * This is the only function that assigns ranges.  Its result is always a
 * complete cover of [0, values - 1].  Ranges do not overlap, except when there
 * are more workers than values; in that case singleton ranges are repeated
 * deliberately and the next password row separates those workers.
 *
 * The caller relies on equal results being adjacent after this function.
 */
static void split_group(size_t values, size_t workers, struct entry *entry)
{
	if (workers == 1) {
		entry->start = 0;
		entry->stop = values - 1;
		entry->initial = 0;
	} else if (workers == values) {
		split_singletons(values, entry);
	} else if (workers > values) {
		split_repeated(values, workers, entry);
	} else
		split_ranges(values, workers, entry);
}

/**
 * Compares entries e1 and e2.
 */
static bool entry_equal(const struct entry *a, const struct entry *b)
{
	return (a->start == b->start && a->stop == b->stop);
}

/* Give every worker the complete range for every row.  build_table() narrows
 * only the rows needed to distinguish workers from one another. */
static void init_table(struct pwstream *pws, size_t start, const size_t *radix)
{
	/*
	 * The default stop values are taken from the radix
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

	for (size_t row = 0; row < pws->position_count; ++row) {
		for (size_t col = 0; col < pws->active_stream_count; ++col) {
			struct entry *entry = entry_at(pws, row, col);
			entry->start = start;
			entry->stop = radix[row] - 1;
			entry->initial = start;
		}
	}
}

/* Return the length of the equal-entry run at the start of entry. split_group()
 * sorts equal ranges next to one another, so generation can consume every
 * row in one linear pass without repeatedly scanning unrelated workers. */
static size_t equal_run(const struct entry *entry, size_t len)
{
	size_t count = 1; /* first entry is always equal */

	while (count < len && entry_equal(&entry[count], entry))
		++count;

	return count;
}

/**
 * split_rows - subdivide one group using progressively more-significant rows
 * @pws: table being generated
 * @row: row to assign now; row 0 was assigned by build_table()
 * @count: number of adjacent workers in this group
 * @entry: cell at [row][first worker in the group]
 *
 * Example with radix 2 and four workers:
 *
 *     current row after split_group(): [0] [0] [1] [1]
 *                                      \____/   \____/
 *                                      group A  group B
 *
 * Each two-worker group is still indistinguishable on this row.  The loop
 * calls split_rows() for each group at row + 1.  Pointer arithmetic adds
 * pws->active_stream_count to move to the same worker in the next row.
 *
 * Once a group contains one worker, all remaining cells for that worker are
 * already full ranges from init_table(), so no further work is needed.
 */
static void split_rows(struct pwstream *pws, size_t row, size_t count,
		       struct entry *entry)
{
	/* A one-worker group is already unique.  Its remaining rows keep the
	 * full ranges installed by init_table(). */
	if (count == 1 || row >= pws->position_count)
		return;

	/* entry points at the first cell in this row's contiguous group. */
	split_group(pws->radix[row], count, entry);

	/* split_group() leaves equal ranges adjacent.  Recurse for groups that
	 * still contain multiple workers and only when another row exists.
	 * Adding pws->active_stream_count advances one complete table row. */
	size_t u = 0;
	for (size_t i = 0; i < count; i += u) {
		u = equal_run(&entry[i], count - i);
		if (u > 1 && row + 1 < pws->position_count)
			split_rows(pws, row + 1, u,
				   &entry[i + pws->active_stream_count]);
	}
}

/**
 * build_table - build the complete worker/position range table
 * @pws: initialized stream with positions, streams, radices, and entries
 *
 * This is the algorithm's entry point after allocation:
 *
 *     init_table() -> split row 0 -> find equal groups
 *                  -> split each group through rows 1..N
 *
 * Row 0 is handled here because it spans every active worker.  split_rows()
 * handles later rows because each of those rows is partitioned separately
 * inside the groups produced by the preceding row.
 */
static void build_table(struct pwstream *pws)
{
	/* Row 0 is the least-significant (last password) position. */
	split_group(pws->radix[0], pws->active_stream_count, pws->table);

	/* Group workers that received the same row-0 range and use subsequent
	 * rows to distinguish the workers inside each group. */
	for (size_t i = 0, u = 0; i < pws->active_stream_count; i += u) {
		u = equal_run(&pws->table[i], pws->active_stream_count - i);
		if (u > 1)
			split_rows(pws, 1, u, entry_at(pws, 1, i));
	}
}

/**
 * set_initial - choose each worker's first complete password
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
static void set_initial(struct pwstream *pws, const size_t *initial)
{
	/* Each column is an independent rectangular password subspace. */
	for (size_t col = 0; col < pws->active_stream_count; ++col) {
		bool found = true;

		/* Compare the requested password from its most-significant (leftmost)
		 * position.  Convert natural position back to the reversed table row. */
		for (size_t pos = 0; pos < pws->position_count; ++pos) {
			size_t row = pws->position_count - pos - 1;
			size_t requested = initial[pos];
			struct entry *e = entry_at(pws, row, col);

			/* The worker's lowest value is already greater than the request at
			 * this position.  The prefix is now greater, so the smallest valid
			 * suffix is simply the start of every remaining range. */
			if (requested < e->start) {
				e->initial = e->start;
				for (++pos; pos < pws->position_count; ++pos) {
					row = pws->position_count - pos - 1;
					e = entry_at(pws, row, col);
					e->initial = e->start;
				}
				break;
			}

			/* Preserve an equal prefix for as long as the requested value is
			 * contained in this worker's range. */
			if (requested <= e->stop) {
				e->initial = requested;
				continue;
			}

			/* The requested value is above this range.  Walk left through the
			 * already matched prefix and find the nearest position that can be
			 * incremented, just like carrying in a mixed-radix counter. */
			found = false;
			while (pos > 0) {
				--pos;
				row = pws->position_count - pos - 1;
				requested = initial[pos];
				e = entry_at(pws, row, col);
				if (requested < e->stop) {
					e->initial = requested + 1;
					found = true;
					break;
				}
			}

			/* After carrying, reset every less-significant position to the
			 * smallest value owned by this worker. */
			if (found) {
				for (++pos; pos < pws->position_count; ++pos) {
					row = pws->position_count - pos - 1;
					e = entry_at(pws, row, col);
					e->initial = e->start;
				}
			}
			break;
		}

		/* No prefix position could be incremented: the worker's complete
		 * subspace precedes the requested password.  An initial value beyond
		 * the outermost stop makes the consumer's first loop empty. */
		if (!found) {
			struct entry *e = entry_at(pws, pws->position_count - 1, col);
			e->initial = e->stop + 1;
		}
	}
}

/**
 * pool_cols - determine how many non-empty columns to allocate
 *
 * stream_count retains the requested count, but active_stream_count should
 * never exceed the number of candidate passwords.  For example, a two-byte
 * pool and a two-character password have four candidates, so a request for
 * eight workers allocates four columns and marks workers 4..7 as empty.
 */
static size_t pool_cols(size_t pool_len, size_t pw_len, size_t workers)
{
	size_t permutations = 1;

	/* Only the comparison with workers matters.  Stop multiplying as soon
	 * as the search space reaches that count, avoiding both integer overflow
	 * and floating-point rounding for large password spaces. */
	for (size_t i = 0; i < pw_len; ++i) {
		if (permutations >= workers)
			return workers;

		if (pool_len > workers / permutations)
			return workers;

		permutations *= pool_len;
	}

	return permutations;
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
 * mask_cols - mixed-radix equivalent of pool_cols
 *
 * For alphabets with lengths [2, 3, 2], the search space contains 12
 * candidates.  Counting stops at the requested number of workers because
 * the exact search-space size is irrelevant once it reaches that value.
 */
static size_t mask_cols(const char *const *mask, size_t mask_len,
			size_t workers)
{
	size_t permutations = 1;

	/* A mask is a mixed-radix space, so its size is the product of the
	 * character counts at all positions.  Stop before multiplication would
	 * overflow or exceed workers; either case means every requested worker
	 * can receive a non-empty range. */
	for (size_t i = 0; i < mask_len; ++i) {
		size_t len = strlen(mask[i]);

		if (permutations >= workers)
			return workers;

		if (len > workers / permutations)
			return workers;

		permutations *= len;
	}

	return permutations;
}

int pwstream_new(struct pwstream **pws)
{
	if (!pws)
		return -1;

	struct pwstream *p = calloc(1, sizeof(struct pwstream));

	if (!p)
		return -1;

	p->table = NULL;
	p->position_count = 0;
	p->active_stream_count = 0;
	p->stream_count = 0;
	p->radix = NULL;

	*pws = p;

	return 0;
}

void pwstream_free(struct pwstream *pws)
{
	if (!pws)
		return;

	if (pws->table)
		free(pws->table);

	if (pws->radix)
		free(pws->radix);

	free(pws);
}

/**
 * pwstream_generate_from_pool - generate a uniform-radix stream table
 *
 * Setup sequence:
 *   1. Cap active columns to the number of possible passwords.
 *   2. Allocate rows * active columns cells.
 *   3. Fill every row radix with pool_len.
 *   4. Initialize full ranges and partition them with build_table().
 *   5. Apply optional starting indexes in natural password order.
 */
int pwstream_generate_from_pool(struct pwstream *pws, size_t pool_len, size_t pw_len,
				size_t streams, const size_t *initial)
{
	struct entry *table;
	size_t *radix;
	size_t bytes;
	size_t entry_count;
	size_t active_stream_count;

	/* Reject invalid dimensions before releasing an existing table. */
	if (!pws || !pool_len || !pw_len || !streams)
		return -1;

	if (initial) {
		for (size_t i = 0; i < pw_len; ++i) {
			if (initial[i] >= pool_len)
				return -1;
		}
	}

	active_stream_count = pool_cols(pool_len, pw_len, streams);

	if (size_mul_overflow(active_stream_count, pw_len, &entry_count))
		return -1;

	if (size_mul_overflow(entry_count, sizeof(struct entry), &bytes))
		return -1;

	if (size_mul_overflow(pw_len, sizeof(size_t), &bytes))
		return -1;

	/* Allocate the complete replacement before changing the current state. */
	table = calloc(entry_count, sizeof(struct entry));
	if (!table)
		return -1;

	radix = calloc(pw_len, sizeof(size_t));
	if (!radix) {
		free(table);
		return -1;
	}

	/* Pool mode is the uniform-radix case: every password position indexes
	 * the same pool and therefore has the same radix. */
	free(pws->table);
	free(pws->radix);
	pws->table = table;
	pws->radix = radix;

	pws->position_count = pw_len;
	pws->active_stream_count = active_stream_count;
	pws->stream_count = streams;

	/* when generating for a pool, all entries are identical */
	for (size_t i = 0; i < pw_len; ++i)
		pws->radix[i] = pool_len;

	init_table(pws, 0, pws->radix);
	build_table(pws);

	if (initial)
		set_initial(pws, initial);

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
 * responsibility.  Lengths are reversed into radix because table row
 * zero represents the final password character.
 *
 * The remaining setup and partitioning steps are identical to pool mode.
 */
int pwstream_generate_from_mask(struct pwstream *pws,
				const char *const *parsed_mask,
				size_t parsed_mask_len, size_t streams,
				const size_t *initial)
{
	struct entry *table;
	size_t *radix;
	size_t bytes;
	size_t entry_count;
	size_t active_stream_count;

	/* parsed_mask is supplied in natural left-to-right password order.  The
	 * table uses the reverse order, so copy only the alphabet lengths and
	 * reverse them while doing so.  The strings remain owned by the caller. */

	/* Every position must provide at least one character.  Validate before
	 * releasing an existing table so a rejected call leaves it usable. */
	if (!pws || !parsed_mask || !parsed_mask_len || !streams)
		return -1;

	for (size_t i = 0; i < parsed_mask_len; ++i) {
		size_t alphabet_len;

		if (!parsed_mask[i] || !parsed_mask[i][0])
			return -1;

		alphabet_len = strlen(parsed_mask[i]);

		if (initial && initial[i] >= alphabet_len)
			return -1;
	}

	active_stream_count = mask_cols(parsed_mask, parsed_mask_len, streams);

	if (size_mul_overflow(active_stream_count, parsed_mask_len, &entry_count))
		return -1;

	if (size_mul_overflow(entry_count, sizeof(struct entry), &bytes))
		return -1;

	if (size_mul_overflow(parsed_mask_len, sizeof(size_t), &bytes))
		return -1;

	table = calloc(entry_count, sizeof(struct entry));
	if (!table)
		return -1;

	radix = calloc(parsed_mask_len, sizeof(size_t));
	if (!radix) {
		free(table);
		return -1;
	}

	free(pws->table);
	free(pws->radix);
	pws->table = table;
	pws->radix = radix;

	pws->position_count = parsed_mask_len;
	pws->active_stream_count = active_stream_count;
	pws->stream_count = streams;

	/* The stream table is least-significant-position first. */
	for (size_t i = 0; i < parsed_mask_len; ++i)
		pws->radix[i] = strlen(parsed_mask[parsed_mask_len - i - 1]);

	init_table(pws, 0, pws->radix);
	build_table(pws);

	if (initial)
		/* Initial indexes use natural left-to-right password order. */
		set_initial(pws, initial);

	return 0;
}

const struct entry *pwstream_get_entry(struct pwstream *pws, size_t stream,
				       size_t pos)
{
	/* pos is an internal table row: pos 0 is the last password character. */
	if (!pws || stream >= pws->active_stream_count ||
	    pos >= pws->position_count)
		return &null_entry;

	return entry_at(pws, pos, stream);
}

size_t pwstream_get_pwlen(const struct pwstream *pws)
{
	return pws ? pws->position_count : 0;
}

size_t pwstream_get_stream_count(const struct pwstream *pws)
{
	/* Return the requested count so callers can retain one worker object per
	 * request.  pwstream_is_empty() identifies inactive streams. */
	return pws ? pws->stream_count : 0;
}

bool pwstream_is_empty(const struct pwstream *pws, size_t stream)
{
	return !pws || stream >= pws->active_stream_count;
}
