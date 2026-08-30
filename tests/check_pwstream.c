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

#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "libzc_private.h"
#include "pwstream.h"

struct pwstream *pws;

void setup_pws()
{
	pwstream_new(&pws);
}

void teardown_pws()
{
	pwstream_free(pws);
}

static void test_generated_stream(const struct entry *ref)
{
	size_t streams = pwstream_get_stream_count(pws);
	size_t pwlen = pwstream_get_pwlen(pws);
	for (size_t i = 0; i < streams; ++i) {
		for (size_t j = 0; j < pwlen; ++j) {
			const struct entry *e = pwstream_get_entry(pws, i, j);
			ck_assert_int_eq(e->start, ref[i * pwlen + j].start);
			ck_assert_int_eq(e->stop, ref[i * pwlen + j].stop);
			ck_assert_int_eq(e->initial, ref[i * pwlen + j].initial);
			/* printf("%d, %d\n", pwstream_get_start_idx(pws, i, j), */
			/*        pwstream_get_stop_idx(pws, i, j)); */
		}
	}
}

/*
  pool len: 3
  pw len: 3
  streams: 3
 */
static const struct entry test_initial1[] = {
	{0, 0, 0}, {0, 2, 0}, {0, 2, 0},
	{1, 1, 1}, {0, 2, 0}, {0, 2, 0},
	{2, 2, 2}, {0, 2, 0}, {0, 2, 0},
};
START_TEST(generate_test_initial1)
{
	pwstream_generate(pws, 3, 3, 3, NULL);
	test_generated_stream(test_initial1);
}
END_TEST

static void assert_mixed_mask_coverage(char **mask, size_t len,
					 size_t streams)
{
	struct pwstream *m;
	size_t total = 1;
	unsigned char *seen;

	for (size_t i = 0; i < len; ++i)
		total *= strlen(mask[i]);
	ck_assert_int_eq(pwstream_new(&m), 0);
	ck_assert_int_eq(pwstream_generate_from_mask(m, mask, len, streams,
							 NULL), 0);
	seen = calloc(total, 1);
	ck_assert_ptr_nonnull(seen);

	for (size_t s = 0; s < streams; ++s) {
		const struct entry *e[len];
		for (size_t p = 0; p < len; ++p)
			e[p] = pwstream_get_entry(m, s, len - p - 1);
		for (size_t a = 0; a < strlen(mask[0]); ++a)
			for (size_t b = 0; b < strlen(mask[1]); ++b)
				for (size_t c = 0; c < strlen(mask[2]); ++c) {
					size_t key = (a * strlen(mask[1]) + b) * strlen(mask[2]) + c;
					bool in = a >= (size_t)e[0]->start && a <= (size_t)e[0]->stop &&
						b >= (size_t)e[1]->start && b <= (size_t)e[1]->stop &&
						c >= (size_t)e[2]->start && c <= (size_t)e[2]->stop;
					if (in) {
						ck_assert_int_eq(seen[key], 0);
						seen[key] = 1;
					}
				}
	}
	for (size_t i = 0; i < total; ++i)
		ck_assert_int_eq(seen[i], 1);
	free(seen);
	pwstream_free(m);
}

START_TEST(generate_mixed_mask_coverage)
{
	char *mask[] = { "ab", "cde", "xy" };
	assert_mixed_mask_coverage(mask, 3, 1);
	assert_mixed_mask_coverage(mask, 3, 2);
	assert_mixed_mask_coverage(mask, 3, 4);
	assert_mixed_mask_coverage(mask, 3, 6);
	assert_mixed_mask_coverage(mask, 3, 12);
}
END_TEST

START_TEST(generate_literal_mask_and_initial)
{
	char *literal[] = { "a", "b", "c" };
	char *mask[] = { "ab", "cde", "xy" };
	const size_t initial[] = { 1, 2, 1 };
	struct pwstream *m;

	ck_assert_int_eq(pwstream_new(&m), 0);
	ck_assert_int_eq(pwstream_generate_from_mask(m, literal, 3, 8, NULL), 0);
	ck_assert_int_eq(pwstream_get_stream_count(m), 8);
	ck_assert(pwstream_is_empty(m, 1));
	for (size_t p = 0; p < 3; ++p) {
		const struct entry *e = pwstream_get_entry(m, 0, p);
		ck_assert_int_eq(e->start, 0);
		ck_assert_int_eq(e->stop, 0);
	}
	ck_assert_int_eq(pwstream_generate_from_mask(m, mask, 3, 4, initial), 0);
	for (size_t s = 0; s < 4; ++s)
		for (size_t p = 0; p < 3; ++p) {
			const struct entry *e = pwstream_get_entry(m, s, p);
			ck_assert(e->initial >= e->start);
			ck_assert(e->initial <= e->stop);
		}
	pwstream_free(m);
}
END_TEST

START_TEST(regenerate_mixed_mask)
{
	char *first[] = { "ab", "cde", "xy" };
	char *second[] = { "a", "bc", "def" };
	struct pwstream *m;

	ck_assert_int_eq(pwstream_new(&m), 0);
	ck_assert_int_eq(pwstream_generate_from_mask(m, first, 3, 4, NULL), 0);
	ck_assert_int_eq(pwstream_generate_from_mask(m, second, 3, 4, NULL), 0);
	pwstream_free(m);
}
END_TEST

/* Force the partitioner to use every row.  With three binary positions and
 * eight streams, each final-row subgroup resolves to exactly one worker.
 * recurse() must stop there instead of constructing a pointer to row 3. */
START_TEST(generate_recursion_stops_at_last_row)
{
	char *mask[] = { "ab", "cd", "xy" };
	struct pwstream *m;

	ck_assert_int_eq(pwstream_new(&m), 0);
	ck_assert_int_eq(pwstream_generate_from_mask(m, mask, 3, 8, NULL), 0);

	for (size_t stream = 0; stream < 8; ++stream) {
		ck_assert(!pwstream_is_empty(m, stream));
		for (size_t row = 0; row < 3; ++row) {
			const struct entry *e = pwstream_get_entry(m, stream, row);
			ck_assert_int_eq(e->start, e->stop);
		}
	}

	pwstream_free(m);
}
END_TEST

/*
  pool len: 3
  pw len: 3
  streams: 3
 */
static const struct entry test_initial2[] = {
	{0, 0, 0}, {0, 2, 0}, {0, 2, 0},
	{1, 1, 1}, {0, 2, 0}, {0, 2, 0},
	{2, 2, 2}, {0, 2, 0}, {0, 2, 0},
};
static const size_t initial2[] = {0, 0, 0};
START_TEST(generate_test_initial2)
{
	pwstream_generate(pws, 3, 3, 3, initial2);
	test_generated_stream(test_initial2);
}
END_TEST

/*
  pool len: 3
  pw len: 3
  streams: 3
 */
static const struct entry test_initial3[] = {
	{0, 0, 0}, {0, 2, 1}, {0, 2, 0},
	{1, 1, 1}, {0, 2, 1}, {0, 2, 0},
	{2, 2, 2}, {0, 2, 1}, {0, 2, 0},
};
static const size_t initial3[] = {0, 1, 0};
START_TEST(generate_test_initial3)
{
	pwstream_generate(pws, 3, 3, 3, initial3);
	test_generated_stream(test_initial3);
}
END_TEST

/*
  pool len: 3
  pw len: 3
  streams: 3
 */
static const struct entry test_initial4[] = {
	{0, 0, 0}, {0, 2, 1}, {0, 2, 0},
	{1, 1, 1}, {0, 2, 1}, {0, 2, 0},
	{2, 2, 2}, {0, 2, 1}, {0, 2, 0},
};
static const size_t initial4[] = {1, 1, 0};
START_TEST(generate_test_initial4)
{
	pwstream_generate(pws, 3, 3, 3, initial4);
	test_generated_stream(test_initial4);
}
END_TEST

/*
  pool len: 3
  pw len: 3
  streams: 3
 */
static const struct entry test_initial5[] = {
	{0, 0, 0}, {0, 2, 1}, {0, 2, 1},
	{1, 1, 1}, {0, 2, 1}, {0, 2, 1},
	{2, 2, 2}, {0, 2, 1}, {0, 2, 1},
};
static const size_t initial5[] = {1, 1, 1};
START_TEST(generate_test_initial5)
{
	pwstream_generate(pws, 3, 3, 3, initial5);
	test_generated_stream(test_initial5);
}
END_TEST

/*
  pool len: 3
  pw len: 3
  streams: 2
 */
static const struct entry test_initial6[] = {
	{0, 0, 0}, {0, 2, 0}, {0, 2, 0},
	{1, 2, 2}, {0, 2, 0}, {0, 2, 0},
};
static const size_t initial6[] = {2, 0, 0};
START_TEST(generate_test_initial6)
{
	pwstream_generate(pws, 3, 3, 2, initial6);
	test_generated_stream(test_initial6);
}
END_TEST

/*
  pool len: 3
  pw len: 3
  streams: 2
 */
static const struct entry test_initial7[] = {
	{0, 0, 0}, {0, 2, 2}, {0, 2, 0},
	{1, 2, 2}, {0, 2, 2}, {0, 2, 0},
};
static const size_t initial7[] = {2, 2, 0};
START_TEST(generate_test_initial7)
{
	pwstream_generate(pws, 3, 3, 2, initial7);
	test_generated_stream(test_initial7);
}
END_TEST

/*
   pool len: 2
   pw len: 2
   streams: 5
 */
static const struct entry over_streams1[] = {
	{0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {1, 1, 1},
	{1, 1, 1}, {0, 0, 0},
	{1, 1, 1}, {1, 1, 1},
	{ -1, -1, -1}, { -1, -1, -1},
};
START_TEST(generate_over_streams1)
{
	pwstream_generate(pws, 2, 2, 5, NULL);
	test_generated_stream(over_streams1);
}
END_TEST

/*
   pool len: 1
   pw len: 2
   streams: 5
 */
static const struct entry over_streams2[] = {
	{0, 0, 0}, {0, 0, 0},
	{ -1, -1, -1}, { -1, -1, -1},
	{ -1, -1, -1}, { -1, -1, -1},
	{ -1, -1, -1}, { -1, -1, -1},
	{ -1, -1, -1}, { -1, -1, -1}
};
START_TEST(generate_over_streams2)
{
	pwstream_generate(pws, 1, 2, 5, NULL);
	test_generated_stream(over_streams2);
}
END_TEST

/*
   pool len: 1
   pw len: 1
   streams: 5
 */
static const struct entry over_streams3[] = {
	{0, 0, 0},
	{ -1, -1, -1},
	{ -1, -1, -1},
	{ -1, -1, -1},
	{ -1, -1, -1}
};
START_TEST(generate_over_streams3)
{
	pwstream_generate(pws, 1, 1, 5, NULL);
	test_generated_stream(over_streams3);
}
END_TEST

/*
   pool len: 3
   pw len: 5
   streams: 5
 */
static const struct entry less[] = {
	{0, 0, 0}, {0, 0, 0}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{0, 0, 0}, {1, 2, 1}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{1, 1, 1}, {0, 0, 0}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{1, 1, 1}, {1, 2, 1}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{2, 2, 2}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0}
};
START_TEST(generate_less)
{
	pwstream_generate(pws, 3, 5, 5, NULL);
	test_generated_stream(less);
}
END_TEST

/*
   pool len: 3
   pw len: 5
   streams: 10
 */
static const struct entry less1[] = {
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 2, 0}, {0, 2, 0},
	{0, 0, 0}, {0, 0, 0}, {1, 2, 1}, {0, 2, 0}, {0, 2, 0},
	{0, 0, 0}, {1, 1, 1}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{0, 0, 0}, {2, 2, 2}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{1, 1, 1}, {0, 0, 0}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{1, 1, 1}, {1, 1, 1}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{1, 1, 1}, {2, 2, 2}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{2, 2, 2}, {0, 0, 0}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{2, 2, 2}, {1, 1, 1}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0},
	{2, 2, 2}, {2, 2, 2}, {0, 2, 0}, {0, 2, 0}, {0, 2, 0}
};
START_TEST(generate_less1)
{
	pwstream_generate(pws, 3, 5, 10, NULL);
	test_generated_stream(less1);
}
END_TEST

/*
  pool len: 8
  pw len: 5
  streams: 5
 */
static const struct entry more[] = {
	{0, 0, 0}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0},
	{1, 2, 1}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0},
	{3, 3, 3}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0},
	{4, 5, 4}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0},
	{6, 7, 6}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0}, {0, 7, 0}
};
START_TEST(generate_more)
{
	pwstream_generate(pws, 8, 5, 5, NULL);
	test_generated_stream(more);
}
END_TEST

/*
  pool len: 5
  pw len: 5
  streams: 5
 */
static const struct entry equal[] = {
	{0, 0, 0}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0},
	{1, 1, 1}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0},
	{2, 2, 2}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0},
	{3, 3, 3}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0},
	{4, 4, 4}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0}, {0, 4, 0}
};
START_TEST(generate_equal)
{
	pwstream_generate(pws, 5, 5, 5, NULL);
	test_generated_stream(equal);
}
END_TEST

Suite *pwstream_suite()
{
	Suite *s = suite_create("pwstream");

	TCase *tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup_pws, teardown_pws);
	tcase_add_test(tc_core, generate_test_initial1);
	tcase_add_test(tc_core, generate_test_initial2);
	tcase_add_test(tc_core, generate_test_initial3);
	tcase_add_test(tc_core, generate_test_initial4);
	tcase_add_test(tc_core, generate_test_initial5);
	tcase_add_test(tc_core, generate_test_initial6);
	tcase_add_test(tc_core, generate_test_initial7);
	tcase_add_test(tc_core, generate_over_streams1);
	tcase_add_test(tc_core, generate_over_streams2);
	tcase_add_test(tc_core, generate_over_streams3);
	tcase_add_test(tc_core, generate_less);
	tcase_add_test(tc_core, generate_less1);
	tcase_add_test(tc_core, generate_more);
	tcase_add_test(tc_core, generate_equal);
	tcase_add_test(tc_core, generate_mixed_mask_coverage);
	tcase_add_test(tc_core, generate_literal_mask_and_initial);
	tcase_add_test(tc_core, regenerate_mixed_mask);
	tcase_add_test(tc_core, generate_recursion_stops_at_last_row);
	suite_add_tcase(s, tc_core);

	return s;
}

int main()
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = pwstream_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
