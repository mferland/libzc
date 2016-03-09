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

#include <check.h>
#include <stdlib.h>

#include "libzc_private.h"
#include "pwstream.h"

struct pwstream *pws;

struct entry {
    int start, stop;
};

void setup_pws()
{
    pwstream_new(&pws);
}

void teardown_pws()
{
    pwstream_free(pws);
}

static void test_generated_stream(const struct entry *ref, struct pwstream *pws)
{
    size_t streams = pwstream_get_stream_count(pws);
    size_t pwlen = pwstream_get_pwlen(pws);
    for (int i = 0; i < streams; ++i)
        for (int j = 0; j < pwlen; ++j) {
            ck_assert_int_eq(pwstream_get_start_idx(pws, i, j),
                              ref[i * pwlen + j].start);
            ck_assert_int_eq(pwstream_get_stop_idx(pws, i, j),
                              ref[i * pwlen + j].stop);

            /* printf("%d, %d\n", pwstream_get_start_idx(pws, i, j), */
            /*        pwstream_get_stop_idx(pws, i, j)); */
        }
}

/*
   pool len: 2
   pw len: 2
   streams: 5
 */
static const struct entry over_streams1[] = {
    {0, 0}, {0, 0},
    {0, 0}, {1, 1},
    {1, 1}, {0, 0},
    {1, 1}, {1, 1},
    {-1, -1}, {-1, -1},
};
START_TEST(generate_over_streams1)
{
    pwstream_generate(pws, 2, 2, 5);
    test_generated_stream(over_streams1, pws);
}
END_TEST

/*
   pool len: 1
   pw len: 2
   streams: 5
 */
static const struct entry over_streams2[] = {
    {0, 0}, {0, 0},
    {-1, -1}, {-1, -1},
    {-1, -1}, {-1, -1},
    {-1, -1}, {-1, -1},
    {-1, -1}, {-1, -1}
};
START_TEST(generate_over_streams2)
{
    pwstream_generate(pws, 1, 2, 5);
    test_generated_stream(over_streams2, pws);
}
END_TEST

/*
   pool len: 1
   pw len: 1
   streams: 5
 */
static const struct entry over_streams3[] = {
    {0, 0},
    {-1, -1},
    {-1, -1},
    {-1, -1},
    {-1, -1}
};
START_TEST(generate_over_streams3)
{
    pwstream_generate(pws, 1, 1, 5);
    test_generated_stream(over_streams3, pws);
}
END_TEST

/*
   pool len: 3
   pw len: 5
   streams: 5
 */
static const struct entry less[] = {
    {0, 0}, {0, 0}, {0, 2}, {0, 2}, {0, 2},
    {0, 0}, {1, 2}, {0, 2}, {0, 2}, {0, 2},
    {1, 1}, {0, 0}, {0, 2}, {0, 2}, {0, 2},
    {1, 1}, {1, 2}, {0, 2}, {0, 2}, {0, 2},
    {2, 2}, {0, 2}, {0, 2}, {0, 2}, {0, 2}
};
START_TEST(generate_less)
{
    pwstream_generate(pws, 3, 5, 5);
    test_generated_stream(less, pws);
}
END_TEST

/*
   pool len: 3
   pw len: 5
   streams: 10
 */
static const struct entry less1[] = {
    {0, 0}, {0, 0}, {0, 0}, {0, 2}, {0, 2},
    {0, 0}, {0, 0}, {1, 2}, {0, 2}, {0, 2},
    {0, 0}, {1, 1}, {0, 2}, {0, 2}, {0, 2},
    {0, 0}, {2, 2}, {0, 2}, {0, 2}, {0, 2},
    {1, 1}, {0, 0}, {0, 2}, {0, 2}, {0, 2},
    {1, 1}, {1, 1}, {0, 2}, {0, 2}, {0, 2},
    {1, 1}, {2, 2}, {0, 2}, {0, 2}, {0, 2},
    {2, 2}, {0, 0}, {0, 2}, {0, 2}, {0, 2},
    {2, 2}, {1, 1}, {0, 2}, {0, 2}, {0, 2},
    {2, 2}, {2, 2}, {0, 2}, {0, 2}, {0, 2}
};
START_TEST(generate_less1)
{
    pwstream_generate(pws, 3, 5, 10);
    test_generated_stream(less1, pws);
}
END_TEST

/*
  pool len: 8
  pw len: 5
  streams: 5
 */
static const struct entry more[] = {
    {0, 0}, {0, 7}, {0, 7}, {0, 7}, {0, 7},
    {1, 2}, {0, 7}, {0, 7}, {0, 7}, {0, 7},
    {3, 3}, {0, 7}, {0, 7}, {0, 7}, {0, 7},
    {4, 5}, {0, 7}, {0, 7}, {0, 7}, {0, 7},
    {6, 7}, {0, 7}, {0, 7}, {0, 7}, {0, 7}
};
START_TEST(generate_more)
{
    pwstream_generate(pws, 8, 5, 5);
    test_generated_stream(more, pws);
}
END_TEST

/*
  pool len: 5
  pw len: 5
  streams: 5
 */
static const struct entry equal[] = {
    {0, 0}, {0, 4}, {0, 4}, {0, 4}, {0, 4},
    {1, 1}, {0, 4}, {0, 4}, {0, 4}, {0, 4},
    {2, 2}, {0, 4}, {0, 4}, {0, 4}, {0, 4},
    {3, 3}, {0, 4}, {0, 4}, {0, 4}, {0, 4},
    {4, 4}, {0, 4}, {0, 4}, {0, 4}, {0, 4}
};
START_TEST(generate_equal)
{
    pwstream_generate(pws, 5, 5, 5);
    test_generated_stream(equal, pws);
}
END_TEST

Suite *make_libzc_pws_suite()
{
    Suite *s = suite_create("pws");

    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup_pws, teardown_pws);
    tcase_add_test(tc_core, generate_over_streams1);
    tcase_add_test(tc_core, generate_over_streams2);
    tcase_add_test(tc_core, generate_over_streams3);
    tcase_add_test(tc_core, generate_less);
    tcase_add_test(tc_core, generate_less1);
    tcase_add_test(tc_core, generate_more);
    tcase_add_test(tc_core, generate_equal);
    suite_add_tcase(s, tc_core);

    return s;
}

int main()
{
    int number_failed;
    SRunner *sr = srunner_create(make_libzc_pws_suite());
    srunner_set_log(sr, "test_pws.log");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
