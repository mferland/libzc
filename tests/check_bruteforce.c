/*
 *  zc - zip crack library
 *  Copyright (C) 2017  Marc Ferland
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
#include <stdio.h>

#include "libzc.h"

struct zc_ctx *ctx;
struct zc_crk_bforce *crk;

static void setup()
{
    zc_new(&ctx);
    zc_crk_bforce_new(ctx, &crk);
}

static void teardown()
{
    zc_crk_bforce_unref(crk);
    zc_unref(ctx);
}

START_TEST(test_parameter_set)
{
    struct zc_crk_pwcfg cfg;

    /* empty set */
    memset(cfg.set, 0, ZC_CHARSET_MAXLEN + 1);
    cfg.setlen = 5;
    cfg.maxlen = 5;
    memcpy(cfg.initial, "test", 5);

    ck_assert_int_eq(zc_crk_bforce_init(crk, "../data/noradi.zip", &cfg), -1);
}
END_TEST

START_TEST(test_parameter_setlen)
{
    struct zc_crk_pwcfg cfg;

    /* wrong setlen */
    strcpy(cfg.set, "aaaaabcd");
    cfg.maxlen = 5;
    strcpy(cfg.initial, "a");

    /* sanitze will correct the setlen */
    cfg.setlen = 8;
    ck_assert_int_eq(zc_crk_bforce_init(crk, "../data/noradi.zip", &cfg), 0);
    ck_assert_str_eq(zc_crk_bforce_sanitized_charset(crk), "abcd");

    cfg.setlen = 0;
    ck_assert_int_eq(zc_crk_bforce_init(crk, "../data/noradi.zip", &cfg), -1);

    cfg.setlen = ZC_CHARSET_MAXLEN;
    ck_assert_int_eq(zc_crk_bforce_init(crk, "../data/noradi.zip", &cfg), -1);

    cfg.setlen = ZC_CHARSET_MAXLEN + 1;
    ck_assert_int_eq(zc_crk_bforce_init(crk, "../data/noradi.zip", &cfg), -1);

}
END_TEST

Suite * bforce_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("bruteforce");

    tc_core = tcase_create("Core");

    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_parameter_set);
    tcase_add_test(tc_core, test_parameter_setlen);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = bforce_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
