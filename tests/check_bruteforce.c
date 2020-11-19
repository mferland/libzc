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
	zc_crk_bforce_force_threads(crk, 1);
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

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), -1);
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
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);
	ck_assert_str_eq(zc_crk_bforce_sanitized_charset(crk), "abcd");

	cfg.setlen = 0;
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), -1);

	cfg.setlen = ZC_CHARSET_MAXLEN;
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), -1);

	cfg.setlen = ZC_CHARSET_MAXLEN + 1;
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), -1);

}
END_TEST

START_TEST(test_parameter_init_leak)
{
	struct zc_crk_pwcfg cfg;

	strcpy(cfg.set, "abcd");
	cfg.maxlen = 5;
	cfg.setlen = 4;
	strcpy(cfg.initial, "a");

	/* first call */
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);
	ck_assert_str_eq(zc_crk_bforce_sanitized_charset(crk), "abcd");

	/* second call, should not leak */
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);
	ck_assert_str_eq(zc_crk_bforce_sanitized_charset(crk), "abcd");

	/* third call, should not leak */
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);
	ck_assert_str_eq(zc_crk_bforce_sanitized_charset(crk), "abcd");
}
END_TEST

START_TEST(test_bruteforce_password_found)
{
	struct zc_crk_pwcfg cfg;
	char out[7];

	strcpy(cfg.set, "noradiqwerty");
	cfg.maxlen = 6;
	cfg.setlen = 12;
	memset(cfg.initial, 0, ZC_PW_MAXLEN + 1);

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);

	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "noradi");
}
END_TEST

START_TEST(test_bruteforce_password_found_multicall)
{
	struct zc_crk_pwcfg cfg;
	char out[7];

	strcpy(cfg.set, "noradiqwerty");
	cfg.maxlen = 6;
	cfg.setlen = 12;
	memset(cfg.initial, 0, ZC_PW_MAXLEN + 1);

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);

	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "noradi");

	memset(out, 0, sizeof(out));
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "noradi");
}
END_TEST

START_TEST(test_bruteforce_password_not_found)
{
	struct zc_crk_pwcfg cfg;
	char out[7];

	strcpy(cfg.set, "noradiqwerty");
	cfg.maxlen = 4;
	cfg.setlen = 12;
	memset(cfg.initial, 0, ZC_PW_MAXLEN + 1);

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);

	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 1);
}
END_TEST

START_TEST(test_bruteforce_password_not_found_multicall)
{
	struct zc_crk_pwcfg cfg;
	char out[7];

	strcpy(cfg.set, "noradiqwerty");
	cfg.maxlen = 4;
	cfg.setlen = 12;
	memset(cfg.initial, 0, ZC_PW_MAXLEN + 1);

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);

	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 1);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 1);
}
END_TEST

START_TEST(test_bruteforce_stored)
{
	struct zc_crk_pwcfg cfg;
	char out[5];

	strcpy(cfg.set, "password");
	cfg.maxlen = 4;
	cfg.setlen = 8;
	memset(cfg.initial, 0, ZC_PW_MAXLEN + 1);

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);

	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "pass");
}
END_TEST

START_TEST(test_bruteforce_stored_multicall)
{
	struct zc_crk_pwcfg cfg;
	char out[5];

	strcpy(cfg.set, "password");
	cfg.maxlen = 4;
	cfg.setlen = 8;
	memset(cfg.initial, 0, ZC_PW_MAXLEN + 1);

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);

	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "pass");
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "pass");
}
END_TEST

#define CANCEL_TESTS 10

static void test_cancel(size_t threads)
{
	struct zc_crk_pwcfg cfg;
	char out[7];

	strcpy(cfg.set, "noradi");
	cfg.maxlen = 6;
	cfg.setlen = 6;
	memset(cfg.initial, 0, ZC_PW_MAXLEN + 1);

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);

	for (int i = 0; i < CANCEL_TESTS; ++i) {
		zc_crk_bforce_force_threads(crk, threads);
		ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
		ck_assert_str_eq(out, "noradi");
	}
}

START_TEST(test_bruteforce_thread_cancellation)
{
	/* Thread cancellation can easily break when making changes, if it
	   does, try to catch it here. If thread cancellation is broken
	   this loop should trigger the problem and the program will just
	   hang forever (making the test fail). */
	for (size_t i = 1; i <= 10; ++i)
		test_cancel(i);
}
END_TEST

START_TEST(test_bruteforce_pay)
{
	struct zc_crk_pwcfg cfg;
	char out[10];

	strcpy(cfg.set, "amorpheus!");
	cfg.maxlen = 10;
	cfg.setlen = 10;
	strcpy(cfg.initial, "moaaaaaaa");

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "pay.zip", &cfg), 0);
	zc_crk_bforce_force_threads(crk, 8);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "morpheus!");
}
END_TEST

#ifdef EXTRACHECK
START_TEST(test_bruteforce_pthread_create_fail)
{
	struct zc_crk_pwcfg cfg;
	char out[7];

	strcpy(cfg.set, "noradiqwerty");
	cfg.maxlen = 6;
	cfg.setlen = 12;
	memset(cfg.initial, 0, ZC_PW_MAXLEN + 1);

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "noradi.zip", &cfg), 0);

	/* create an insane amount of threads, should return an error (not
	 * crash ...) */
	zc_crk_bforce_force_threads(crk, 95884);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 1);
}
END_TEST
#endif

Suite *bforce_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("bruteforce");

	tc_core = tcase_create("Core");

	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_parameter_set);
	tcase_add_test(tc_core, test_parameter_setlen);
	tcase_add_test(tc_core, test_parameter_init_leak);
	tcase_add_test(tc_core, test_bruteforce_password_found);
	tcase_add_test(tc_core, test_bruteforce_password_found_multicall);
	tcase_add_test(tc_core, test_bruteforce_password_not_found);
	tcase_add_test(tc_core, test_bruteforce_password_not_found_multicall);
	tcase_add_test(tc_core, test_bruteforce_stored);
	tcase_add_test(tc_core, test_bruteforce_stored_multicall);
	tcase_add_test(tc_core, test_bruteforce_thread_cancellation);
	tcase_add_test(tc_core, test_bruteforce_pay);
#ifdef EXTRACHECK
	tcase_add_test(tc_core, test_bruteforce_pthread_create_fail);
#endif
	tcase_set_timeout(tc_core, 120);
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
