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
	struct zc_crk_pwcfg cfg = {0};

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
	struct zc_crk_pwcfg cfg = {0};

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
	struct zc_crk_pwcfg cfg = {0};

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

START_TEST(test_parameter_mask_init_leak)
{
	struct zc_crk_pwcfg cfg = {0};

	cfg.mask.str = "p[ba][xs][xs]";

	/* Reinitializing replaces the owned parsed mask each time. */
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);
}
END_TEST

START_TEST(test_reinitialize_mask_as_charset)
{
	struct zc_crk_pwcfg cfg = {0};
	char out[5];

	/* Establish mask mode with a search space that cannot find "pass". */
	cfg.mask.str = "xxxx";
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);

	/* Reinitialize the same cracker in charset mode.  A stale parsed-mask
	 * length would incorrectly make zc_crk_bforce_start() reuse "xxxx". */
	memset(&cfg, 0, sizeof(cfg));
	strcpy(cfg.set, "pas");
	cfg.setlen = 3;
	cfg.maxlen = 4;
	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "pass");
}
END_TEST

START_TEST(test_reject_initial_password_outside_set)
{
	struct zc_crk_pwcfg cfg = {0};

	strcpy(cfg.set, "abc");
	cfg.setlen = 3;
	cfg.maxlen = 3;
	/* 'd' cannot be converted to an index in the configured set. */
	strcpy(cfg.initial, "abd");

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), -1);
}
END_TEST

START_TEST(test_reject_initial_password_outside_mask)
{
	struct zc_crk_pwcfg cfg = {0};

	cfg.mask.str = "[ab][cd]";
	/* 'e' cannot be converted to an index in the second mask alphabet. */
	strcpy(cfg.initial, "ae");

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), -1);
}
END_TEST

START_TEST(test_bruteforce_password_found)
{
	struct zc_crk_pwcfg cfg = {0};
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
	struct zc_crk_pwcfg cfg = {0};
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
	struct zc_crk_pwcfg cfg = {0};
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
	struct zc_crk_pwcfg cfg = {0};
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
	struct zc_crk_pwcfg cfg = {0};
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
	struct zc_crk_pwcfg cfg = {0};
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

START_TEST(test_bruteforce_mask)
{
	struct zc_crk_pwcfg cfg = {0};
	char out[5];

	/* The first candidate is "pbxx"; "pass" requires selecting the second
	 * character from all three variable positions.  Multiple workers exercise
	 * the complete parser -> pwstream -> candidate lookup path. */
	cfg.mask.str = "p[ba][xs][xs]";

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);
	zc_crk_bforce_force_threads(crk, 8);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "pass");
}
END_TEST

static const char mask_options_password[] = "aA0!fF?\x80??";

static void assert_mask_config_finds_options_password(const char *mask,
						      size_t minlen,
						      size_t maxlen)
{
	struct zc_crk_pwcfg cfg = {0};
	char out[sizeof(mask_options_password)];

	cfg.mask.str = mask;
	cfg.mask.minlen = minlen;
	cfg.mask.maxlen = maxlen;

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "mask_options.zip",
					      &cfg), 0);
	zc_crk_bforce_force_threads(crk, 8);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_mem_eq(out, mask_options_password,
			 sizeof(mask_options_password));
}

static void assert_mask_finds_options_password(const char *mask)
{
	assert_mask_config_finds_options_password(mask, 0, 0);
}

START_TEST(test_bruteforce_mask_literals)
{
	/* Exercise ordinary literals plus both escaped '?' and a hexadecimal
	 * byte escape. */
	assert_mask_finds_options_password("aA0!fF\\?\\x80\\?\\?");
}
END_TEST

static const char *const mask_range_cases[] = {
	"[ba]A0!fF\\?\\x80\\?\\?",  /* explicit character list */
	"[a-c]A0!fF\\?\\x80\\?\\?", /* lowercase range */
	"a[A-C]0!fF\\?\\x80\\?\\?", /* uppercase range */
	"aA[0-2]!fF\\?\\x80\\?\\?", /* numeric range */
};

START_TEST(test_bruteforce_mask_ranges)
{
	assert_mask_finds_options_password(mask_range_cases[_i]);
}
END_TEST

static const char *const mask_placeholder_cases[] = {
	"?lA0!fF\\?\\x80\\?\\?",    /* lowercase */
	"a?u0!fF\\?\\x80\\?\\?",    /* uppercase */
	"aA?d!fF\\?\\x80\\?\\?",    /* decimal digit */
	"aA0?sfF\\?\\x80\\?\\?",    /* special character */
	"aA0!fF?a\\x80\\?\\?",       /* printable ASCII */
	"aA0!fF\\??B\\?\\?",          /* upper 8-bit range */
	"aA0!fF\\??b\\?\\?",          /* every non-NUL byte */
	"aA0!?hF\\?\\x80\\?\\?",    /* lowercase hexadecimal */
	"aA0!f?H\\?\\x80\\?\\?",    /* uppercase hexadecimal */
};

START_TEST(test_bruteforce_mask_placeholders)
{
	assert_mask_finds_options_password(mask_placeholder_cases[_i]);
}
END_TEST

static const char *const mask_maxlen_cases[] = {
	/* No ranges: repeat the final literal '?'. */
	"aA0!fF\\?\\x80\\?",
	/* The final position is a range, so repeat it. */
	"aA0!fF\\?\\x80[!\\?]",
	/* An earlier range does not change the rule: repeat the final literal. */
	"a[A-C]0!fF\\?\\x80\\?",
};

START_TEST(test_bruteforce_mask_maxlen)
{
	assert_mask_config_finds_options_password(mask_maxlen_cases[_i], 0, 10);
}
END_TEST

START_TEST(test_bruteforce_initial_password_boundary)
{
	struct zc_crk_pwcfg cfg = {0};
	char out[5];

	/* Pool order is p < a < s.  The archive password is exactly the
	 * requested initial password and must still be tested. */
	strcpy(cfg.set, "pas");
	cfg.maxlen = 4;
	cfg.setlen = 3;
	strcpy(cfg.initial, "pass");

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);
	zc_crk_bforce_force_threads(crk, 8);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 0);
	ck_assert_str_eq(out, "pass");
}
END_TEST

START_TEST(test_bruteforce_skips_password_before_initial)
{
	struct zc_crk_pwcfg cfg = {0};
	char out[5];

	/* With pool order p < a < s, "saaa" is after "pass" because its
	 * first character is greater.  The cracker must not retry "pass". */
	strcpy(cfg.set, "pas");
	cfg.maxlen = 4;
	cfg.setlen = 3;
	strcpy(cfg.initial, "saaa");

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);
	zc_crk_bforce_force_threads(crk, 8);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 1);
}
END_TEST

START_TEST(test_bruteforce_mask_skips_password_before_initial)
{
	struct zc_crk_pwcfg cfg = {0};
	char out[5];

	/* "pass" precedes "saaa" in this mask's mixed-radix order.  Starting
	 * from the requested initial password must therefore skip the archive
	 * password rather than eventually finding it. */
	cfg.mask.str = "[ps][ab][as][as]";
	strcpy(cfg.initial, "saaa");

	ck_assert_int_eq(zc_crk_bforce_init(crk, DATADIR "stored.zip", &cfg), 0);
	zc_crk_bforce_force_threads(crk, 8);
	ck_assert_int_eq(zc_crk_bforce_start(crk, out, sizeof(out)), 1);
}
END_TEST

#define CANCEL_TESTS 10

static void test_cancel(size_t threads)
{
	struct zc_crk_pwcfg cfg = {0};
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
	struct zc_crk_pwcfg cfg = {0};
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
	struct zc_crk_pwcfg cfg = {0};
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
	tcase_add_test(tc_core, test_parameter_mask_init_leak);
	tcase_add_test(tc_core, test_reinitialize_mask_as_charset);
	tcase_add_test(tc_core, test_reject_initial_password_outside_set);
	tcase_add_test(tc_core, test_reject_initial_password_outside_mask);
	tcase_add_test(tc_core, test_bruteforce_password_found);
	tcase_add_test(tc_core, test_bruteforce_password_found_multicall);
	tcase_add_test(tc_core, test_bruteforce_password_not_found);
	tcase_add_test(tc_core, test_bruteforce_password_not_found_multicall);
	tcase_add_test(tc_core, test_bruteforce_stored);
	tcase_add_test(tc_core, test_bruteforce_stored_multicall);
	tcase_add_test(tc_core, test_bruteforce_mask);
	tcase_add_test(tc_core, test_bruteforce_mask_literals);
	tcase_add_loop_test(tc_core, test_bruteforce_mask_ranges, 0,
			    sizeof(mask_range_cases) / sizeof(mask_range_cases[0]));
	tcase_add_loop_test(tc_core, test_bruteforce_mask_placeholders, 0,
			    sizeof(mask_placeholder_cases) /
			    sizeof(mask_placeholder_cases[0]));
	tcase_add_loop_test(tc_core, test_bruteforce_mask_maxlen, 0,
			    sizeof(mask_maxlen_cases) /
			    sizeof(mask_maxlen_cases[0]));
	tcase_add_test(tc_core, test_bruteforce_initial_password_boundary);
	tcase_add_test(tc_core, test_bruteforce_skips_password_before_initial);
	tcase_add_test(tc_core, test_bruteforce_mask_skips_password_before_initial);
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
