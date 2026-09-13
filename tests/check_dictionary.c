/*
 *  yazc - ZIP password recovery application
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

#include "dictionary.h"

#define LEN 20
struct zc_dictionary *ctx;
char pw[LEN];

static void setup()
{
	ck_assert_int_eq(zc_dictionary_new(&ctx), 0);
	ck_assert_ptr_nonnull(ctx);
}

static void teardown()
{
	zc_dictionary_destroy(ctx);
}

START_TEST(test_init_file_not_found)
{
	ck_assert_int_eq(zc_dictionary_init(ctx, "doesnotexits.zip"), -1);
}
END_TEST

START_TEST(test_init_file_found)
{
	ck_assert_int_eq(zc_dictionary_init(ctx, DATADIR "noradi.zip"), 0);
}
END_TEST

START_TEST(test_start_requires_initialization)
{
	ck_assert_int_eq(zc_dictionary_start(ctx, DATADIR "dict.txt", pw,
					     LEN), -1);
}
END_TEST

START_TEST(test_start_rejects_small_buffer)
{
	ck_assert_int_eq(zc_dictionary_init(ctx, DATADIR "noradi.zip"), 0);
	ck_assert_int_eq(zc_dictionary_start(ctx, DATADIR "dict.txt", pw, 0), -1);
	ck_assert_int_eq(zc_dictionary_start(ctx, DATADIR "dict.txt", pw, 1), -1);
	ck_assert_int_eq(zc_dictionary_start(ctx, DATADIR "dict.txt", pw, 2), -1);
}
END_TEST

START_TEST(test_dictionary_not_found)
{
	ck_assert_int_eq(zc_dictionary_init(ctx, DATADIR "noradi.zip"), 0);
	ck_assert_int_eq(zc_dictionary_start(ctx, "doesnotexits", pw, LEN), -1);
}
END_TEST

START_TEST(test_dictionary_success)
{
	ck_assert_int_eq(zc_dictionary_init(ctx, DATADIR "noradi.zip"), 0);
	ck_assert_int_eq(zc_dictionary_start(ctx, DATADIR "dict.txt", pw, LEN), 0);
	ck_assert_str_eq(pw, "noradi");
}
END_TEST

START_TEST(test_dictionary_password_not_found)
{
	ck_assert_int_eq(zc_dictionary_init(ctx, DATADIR "noradi.zip"), 0);
	ck_assert_int_eq(zc_dictionary_start(ctx, DATADIR "pw.txt", pw, LEN), 1);
}
END_TEST

Suite *dictionary_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("dictionary");

	tc_core = tcase_create("Core");

	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_init_file_not_found);
	tcase_add_test(tc_core, test_init_file_found);
	tcase_add_test(tc_core, test_start_requires_initialization);
	tcase_add_test(tc_core, test_start_rejects_small_buffer);
	tcase_add_test(tc_core, test_dictionary_not_found);
	tcase_add_test(tc_core, test_dictionary_success);
	tcase_add_test(tc_core, test_dictionary_password_not_found);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = dictionary_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
