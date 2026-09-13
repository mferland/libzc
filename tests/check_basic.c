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
#include "bruteforce.h"
#include "dictionary.h"
#include "plaintext.h"
#include "zip.h"

START_TEST(test_zc_zip_lifecycle)
{
	struct zc_zip *zip;

	ck_assert_int_eq(zc_zip_new_from_filename(DATADIR "test.zip", &zip), 0);
	ck_assert_ptr_nonnull(zip);
	ck_assert_int_eq(zc_zip_open(zip), 0);
	zc_zip_destroy(zip);
	zc_zip_destroy(NULL);
}
END_TEST

START_TEST(test_zc_dictionary_lifecycle)
{
	struct zc_dictionary *ctx;

	ck_assert_int_eq(zc_dictionary_new(&ctx), 0);
	ck_assert_ptr_nonnull(ctx);
	ck_assert_int_eq(zc_dictionary_init(ctx, DATADIR "noradi.zip"), 0);
	zc_dictionary_destroy(ctx);
	zc_dictionary_destroy(NULL);
}
END_TEST

START_TEST(test_zc_bruteforce_lifecycle)
{
	struct zc_bruteforce *ctx;

	ck_assert_int_eq(zc_bruteforce_new(&ctx), 0);
	ck_assert_ptr_nonnull(ctx);
	zc_bruteforce_destroy(ctx);
	zc_bruteforce_destroy(NULL);
}
END_TEST

START_TEST(test_zc_plaintext_lifecycle)
{
	struct zc_plaintext *ctx;

	ck_assert_int_eq(zc_plaintext_new(&ctx, -1), 0);
	ck_assert_ptr_nonnull(ctx);
	zc_plaintext_destroy(ctx);
	zc_plaintext_destroy(NULL);
}
END_TEST

Suite *basic_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Basic");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_zc_zip_lifecycle);
	tcase_add_test(tc_core, test_zc_dictionary_lifecycle);
	tcase_add_test(tc_core, test_zc_bruteforce_lifecycle);
	tcase_add_test(tc_core, test_zc_plaintext_lifecycle);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = basic_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
