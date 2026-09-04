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
/* libzc */
#include <libzc.h>

START_TEST(test_zc_file_lifecycle)
{
	struct zc_file *file;

	ck_assert_int_eq(zc_file_new_from_filename(DATADIR "test.zip", &file), 0);
	ck_assert_ptr_nonnull(file);
	ck_assert_int_eq(zc_file_open(file), 0);
	zc_file_destroy(file);
	zc_file_destroy(NULL);
}
END_TEST

START_TEST(test_zc_crk_dict_lifecycle)
{
	struct zc_crk_dict *crk;

	ck_assert_int_eq(zc_crk_dict_new(&crk), 0);
	ck_assert_ptr_nonnull(crk);
	ck_assert_int_eq(zc_crk_dict_init(crk, DATADIR "noradi.zip"), 0);
	zc_crk_dict_destroy(crk);
	zc_crk_dict_destroy(NULL);
}
END_TEST

START_TEST(test_zc_crk_bforce_lifecycle)
{
	struct zc_crk_bforce *crk;

	ck_assert_int_eq(zc_crk_bforce_new(&crk), 0);
	ck_assert_ptr_nonnull(crk);
	zc_crk_bforce_destroy(crk);
	zc_crk_bforce_destroy(NULL);
}
END_TEST

START_TEST(test_zc_crk_ptext_lifecycle)
{
	struct zc_crk_ptext *ptext;

	ck_assert_int_eq(zc_crk_ptext_new(&ptext, -1), 0);
	ck_assert_ptr_nonnull(ptext);
	zc_crk_ptext_destroy(ptext);
	zc_crk_ptext_destroy(NULL);
}
END_TEST

Suite *basic_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Basic");

	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_zc_file_lifecycle);
	tcase_add_test(tc_core, test_zc_crk_dict_lifecycle);
	tcase_add_test(tc_core, test_zc_crk_bforce_lifecycle);
	tcase_add_test(tc_core, test_zc_crk_ptext_lifecycle);
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
