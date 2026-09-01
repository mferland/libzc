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
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

#include "compat.h"

START_TEST(test_reallocarray_rejects_overflow)
{
	volatile size_t count = SIZE_MAX;
	int *values = malloc(sizeof(*values));
	void *result;

	ck_assert_ptr_nonnull(values);
	values[0] = 42;
	errno = 0;

	result = reallocarray(values, count, 2);

	ck_assert_ptr_null(result);
	ck_assert_int_eq(errno, ENOMEM);
	ck_assert_int_eq(values[0], 42);
	free(values);
}
END_TEST

static Suite *compat_suite(void)
{
	Suite *suite = suite_create("Compatibility");
	TCase *tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_reallocarray_rejects_overflow);
	suite_add_tcase(suite, tc_core);

	return suite;
}

int main(void)
{
	Suite *suite = compat_suite();
	SRunner *runner = srunner_create(suite);
	int number_failed;

	srunner_run_all(runner, CK_NORMAL);
	number_failed = srunner_ntests_failed(runner);
	srunner_free(runner);

	return number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
