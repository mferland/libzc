/*
 *  zc - zip crack library
 *  Copyright (C) 2014  Marc Ferland
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

struct ka *a;

void setup_ka()
{
    int err;
    err = ka_alloc(&a, 1024);
    fail_if(err != 0);
    fail_if(a == 0);
}

void teardown_ka()
{
    ka_free(a);
}

START_TEST(test_ka_new)
{
    int err;
    a = 0;
    err = ka_alloc(&a, 0);
    fail_if(err == 0);
    fail_if(a != 0);
    ka_free(a);
}
END_TEST

START_TEST(test_ka_append)
{
    ka_append(a, 0x12345678);
    fail_if(a->size != 1024 + 1);
    fail_if(a->capacity != 2048);
}
END_TEST

START_TEST(test_ka_append_multi)
{
    for (int i = 0; i < 1024; ++i) {
        ka_append(a, 1);
        fail_if(a->size != 1024 + i + 1);
        fail_if(a->capacity != 2048);
    }
}
END_TEST

START_TEST(test_ka_uniq1)
{
    a->array[0] = 0;
    a->array[1] = 0;
    for (int i = 2; i < 1024; ++i) {
        a->array[i] = i;
    }
    ka_uniq(a);
    fail_if(a->size != 1023);
    fail_if(a->array[0] != 0);
    for (int i = 1; i < a->size; ++i)
        fail_if(a->array[i] != i + 1);
}
END_TEST

START_TEST(test_ka_uniq2)
{
    for (int i = 0; i < 1024; ++i)
        a->array[i] = 0;
    ka_uniq(a);
    fail_if(a->size != 1);
    fail_if(a->array[0] != 0);
}
END_TEST

START_TEST(test_ka_uniq3)
{
    for (int i = 0; i < 1024; ++i)
        a->array[i] = i;
    ka_uniq(a);
    fail_if(a->size != 1024);
    for (int i = 0; i < 1024; ++i)
        fail_if(a->array[i] != i);
}
END_TEST

START_TEST(test_ka_squeeze1)
{
    ka_squeeze(a);
    fail_if(a->size != 1024);
    fail_if(a->capacity != 1024);
}
END_TEST

START_TEST(test_ka_squeeze2)
{
    for (int i = 0; i < 1024; ++i)
        a->array[i] = 0;
    ka_uniq(a);
    fail_if(a->size != 1);
    fail_if(a->capacity != 1024);
    ka_squeeze(a);
    fail_if(a->size != 1);
    fail_if(a->capacity != 1);
}
END_TEST

START_TEST(test_ka_empty1)
{
    ka_empty(a);
    fail_if(a->size != 0);
}
END_TEST

START_TEST(test_ka_empty2)
{
    ka_empty(a);
    ka_uniq(a);
    fail_if(a->size != 0);
    fail_if(a->capacity != 1024);
}
END_TEST

START_TEST(test_ka_empty3)
{
    ka_empty(a);
    ka_squeeze(a);
    fail_if(a->size != 0);
    fail_if(a->capacity != 0);
    fail_if(a->array != 0);
}
END_TEST

START_TEST(test_ka_empty4)
{
    ka_empty(a);
    ka_squeeze(a);
    ka_append(a, 5);
    fail_if(a->size != 1);
    fail_if(a->capacity != 1024);
    fail_if(a->array == 0);
}
END_TEST

Suite *make_libzc_ka_suite()
{
    Suite *s = suite_create("key array");

    TCase *tc_nofix = tcase_create("No fixtures");
    tcase_add_test(tc_nofix, test_ka_new);
    suite_add_tcase(s, tc_nofix);

    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup_ka, teardown_ka);
    tcase_add_test(tc_core, test_ka_append);
    tcase_add_test(tc_core, test_ka_append_multi);
    tcase_add_test(tc_core, test_ka_uniq1);
    tcase_add_test(tc_core, test_ka_uniq2);
    tcase_add_test(tc_core, test_ka_uniq3);
    tcase_add_test(tc_core, test_ka_squeeze1);
    tcase_add_test(tc_core, test_ka_squeeze2);
    tcase_add_test(tc_core, test_ka_empty1);
    tcase_add_test(tc_core, test_ka_empty2);
    tcase_add_test(tc_core, test_ka_empty3);
    tcase_add_test(tc_core, test_ka_empty4);
    suite_add_tcase(s, tc_core);

    return s;
}

int main()
{
    int number_failed;
    SRunner *sr = srunner_create(make_libzc_ka_suite());
    srunner_set_log(sr, "test_ka.log");
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
