/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2017 Marc Ferland
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

struct zc_ctx *ctx;

void setup(void)
{
    zc_new(&ctx);
}

void teardown(void)
{
    zc_unref(ctx);
}

START_TEST(test_zc_log_priority)
{
    zc_set_log_priority(ctx, 2);
    ck_assert_int_eq(zc_get_log_priority(ctx), 2);
}
END_TEST

START_TEST(test_zc_refcount)
{
    struct zc_ctx *p;

    ck_assert_ptr_eq(zc_ref(ctx), ctx);    /* inc */

    p = zc_unref(ctx);
    ck_assert_ptr_eq(p, ctx);              /* dec */
    ctx = p;

    p = zc_unref(ctx);
    ck_assert_ptr_eq(p, NULL);             /* dec */
    ctx = p;

    ck_assert_ptr_eq(zc_unref(NULL), NULL);
}
END_TEST

START_TEST(test_zc_file_refcount)
{
    struct zc_file *file, *tmp;
    int ret;

    ret = zc_file_new_from_filename(ctx, "dummy", &file);
    ck_assert_int_eq(ret, 0);

    tmp = zc_file_ref(file);
    ck_assert_ptr_eq(tmp, file);                 /* inc */
    file = tmp;

    tmp = zc_file_unref(file);
    ck_assert_ptr_eq(tmp, file);                 /* dec */
    file = tmp;

    tmp = zc_file_unref(file);
    ck_assert_ptr_eq(tmp, NULL);                 /* dec */

    ck_assert_ptr_eq(zc_file_unref(NULL), NULL); /* dec */
}
END_TEST

START_TEST(test_zc_crk_dict_refcount)
{
    struct zc_crk_dict *p, *tmp;
    int ret;

    ret = zc_crk_dict_new(ctx, &p);
    ck_assert_int_eq(ret, 0);

    tmp = zc_crk_dict_ref(p);
    ck_assert_ptr_eq(tmp, p);                        /* inc */
    p = tmp;

    tmp = zc_crk_dict_unref(p);
    ck_assert_ptr_eq(tmp, p);                        /* dec */
    p = tmp;

    tmp = zc_crk_dict_unref(p);
    ck_assert_ptr_eq(tmp, NULL);                     /* dec */

    ck_assert_ptr_eq(zc_crk_dict_unref(NULL), NULL); /* dec */
}
END_TEST

START_TEST(test_zc_crk_bforce_refcount)
{
    struct zc_crk_bforce *p, *tmp;
    int ret;

    ret = zc_crk_bforce_new(ctx, &p);
    ck_assert_int_eq(ret, 0);

    tmp = zc_crk_bforce_ref(p);
    ck_assert_ptr_eq(tmp, p);                          /* inc */
    p = tmp;

    tmp = zc_crk_bforce_unref(p);
    ck_assert_ptr_eq(tmp, p);                          /* dec */
    p = tmp;

    tmp = zc_crk_bforce_unref(p);
    ck_assert_ptr_eq(tmp, NULL);                       /* dec */

    ck_assert_ptr_eq(zc_crk_bforce_unref(NULL), NULL); /* dec */
}
END_TEST

START_TEST(test_zc_crk_ptext_refcount)
{
    struct zc_crk_ptext *p, *tmp;
    int ret;

    ret = zc_crk_ptext_new(ctx, &p);
    ck_assert_int_eq(ret, 0);

    tmp = zc_crk_ptext_ref(p);
    ck_assert_ptr_eq(tmp, p);                         /* inc */
    p = tmp;

    tmp = zc_crk_ptext_unref(p);
    ck_assert_ptr_eq(tmp, p);                         /* dec */
    p = tmp;

    tmp = zc_crk_ptext_unref(p);
    ck_assert_ptr_eq(tmp, NULL);                      /* dec */

    ck_assert_ptr_eq(zc_crk_ptext_unref(NULL), NULL); /* dec */
}
END_TEST

Suite *basic_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Basic");

    tc_core = tcase_create("Core");

    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_zc_log_priority);
    tcase_add_test(tc_core, test_zc_refcount);
    tcase_add_test(tc_core, test_zc_file_refcount);
    tcase_add_test(tc_core, test_zc_crk_dict_refcount);
    tcase_add_test(tc_core, test_zc_crk_bforce_refcount);
    tcase_add_test(tc_core, test_zc_crk_ptext_refcount);
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
