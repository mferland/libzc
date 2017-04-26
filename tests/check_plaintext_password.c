/*
 *  zc - zip crack library
 *  Copyright (C) 2017 Marc Ferland
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

#include "libzc.h"

struct zc_ctx *ctx;
struct zc_crk_ptext *ptext;

void setup_ptext()
{
    zc_new(&ctx);
    zc_crk_ptext_new(ctx, &ptext);
}

void teardown_ptext()
{
    zc_crk_ptext_unref(ptext);
    zc_unref(ctx);
}

START_TEST(test_zc_crk_ptext_find_password_0)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x12345678, .key1 = 0x23456789, .key2 = 0x34567890 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 0);
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_1)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x64799c96, .key1 = 0xb303049c, .key2 = 0xa253270a };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 1);
    ck_assert_str_eq(pw, "a");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_2)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x23bd1e23, .key1 = 0x2b7993bc, .key2 = 0x4ccb4379 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 2);
    ck_assert_str_eq(pw, "aa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_3)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x98f19da2, .key1 = 0x1cd05dd7, .key2 = 0x3d945e94 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 3);
    ck_assert_str_eq(pw, "aaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_4)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x2f56297, .key1 = 0x64329027, .key2 = 0xbd806642 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 4);
    ck_assert_str_eq(pw, "aaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_5)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x54dca24b, .key1 = 0x1b079a3b, .key2 = 0x120a6936 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 5);
    ck_assert_str_eq(pw, "aaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_6)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0xdbef1574, .key1 = 0xc060416c, .key2 = 0x54cc5d40 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 6);
    ck_assert_str_eq(pw, "aaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_7)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x6d060bfe, .key1 = 0xc76ff413, .key2 = 0x7388dade };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 7);
    ck_assert_str_eq(pw, "aaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_8)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x60dd88de, .key1 = 0xcf040cb6, .key2 = 0x6ac3a828 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 8);
    ck_assert_str_eq(pw, "aaaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_9)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x5bbe7395, .key1 = 0xe446ee78, .key2 =  0x92b84d33};
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 9);
    ck_assert_str_eq(pw, "aaaaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_10)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0xba8b8876, .key1 = 0xf00562a7, .key2 = 0x02ff2b47 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 10);
    ck_assert_str_eq(pw, "aaaaaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_11)
{
    char pw[14];
    struct zc_key internal_rep = { .key0 = 0x83690e4f, .key1 = 0x3ed1c6cf, .key2 = 0x29db36b3 };
    ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw, sizeof(pw)), 11);
    ck_assert_str_eq(pw, "aaaaaaaaaaa");
}
END_TEST

Suite *plaintext_password_suite()
{
    Suite *s = suite_create("plaintext_password");

    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup_ptext, teardown_ptext);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_0);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_1);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_2);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_3);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_4);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_5);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_6);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_7);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_8);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_9);
    tcase_add_test(tc_core, test_zc_crk_ptext_find_password_10);
    //tcase_add_test(tc_core, test_zc_crk_ptext_find_password_11);
    tcase_set_timeout(tc_core, 120);
    suite_add_tcase(s, tc_core);

    return s;
}

int main()
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = plaintext_password_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
