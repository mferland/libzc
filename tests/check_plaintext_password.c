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

#include "libzc.h"

struct zc_ctx *ctx;
struct zc_crk_ptext *ptext;

struct test_pool {
	struct zc_key k;
	const char *pw;
	size_t len;
};

#ifdef EXTRACHECK
#define POOL_LEN 22
#else
#define POOL_LEN 19
#endif
struct test_pool pool[POOL_LEN] = {
	{ { 0x64799c96, 0xb303049c, 0xa253270a }, "a", 1 },
	{ { 0xfd70cd2c, 0x5f7c5a8a, 0x0bef8959 }, "b", 1 },
	{ { 0x8a77fdba, 0xd4359550, 0x7185d3f1 }, "c", 1 },
	{ { 0x14136819, 0xc6da8e2b, 0x823ca2b9 }, "d", 1 },
	{ { 0x6b644339, 0xb7a8c716, 0x2943427d }, "12", 2 },
	{ { 0xe0be8d5d, 0x70bb3140, 0x7e983fff }, "123", 3 },
	{ { 0x5dd2af4d, 0x589d03b4, 0x3cf5ffa4 }, "abc", 3 },
	{ { 0x42ef4ac3, 0x8d167254, 0x428e6d93 }, "abcd", 4 },
	{ { 0x86acf865, 0x35f28777, 0x487a4de6 }, "eert", 4 },
	{ { 0xc7c2fd91, 0x8ceeffa2, 0x607e0c0b }, "marc", 4 },
	{ { 0x71850bee, 0xf0d3c2f5, 0xcd86a60b }, "12345", 5 },
	{ { 0x69ca8e31, 0xada107e8, 0x1a02db98 }, "soleil", 6 },
	{ { 0xbfa7c384, 0x8ce275f6, 0x381ff5ad }, "pploam", 6 },
	{ { 0x92d892f8, 0x929fc2cd, 0xbecc427c }, "olivier", 7 },
	{ { 0xf06c6793, 0xa728bdfe, 0xad145306 }, "quanfp5", 7 },
	{ { 0xc55fcbf5, 0xb45779f0, 0xaad9ef66 }, "p)(]lkj", 7 },
	{ { 0xf5ba4621, 0x5333625d, 0x6c5eaac2 }, "laurence", 8 },
	{ { 0x6c0c6c36, 0x4c8d85db, 0xdf01fc4f }, "mmna017f", 8 },
	{ { 0x354fe972, 0x1d10245c, 0xb361d1e4 }, "uuhnd5FG%", 9 },
#ifdef EXTRACHECK
	{ { 0x315e2c2d, 0x5b1586ba, 0xf57b0245 }, "kkjnhbgv78", 10 },
	{ { 0xd9a4f37e, 0x671cc039, 0xe1c65a02 }, "yhfg-098m31", 11 },
	{ { 0x9986f7db, 0x67338fae, 0x131eb6d7 }, "0098ikjmn3@@", 12 },
#endif
};

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
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 0);
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_1)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x64799c96, .key1 = 0xb303049c, .key2 = 0xa253270a };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 1);
	ck_assert_str_eq(pw, "a");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_2)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x23bd1e23, .key1 = 0x2b7993bc, .key2 = 0x4ccb4379 };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 2);
	ck_assert_str_eq(pw, "aa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_3)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x98f19da2, .key1 = 0x1cd05dd7, .key2 = 0x3d945e94 };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 3);
	ck_assert_str_eq(pw, "aaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_4)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x2f56297, .key1 = 0x64329027, .key2 = 0xbd806642 };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 4);
	ck_assert_str_eq(pw, "aaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_5)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x54dca24b, .key1 = 0x1b079a3b, .key2 = 0x120a6936 };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 5);
	ck_assert_str_eq(pw, "aaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_6)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0xdbef1574, .key1 = 0xc060416c, .key2 = 0x54cc5d40 };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 6);
	ck_assert_str_eq(pw, "aaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_7)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x6d060bfe, .key1 = 0xc76ff413, .key2 = 0x7388dade };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 7);
	ck_assert_str_eq(pw, "aaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_8)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x60dd88de, .key1 = 0xcf040cb6, .key2 = 0x6ac3a828 };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 8);
	ck_assert_str_eq(pw, "aaaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_9)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x5bbe7395, .key1 = 0xe446ee78, .key2 =  0x92b84d33};
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 9);
	ck_assert_str_eq(pw, "aaaaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_10)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0xba8b8876, .key1 = 0xf00562a7, .key2 = 0x02ff2b47 };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 10);
	ck_assert_str_eq(pw, "aaaaaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_11)
{
	char pw[14];
	struct zc_key internal_rep = { .key0 = 0x83690e4f, .key1 = 0x3ed1c6cf, .key2 = 0x29db36b3 };
	ck_assert_int_eq(zc_crk_ptext_find_password(ptext, &internal_rep, pw,
						    sizeof(pw)), 11);
	ck_assert_str_eq(pw, "aaaaaaaaaaa");
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password_pool)
{
	char pw[14];
	struct zc_key internal_rep;

	for (int i = 0; i < POOL_LEN; ++i) {
		internal_rep = pool[i].k;
		ck_assert_int_eq(zc_crk_ptext_find_password(ptext,
							    &internal_rep,
							    pw, sizeof(pw)),
				 pool[i].len);
		ck_assert_str_eq(pw, pool[i].pw);
	}
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
#ifdef EXTRACHECK
	tcase_add_test(tc_core, test_zc_crk_ptext_find_password_9);
	tcase_add_test(tc_core, test_zc_crk_ptext_find_password_10);
	tcase_add_test(tc_core, test_zc_crk_ptext_find_password_11);
	tcase_set_timeout(tc_core, 3600);
#else
	tcase_set_timeout(tc_core, 60);
#endif
	tcase_add_test(tc_core, test_zc_crk_ptext_find_password_pool);
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
