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
#include <string.h>

#include "plaintext.h"
#include "test_plaintext.h"

START_TEST(test_zc_plaintext_new)
{
	struct zc_plaintext *ctx;

	ck_assert_int_eq(zc_plaintext_new(&ctx, -1), 0);
	ck_assert_ptr_nonnull(ctx);
	ck_assert_int_eq(zc_plaintext_key2_count(ctx), 0);
	zc_plaintext_destroy(ctx);
}
END_TEST

START_TEST(test_zc_plaintext_set_text_size_boundary)
{
	uint8_t plaintext[13] = {0};
	uint8_t ciphertext[13] = {0};
	struct zc_plaintext *ctx;

	ck_assert_int_eq(zc_plaintext_new(&ctx, 1), 0);
	ck_assert_int_eq(zc_plaintext_set_text(ctx, plaintext, ciphertext,
					       12), -1);
	ck_assert_int_eq(zc_plaintext_set_text(ctx, plaintext, ciphertext,
					       13), 0);
	zc_plaintext_destroy(ctx);
}
END_TEST

START_TEST(test_zc_plaintext_set_cipher_and_plaintext)
{
	struct zc_plaintext *ctx;
	ck_assert(zc_plaintext_new(&ctx, -1) == 0);
	ck_assert(zc_plaintext_set_text(ctx, test_plaintext, test_ciphertext,
					TEST_PLAINTEXT_SIZE) == 0);
	zc_plaintext_destroy(ctx);
}
END_TEST

#ifdef EXTRACHECK
START_TEST(test_zc_plaintext_attack)
{
	struct zc_plaintext *ctx;
	struct zc_key out_key;
	ck_assert(zc_plaintext_new(&ctx, -1) == 0);
	ck_assert(zc_plaintext_set_text(ctx, test_plaintext, test_ciphertext,
					TEST_PLAINTEXT_SIZE) == 0);
	ck_assert(zc_plaintext_key2_reduction(ctx) == 0);
	ck_assert(zc_plaintext_attack(ctx, &out_key) == 0);
	ck_assert(out_key.key0 == 0x6b1e4593 &&
		  out_key.key1 == 0xd81e41ed &&
		  out_key.key2 == 0x9a616e02);
	zc_plaintext_destroy(ctx);
}
END_TEST

START_TEST(test_zc_plaintext_attack_rejects_invalid_plaintext)
{
	uint8_t plaintext[TEST_PLAINTEXT_SIZE];
	struct zc_plaintext *ctx;
	struct zc_key out_key;

	memcpy(plaintext, test_plaintext, sizeof(plaintext));
	plaintext[0] ^= 0xff;

	ck_assert_int_eq(zc_plaintext_new(&ctx, -1), 0);
	ck_assert_int_eq(zc_plaintext_set_text(ctx, plaintext,
					       test_ciphertext,
					       TEST_PLAINTEXT_SIZE), 0);
	ck_assert_int_eq(zc_plaintext_key2_reduction(ctx), 0);
	ck_assert_int_eq(zc_plaintext_attack(ctx, &out_key), -1);
	zc_plaintext_destroy(ctx);
}
END_TEST

START_TEST(test_zc_plaintext_key2_reduction_rejects_no_candidates)
{
	uint8_t plaintext[TEST_PLAINTEXT_SIZE];
	struct zc_plaintext *ctx;

	memcpy(plaintext, test_plaintext, sizeof(plaintext));
	for (size_t i = 11; i < sizeof(plaintext); ++i)
		plaintext[i] ^= 0xff;

	ck_assert_int_eq(zc_plaintext_new(&ctx, -1), 0);
	ck_assert_int_eq(zc_plaintext_set_text(ctx, plaintext,
					       test_ciphertext,
					       TEST_PLAINTEXT_SIZE), 0);
	ck_assert_int_eq(zc_plaintext_key2_reduction(ctx), -1);
	ck_assert_int_eq(zc_plaintext_key2_count(ctx), 0);
	zc_plaintext_destroy(ctx);
}
END_TEST
#endif

START_TEST(test_zc_plaintext_find_internal_rep)
{
	struct zc_key out_key = { .key0 = 0x6b1e4593, .key1 = 0xd81e41ed, .key2 = 0x9a616e02 };
	struct zc_key internal_rep;
	ck_assert(zc_plaintext_find_internal_rep(&out_key, test_encrypted_header, 12,
						 &internal_rep) == 0);
	ck_assert(internal_rep.key0 == 0x9ccebdf4 &&
		  internal_rep.key1 == 0x758c65be &&
		  internal_rep.key2 == 0xc661eb70);
}
END_TEST

START_TEST(test_zc_plaintext_find_internal_rep_rejects_short_input)
{
	struct zc_key start_key = {0};
	struct zc_key internal_rep = {
		.key0 = UINT32_MAX,
		.key1 = UINT32_MAX,
		.key2 = UINT32_MAX,
	};

	ck_assert_int_eq(zc_plaintext_find_internal_rep(
				 &start_key, test_encrypted_header, 11, &internal_rep), -1);
	ck_assert_uint_eq(internal_rep.key0, UINT32_MAX);
	ck_assert_uint_eq(internal_rep.key1, UINT32_MAX);
	ck_assert_uint_eq(internal_rep.key2, UINT32_MAX);
}
END_TEST

Suite *plaintext_suite()
{
	Suite *s = suite_create("plaintext");

	TCase *tc_core = tcase_create("Core");
	tcase_add_test(tc_core, test_zc_plaintext_new);
	tcase_add_test(tc_core, test_zc_plaintext_set_text_size_boundary);
	tcase_add_test(tc_core, test_zc_plaintext_set_cipher_and_plaintext);
#ifdef EXTRACHECK
	tcase_add_test(tc_core, test_zc_plaintext_attack);
	tcase_add_test(tc_core,
		       test_zc_plaintext_attack_rejects_invalid_plaintext);
	tcase_add_test(tc_core,
		       test_zc_plaintext_key2_reduction_rejects_no_candidates);
	tcase_set_timeout(tc_core, 60 * 60);
#endif
	tcase_add_test(tc_core, test_zc_plaintext_find_internal_rep);
	tcase_add_test(tc_core,
		       test_zc_plaintext_find_internal_rep_rejects_short_input);
	suite_add_tcase(s, tc_core);

	return s;
}

int main()
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = plaintext_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
