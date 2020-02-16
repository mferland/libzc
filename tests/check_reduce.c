/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2018 Marc Ferland
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
#include "ptext_private.h"
#include "test_plaintext.h"
#include "ptext_reduce.c"

#define KEY3(index) test_plaintext[index] ^ test_ciphertext[index]

struct zc_ctx *ctx;
struct zc_crk_ptext *ptext;

void setup_reduce()
{
	zc_new(&ctx);
	zc_crk_ptext_new(ctx, &ptext);
}

void teardown_reduce()
{
	zc_crk_ptext_unref(ptext);
	zc_unref(ctx);
}

START_TEST(test_can_get_bits_15_2)
{
	fail_if(ptext->bits_15_2[0] != 0);
}
END_TEST

START_TEST(test_can_generate_first_gen_key2)
{
	uint32_t *key2_first_gen;
	uint16_t *bits15_2;

	bits15_2 = get_bits_15_2(ptext->bits_15_2, 0);
	key2_first_gen = calloc((1 << 22), sizeof(uint32_t));
	generate_all_key2_bits_31_2(key2_first_gen, bits15_2);
	fail_if(key2_first_gen[0] != 0);
	free(key2_first_gen);
}
END_TEST

START_TEST(test_can_generate_next_array_from_plaintext)
{
	int32_t *key2_first_gen;
	int32_t *key2_next_gen;
	size_t key2_first_gen_size, total;

	uint8_t key3i = KEY3(TEST_PLAINTEXT_SIZE - 1);
	uint8_t key3im1 = KEY3(TEST_PLAINTEXT_SIZE - 2);
	uint8_t key3im2 = KEY3(TEST_PLAINTEXT_SIZE - 3);

	key2_first_gen = calloc((1 << 22), sizeof(uint32_t));
	generate_all_key2_bits_31_2(key2_first_gen, get_bits_15_2(ptext->bits_15_2, key3i));
	key2_first_gen_size = (1 << 22);
	key2_next_gen = calloc((1 << 22), sizeof(uint32_t));

	for (size_t i = 0; i < key2_first_gen_size; ++i)
		total += key2r_compute_single(key2_first_gen[i],
					      key2_next_gen,
					      get_bits_15_2(ptext->bits_15_2, key3im1),
					      get_bits_15_2(ptext->bits_15_2, key3im2),
					      KEY2_MASK_6BITS);

	uniq(key2_next_gen, &total);

	fail_if(total != 2256896);

	free(key2_next_gen);
	free(key2_first_gen);
}
END_TEST

Suite *reduce_suite()
{
	Suite *s = suite_create("reduce");

	TCase *tc_core = tcase_create("Core");
	tcase_add_checked_fixture(tc_core, setup_reduce, teardown_reduce);
	tcase_add_test(tc_core, test_can_get_bits_15_2);
	tcase_add_test(tc_core, test_can_generate_first_gen_key2);
#ifdef EXTRACHECK
	tcase_add_test(tc_core, test_can_generate_next_array_from_plaintext);
#endif
	tcase_set_timeout(tc_core, 60);
	suite_add_tcase(s, tc_core);

	return s;
}

int main()
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = reduce_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
