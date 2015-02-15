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

#include "key_table.h"
#include "key2_reduce.h"
#include "test_plaintext.h"
#include "libzc_private.h"

#define KEY3(index) test_plaintext[index] ^ test_ciphertext[index]

struct key2r *k2r;

void setup_key2r()
{
   key2r_new(&k2r);
}

void teardown_key2r()
{
   key2r_free(k2r);
}

START_TEST(test_can_get_bits_15_2)
{
   uint16_t *bits15_2;
   bits15_2 = key2r_get_bits_15_2(k2r, 0);
   fail_if(bits15_2[0] != 0);
}
END_TEST

START_TEST(test_can_generate_first_gen_key2)
{
   struct key_table *key2_first_gen;
   uint16_t *bits15_2;

   bits15_2 = key2r_get_bits_15_2(k2r, 0);
   key2_first_gen = key2r_compute_first_gen(bits15_2);
   fail_if(key_table_at(key2_first_gen, 0) != 0);
   free(key2_first_gen);
}
END_TEST

START_TEST(test_can_generate_next_table_from_plaintext)
{
   struct key_table *key2_first_gen;
   struct key_table *key2_next_gen;

   uint8_t key3i = KEY3(TEST_PLAINTEXT_SIZE - 1);
   uint8_t key3im1 = KEY3(TEST_PLAINTEXT_SIZE - 2);
   uint8_t key3im2 = KEY3(TEST_PLAINTEXT_SIZE - 3);

   key2_first_gen = key2r_compute_first_gen(key2r_get_bits_15_2(k2r, key3i));
   key_table_new(&key2_next_gen, pow2(22));

   key2r_compute_next_table(key2_first_gen,
                            key2_next_gen,
                            key2r_get_bits_15_2(k2r, key3im1),
                            key2r_get_bits_15_2(k2r, key3im2),
                            KEY2_MASK_6BITS);
   key_table_uniq(key2_next_gen);

   fail_if(key2_next_gen->size != 2256896);

   key_table_free(key2_next_gen);
   key_table_free(key2_first_gen);
}
END_TEST

Suite *make_key2_reduce_suite()
{
   Suite *s = suite_create("key2");

   TCase *tc_core = tcase_create("Core");
   tcase_add_checked_fixture(tc_core, setup_key2r, teardown_key2r);
   tcase_add_test(tc_core, test_can_get_bits_15_2);
   tcase_add_test(tc_core, test_can_generate_first_gen_key2);
   tcase_add_test(tc_core, test_can_generate_next_table_from_plaintext);
   suite_add_tcase(s, tc_core);

   return s;
}

int main()
{
   int number_failed;
   SRunner *sr = srunner_create(make_key2_reduce_suite());
   srunner_set_log(sr, "test_key2_reduce.log");
   srunner_run_all(sr, CK_NORMAL);
   number_failed = srunner_ntests_failed(sr);
   srunner_free(sr);
   return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
