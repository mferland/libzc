/*
 *  zc - zip crack library
 *  Copyright (C) 2013  Marc Ferland
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
#include "test_plaintext.h"

struct zc_ctx *ctx;

void setup_ptext()
{
   zc_new(&ctx);
}

void teardown_ptext()
{
   zc_unref(ctx);
}

START_TEST(test_zc_ptext_new)
{
   struct zc_crk_ptext *ptext;
   fail_unless(zc_crk_ptext_new(ctx, &ptext) == 0, NULL);
   fail_unless(zc_crk_ptext_unref(ptext) == 0, NULL);
}
END_TEST

START_TEST(test_zc_ptext_set_cipher_and_plaintext)
{
   struct zc_crk_ptext *ptext;
   fail_unless(zc_crk_ptext_new(ctx, &ptext) == 0, NULL);
   fail_unless(zc_crk_ptext_set_text(ptext, test_plaintext, test_ciphertext, TEST_PLAINTEXT_SIZE) == 0, NULL);
   fail_unless(zc_crk_ptext_unref(ptext) == 0, NULL);
}
END_TEST

START_TEST(test_zc_crk_ptext_attack)
{
   struct zc_crk_ptext *ptext;
   struct zc_key out_key;
   fail_unless(zc_crk_ptext_new(ctx, &ptext) == 0, NULL);
   fail_unless(zc_crk_ptext_set_text(ptext, test_plaintext, test_ciphertext, TEST_PLAINTEXT_SIZE) == 0, NULL);
   fail_unless(zc_crk_ptext_key2_reduction(ptext) == 0, NULL);
   fail_unless(zc_crk_ptext_attack(ptext, &out_key) == 0, NULL);
   fail_unless(zc_crk_ptext_unref(ptext) == 0, NULL);
}
END_TEST

START_TEST(test_zc_crk_ptext_find_internal_rep)
{
   struct zc_key out_key = { .key0 = 0x6b1e4593, .key1 = 0xd81e41ed, .key2 = 0x9a616e02 };
   struct zc_key internal_rep;
   fail_unless(zc_crk_ptext_find_internal_rep(&out_key, test_encrypted_header, 12, &internal_rep) == 0, NULL);
   fail_unless(internal_rep.key0 == 0x9ccebdf4 &&
               internal_rep.key1 == 0x758c65be &&
               internal_rep.key2 == 0xc661eb70, NULL);
}
END_TEST

START_TEST(test_zc_crk_ptext_find_password)
{
   struct zc_key internal_rep = { .key0 = 0x9ccebdf4,
                                  .key1 = 0x758c65be,
                                  .key2 = 0xc661eb70 };
   fail_unless(zc_crk_ptext_find_password(&internal_rep) == 0, NULL);
}
END_TEST

Suite *make_libzc_ptext_suite()
{
   Suite *s = suite_create("plaintext");

   TCase *tc_core = tcase_create("Core");
   tcase_add_checked_fixture(tc_core, setup_ptext, teardown_ptext);
   tcase_add_test(tc_core, test_zc_ptext_new);
   tcase_add_test(tc_core, test_zc_ptext_set_cipher_and_plaintext);
   // tcase_add_test(tc_core, test_zc_crk_ptext_attack);
   tcase_add_test(tc_core, test_zc_crk_ptext_find_internal_rep);
   tcase_add_test(tc_core, test_zc_crk_ptext_find_password);
   suite_add_tcase(s, tc_core);

   return s;
}
