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

#include <stdlib.h>
#include <check.h>

#include "libzc.h"
#include "test_libzc.h"

START_TEST(test_zc_new_context)
{
   struct zc_ctx *ctx = NULL;
   fail_if(zc_new(&ctx) != 0,
           "Creating new library context failed.");
   zc_unref(ctx);
}
END_TEST

START_TEST(test_zc_addremove_ref)
{
   struct zc_ctx *ctx;
   zc_new(&ctx);
   zc_ref(ctx);
   fail_if(zc_unref(ctx) == NULL,
           "Ref. count decrement failed.");
   fail_unless(zc_unref(ctx) == NULL,
               "Ref. count decrement and free failed.");
}
END_TEST

START_TEST(test_zc_ref_with_null_ptr)
{
   struct zc_ctx *ctx = NULL;
   fail_unless(zc_ref(ctx) == NULL, NULL);
}
END_TEST

START_TEST(test_zc_unref_with_null_ptr)
{
   struct zc_ctx *ctx = NULL;
   fail_unless(zc_unref(ctx) == NULL, NULL);
}
END_TEST

Suite *make_libzc_master_suite()
{
   Suite *s = suite_create("master");
   TCase *tc_core = tcase_create("Core");
   tcase_add_test(tc_core, test_zc_new_context);
   tcase_add_test(tc_core, test_zc_addremove_ref);
   tcase_add_test(tc_core, test_zc_ref_with_null_ptr);
   tcase_add_test(tc_core, test_zc_unref_with_null_ptr);
   suite_add_tcase(s, tc_core);

   return s;
}

int main()
{
   int number_failed;
   SRunner *sr = srunner_create(make_libzc_master_suite());
   srunner_add_suite(sr, make_libzc_file_suite());
   srunner_add_suite(sr, make_libzc_pwgen_suite());
   srunner_add_suite(sr, make_libzc_crack_suite());
   srunner_add_suite(sr, make_libzc_pwdict_suite());
   srunner_add_suite(sr, make_libzc_ptext_suite());
   srunner_run_all(sr, CK_NORMAL);
   number_failed = srunner_ntests_failed(sr);
   srunner_free(sr);
   return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
