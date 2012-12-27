/*
 *  zc - zip crack library
 *  Copyright (C) 2009  Marc Ferland
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
#include <stdio.h>
#include <check.h>

#include "libzc.h"

START_TEST(test_zc_new)
{
   struct zc_ctx *ctx;
   struct zc_ctx *freedctx;
   int err;

   err = zc_new(&ctx);
   fail_unless(err == 0, NULL);

   freedctx = zc_unref(ctx);
   fail_unless(freedctx == NULL, NULL);
}
END_TEST

START_TEST(test_zc_file_new)
{
   struct zc_ctx *ctx;
   struct zc_file *file;

   zc_new(&ctx);
   zc_file_new_from_filename(ctx, "toto.zip", &file);
   fail_if(strcmp(zc_file_get_filename(file), "toto.zip") != 0,
           "Filename does not match.");

   zc_file_unref(file);
   zc_unref(ctx);
}
END_TEST

START_TEST(test_zc_file_open_existant)
{
   struct zc_ctx *ctx;
   struct zc_file *file;
   int err;

   zc_new(&ctx);
   zc_file_new_from_filename(ctx, "test.zip", &file);
   fail_if(zc_file_open(file) != 0,
           "File could not be opened.");
   
   zc_file_unref(file);
   zc_unref(ctx);
}
END_TEST

START_TEST(test_zc_file_open_nonexistant)
{
   struct zc_ctx *ctx;
   struct zc_file *file;
   int err;

   zc_new(&ctx);
   zc_file_new_from_filename(ctx, "doesnotexists.zip", &file);
   fail_if(zc_file_open(file) == 0,
           "Non-existant file reported having been opened.");
   
   zc_file_unref(file);
   zc_unref(ctx);
}
END_TEST

Suite *libzc_suite()
{
   Suite *s = suite_create("");

   /* Core test case */
   TCase *tc_core = tcase_create("Core");
   tcase_add_test(tc_core, test_zc_new);
   tcase_add_test(tc_core, test_zc_file_new);
   tcase_add_test(tc_core, test_zc_file_open_existant);
   tcase_add_test(tc_core, test_zc_file_open_nonexistant);
   suite_add_tcase(s, tc_core);

   return s;
}

int main()
{
   int number_failed;
   Suite *s = libzc_suite();
   SRunner *sr = srunner_create(s);
   srunner_run_all(sr, CK_NORMAL);
   number_failed = srunner_ntests_failed(sr);
   srunner_free(sr);
   return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
