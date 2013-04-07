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

#include <check.h>

#include "libzc.h"

struct zc_ctx *ctx;
struct zc_file *file;
const char wrong_password[] = "mfe";
const char good_password[] = "yamaha";
struct zc_validation_data vdata[3];

void setup_crack()
{
   zc_new(&ctx);
   zc_file_new_from_filename(ctx, "test.zip", &file);
   zc_file_open(file);
   zc_file_read_validation_data(file, &vdata[0], 3);
}

void teardown_crack()
{
   zc_file_close(file);
   zc_file_unref(file);
   zc_unref(ctx);
}

START_TEST(test_wrong_password)
{
   fail_unless(zc_crack(wrong_password, vdata, 3) == false, NULL);
}
END_TEST

START_TEST(test_good_password)
{
   fail_unless(zc_crack(good_password, vdata, 3) == true, NULL);
}
END_TEST

Suite *make_libzc_crack_suite()
{
   Suite *s = suite_create("crack");

   TCase *tc_core = tcase_create("Core");
   tcase_add_checked_fixture(tc_core, setup_crack, teardown_crack);
   tcase_add_test(tc_core, test_wrong_password);
   tcase_add_test(tc_core, test_good_password);
   suite_add_tcase(s, tc_core);

   return s;
}
