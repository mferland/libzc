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

#include "libzc.h"

static struct zc_ctx *ctx;
static struct zc_file *file;
static const char const wrong_password[] = "mfe";
static const char const good_password[] = "yamaha";
static struct zc_validation_data vdata[3];

void setup_crack()
{
   zc_new(&ctx);
   zc_file_new_from_filename(ctx, "test.zip", &file);
   zc_file_open(file);
   zc_file_read_validation_data(file, vdata, 3);
}

void teardown_crack()
{
   zc_file_close(file);
   zc_file_unref(file);
   zc_unref(ctx);
}

START_TEST(test_wrong_password)
{
   fail_unless(zc_crk_test_one_pw(wrong_password, vdata, 3) == false, NULL);
}
END_TEST

START_TEST(test_good_password)
{
   fail_unless(zc_crk_test_one_pw(good_password, vdata, 3) == true, NULL);
}
END_TEST

START_TEST(test_unref_cracker)
{
   struct zc_crk_bforce *cracker;
   int ret;
   ret = zc_crk_bforce_new(ctx, &cracker);
   fail_unless(ret == 0, NULL);
   fail_unless(!zc_crk_bforce_unref(cracker), NULL);
}
END_TEST

START_TEST(test_set_pwgen)
{
   struct zc_crk_bforce *cracker;
   struct zc_pwgen *pwgen;

   zc_crk_bforce_new(ctx, &cracker);
   zc_pwgen_new(ctx, &pwgen);
   zc_crk_bforce_set_pwgen(cracker, pwgen);
   fail_unless(zc_pwgen_unref(pwgen) != NULL, NULL);
   zc_crk_bforce_unref(cracker);
}
END_TEST

START_TEST(test_set_vdata)
{
   struct zc_crk_bforce *cracker;
   struct zc_validation_data vdata[5];
   size_t vdata_size = 5;

   zc_crk_bforce_new(ctx, &cracker);
   zc_crk_bforce_set_vdata(cracker, vdata, vdata_size);
   zc_crk_bforce_unref(cracker);
}
END_TEST

START_TEST(test_start_crack)
{
   struct zc_crk_bforce *cracker;
   struct zc_validation_data vdata[5];
   size_t vdata_size = 5;
   struct zc_pwgen *pwgen;
   struct zc_file *file;
   char pw[7];

   zc_file_new_from_filename(ctx, "test.zip", &file);
   zc_file_open(file);
   vdata_size = zc_file_read_validation_data(file, vdata, vdata_size);
   zc_file_close(file);
   zc_file_unref(file);

   zc_pwgen_new(ctx, &pwgen);
   zc_pwgen_init(pwgen, "abcdefghijklmnopqrstuvwxyz", 6);
   zc_pwgen_reset(pwgen, "yamaga");
   zc_pwgen_set_step(pwgen, 1);

   zc_crk_bforce_new(ctx, &cracker);
   zc_crk_bforce_set_vdata(cracker, vdata, vdata_size);
   zc_crk_bforce_set_pwgen(cracker, pwgen);

   int ret = zc_crk_bforce_start(cracker, pw, 7);
   fail_unless(ret == 0, NULL);
   fail_unless(strncmp(pw, "yamaha", 6) == 0, NULL);

   zc_crk_bforce_unref(cracker);
   zc_pwgen_unref(pwgen);
}
END_TEST

START_TEST(test_cannot_find_password)
{
   struct zc_crk_bforce *cracker;
   struct zc_validation_data vdata[5];
   size_t vdata_size = 5;
   struct zc_pwgen *pwgen;
   struct zc_file *file;
   char pw[7];

   zc_file_new_from_filename(ctx, "test.zip", &file);
   zc_file_open(file);
   vdata_size = zc_file_read_validation_data(file, vdata, vdata_size);
   zc_file_close(file);
   zc_file_unref(file);

   zc_pwgen_new(ctx, &pwgen);
   zc_pwgen_init(pwgen, "abcdefghijklmnopqrstuvwxyz", 4);
   zc_pwgen_reset(pwgen, "aaa");
   zc_pwgen_set_step(pwgen, 1);

   zc_crk_bforce_new(ctx, &cracker);
   zc_crk_bforce_set_vdata(cracker, vdata, vdata_size);
   zc_crk_bforce_set_pwgen(cracker, pwgen);

   int ret = zc_crk_bforce_start(cracker, pw, 7);
   fail_unless(ret == -1, NULL);

   zc_crk_bforce_unref(cracker);
   zc_pwgen_unref(pwgen);
}
END_TEST

Suite *make_libzc_crack_suite()
{
   Suite *s = suite_create("crack");

   TCase *tc_core = tcase_create("Core");
   tcase_add_checked_fixture(tc_core, setup_crack, teardown_crack);
   tcase_add_test(tc_core, test_wrong_password);
   tcase_add_test(tc_core, test_good_password);
   tcase_add_test(tc_core, test_unref_cracker);
   tcase_add_test(tc_core, test_set_pwgen);
   tcase_add_test(tc_core, test_set_vdata);
   tcase_add_test(tc_core, test_start_crack);
   tcase_add_test(tc_core, test_cannot_find_password);
   suite_add_tcase(s, tc_core);

   return s;
}
