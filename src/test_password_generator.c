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
#include <stdlib.h>

#include "libzc.h"

struct zc_ctx *ctx;
struct zc_passw_generator *generator;

void setup()
{
   zc_new(&ctx);
   generator = NULL;
}

void teardown()
{
   zc_pwgen_unref(generator);
   zc_unref(ctx);
}

START_TEST(test_zc_generator_new)
{
   zc_pwgen_new(ctx, &generator);
   fail_if(generator == NULL,
           "Creating new password generator failed.");
}
END_TEST

Suite *make_libzc_password_generator_suite()
{
   Suite *s = suite_create("password generator");

   TCase *tc_core = tcase_create("Core");
   tcase_add_checked_fixture(tc_core, setup, teardown);
   tcase_add_test(tc_core, test_zc_file_new);
   suite_add_tcase(s, tc_core);

   return s;
}
