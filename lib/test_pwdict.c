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
#include <errno.h>

#include "libzc.h"

struct zc_ctx *ctx;
struct zc_pwdict *pwdict;

void setup_pwdict()
{
    zc_new(&ctx);
    pwdict = NULL;
}

void teardown_pwdict()
{
    zc_pwdict_unref(pwdict);
    zc_unref(ctx);
}

START_TEST(test_zc_pwdict_new)
{
    zc_pwdict_new_from_filename(ctx, "../data/pw.txt", &pwdict);
    fail_if(!pwdict,
            "Creating new password dictionary failed.");
}
END_TEST

START_TEST(test_zc_pwdict_open_and_close)
{
    int err;
    zc_pwdict_new_from_filename(ctx, "../data/pw.txt", &pwdict);
    err = zc_pwdict_open(pwdict);
    fail_if(err != 0,
            "Opening password file pw.txt failed.");
    err = zc_pwdict_close(pwdict);
    fail_if(err != 0,
            "Closing password file pw.txt failed.");
}
END_TEST

START_TEST(test_zc_pwdict_open_non_existant)
{
    int err;
    zc_pwdict_new_from_filename(ctx, "does_not_exist.txt", &pwdict);
    err = zc_pwdict_open(pwdict);
    fail_if(err == 0,
            "Opening non-existant file succeeded?");
}
END_TEST

START_TEST(test_zc_pwdict_can_read_one_line)
{
    char str[64];
    int err;
    zc_pwdict_new_from_filename(ctx, "../data/pw.txt", &pwdict);
    zc_pwdict_open(pwdict);

    err = zc_pwdict_read_one_pw(pwdict, str, 64);
    fail_if(err != 0 || strcmp("ab", str) != 0,
            "Reading first password failed.");

    err = zc_pwdict_read_one_pw(pwdict, str, 64);
    fail_if(err != 0 || strcmp("cd", str) != 0,
            "Reading second password failed.");

    err = zc_pwdict_read_one_pw(pwdict, str, 64);
    fail_if(err != 0 || strcmp("ef", str) != 0,
            "Reading third password failed.");

    err = zc_pwdict_read_one_pw(pwdict, str, 64);
    fail_if(err != 0 || strcmp("gh", str) != 0,
            "Reading third password failed.");

    err = zc_pwdict_read_one_pw(pwdict, str, 64);
    fail_if(err == 0,
            "Reading past eof succeeded?.");

    zc_pwdict_close(pwdict);
}
END_TEST

Suite *make_libzc_pwdict_suite()
{
    Suite *s = suite_create("password dictionary");

    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup_pwdict, teardown_pwdict);
    tcase_add_test(tc_core, test_zc_pwdict_new);
    tcase_add_test(tc_core, test_zc_pwdict_open_and_close);
    tcase_add_test(tc_core, test_zc_pwdict_open_non_existant);
    tcase_add_test(tc_core, test_zc_pwdict_can_read_one_line);
    suite_add_tcase(s, tc_core);

    return s;
}
