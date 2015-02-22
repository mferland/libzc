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

struct zc_ctx *ctx;
struct zc_file *file;

void setup_file()
{
    zc_new(&ctx);
    file = NULL;
}

void teardown_file()
{
    zc_file_unref(file);
    zc_unref(ctx);
}

START_TEST(test_zc_file_new)
{
    zc_file_new_from_filename(ctx, "toto.zip", &file);
    fail_if(strcmp(zc_file_get_filename(file), "toto.zip") != 0,
            "Filename does not match.");
}
END_TEST

START_TEST(test_zc_file_open_existant)
{
    zc_file_new_from_filename(ctx, "test.zip", &file);
    fail_if(zc_file_open(file) != 0,
            "File could not be opened.");
    zc_file_close(file);
}
END_TEST

START_TEST(test_zc_file_open_nonexistant)
{
    zc_file_new_from_filename(ctx, "doesnotexists.zip", &file);
    fail_if(zc_file_open(file) == 0,
            "Non-existant file reported having been opened.");
}
END_TEST

START_TEST(test_zc_file_close_opened)
{
    zc_file_new_from_filename(ctx, "test.zip", &file);
    zc_file_open(file);
    fail_if(zc_file_close(file) != 0,
            "Closing existant file failed.");
}
END_TEST

START_TEST(test_zc_file_isopened_true)
{
    zc_file_new_from_filename(ctx, "test.zip", &file);
    zc_file_open(file);
    fail_unless(zc_file_isopened(file),
                "File should be open.");
    zc_file_close(file);
}
END_TEST

START_TEST(test_zc_file_isopened_false)
{
    zc_file_new_from_filename(ctx, "test.zip", &file);
    fail_if(zc_file_isopened(file),
            "File should not be open.");
}
END_TEST

START_TEST(test_zc_file_can_read_validation_data)
{
    struct zc_validation_data vdata[3];

    zc_file_new_from_filename(ctx, "test.zip", &file);
    zc_file_open(file);
    int err = zc_file_read_validation_data(file, vdata, 3);

    fail_unless(err == 3,
                "Reading validation data failed.");

    zc_file_close(file);
}
END_TEST

START_TEST(test_zc_file_specify_large_validation_data)
{
    struct zc_validation_data vdata[12];

    zc_file_new_from_filename(ctx, "test.zip", &file);
    zc_file_open(file);
    int err = zc_file_read_validation_data(file, vdata, 12);

    fail_unless(err == 4,
                "Reading validation data in large array failed.");

    zc_file_close(file);
}
END_TEST

START_TEST(test_zc_file_not_encrypted)
{
    struct zc_validation_data vdata[3];

    zc_file_new_from_filename(ctx, "test_non_encrypted.zip", &file);
    zc_file_open(file);
    int err = zc_file_read_validation_data(file, vdata, 3);

    fail_unless(err == 0,
                "Reading non encrypted file failed.");

    zc_file_close(file);
}
END_TEST

START_TEST(test_zc_file_wrong_password)
{
    fail_unless(zc_file_test_password("test.zip", "mfe") == false, NULL);
}
END_TEST

START_TEST(test_zc_file_good_password)
{
    fail_unless(zc_file_test_password("test.zip", "yamaha") == true, NULL);
}
END_TEST

START_TEST(test_zc_file_read_cipher_bytes)
{
    char str[10];
    memset(str, 0, 10);
    zc_file_new_from_filename(ctx, "notcompressed.zip", &file);
    zc_file_open(file);
    int err = zc_file_read_cipher_bytes(file, "test.txt", str, 0, 9);

    fail_unless(err == 0,
                "Reading cipher bytes failed.");
    fail_unless(strncmp(str, "some text", 9) == 0,
                "Reading cipher bytes failed.");

    zc_file_close(file);
}
END_TEST

START_TEST(test_zc_file_read_cipher_bytes_beyond_eof)
{
    char str[20];
    memset(str, 0, 20);
    zc_file_new_from_filename(ctx, "notcompressed.zip", &file);
    zc_file_open(file);
    int err = zc_file_read_cipher_bytes(file, "test.txt", str, 0, 20);

    fail_unless(err < 0, "Expected error!");

    zc_file_close(file);
}
END_TEST

START_TEST(test_zc_file_read_cipher_bytes_missing_file)
{
    char str[10];
    memset(str, 0, 10);
    zc_file_new_from_filename(ctx, "notcompressed.zip", &file);
    zc_file_open(file);
    int err = zc_file_read_cipher_bytes(file, "missing-file", str, 0, 10);

    fail_unless(err < 0, "Expected error!");

    zc_file_close(file);
}
END_TEST

START_TEST(test_zc_file_read_cipher_bytes_encrypted)
{
    char str[10];
    memset(str, 0, 10);
    zc_file_new_from_filename(ctx, "notcompressed_en.zip", &file);
    zc_file_open(file);
    int err = zc_file_read_cipher_bytes(file, "test.txt", str, 0, 9);

    fail_unless(err == 0, "Error reading encrypted bytes!");

    zc_file_close(file);
}
END_TEST

Suite *make_libzc_file_suite()
{
    Suite *s = suite_create("file");

    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, setup_file, teardown_file);
    tcase_add_test(tc_core, test_zc_file_new);
    tcase_add_test(tc_core, test_zc_file_open_existant);
    tcase_add_test(tc_core, test_zc_file_open_nonexistant);
    tcase_add_test(tc_core, test_zc_file_close_opened);
    tcase_add_test(tc_core, test_zc_file_isopened_true);
    tcase_add_test(tc_core, test_zc_file_isopened_false);
    tcase_add_test(tc_core, test_zc_file_can_read_validation_data);
    tcase_add_test(tc_core, test_zc_file_specify_large_validation_data);
    tcase_add_test(tc_core, test_zc_file_not_encrypted);
    tcase_add_test(tc_core, test_zc_file_wrong_password);
    tcase_add_test(tc_core, test_zc_file_good_password);
    tcase_add_test(tc_core, test_zc_file_read_cipher_bytes);
    tcase_add_test(tc_core, test_zc_file_read_cipher_bytes_beyond_eof);
    tcase_add_test(tc_core, test_zc_file_read_cipher_bytes_missing_file);
    tcase_add_test(tc_core, test_zc_file_read_cipher_bytes_encrypted);
    suite_add_tcase(s, tc_core);

    return s;
}
