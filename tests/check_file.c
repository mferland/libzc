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

/* libzc */
#include <libzc.h>

struct zc_ctx *ctx;
struct zc_file *file;

void setup(void)
{
	zc_new(&ctx);
	file = NULL;
}

void teardown(void)
{
	zc_file_unref(file);
	zc_unref(ctx);
}

START_TEST(test_zc_file_new)
{
	zc_file_new_from_filename(ctx, "toto.zip", &file);
	fail_if(strcmp(zc_file_get_filename(file), "toto.zip") != 0,
		"Filename does not match.");
	ck_assert(zc_file_isopened(file) == false);
}
END_TEST

START_TEST(test_zc_file_open_existant)
{
	zc_file_new_from_filename(ctx, DATADIR "test.zip", &file);
	ck_assert(zc_file_isopened(file) == false);
	fail_if(zc_file_open(file) != 0,
		"File could not be opened.");
	ck_assert(zc_file_isopened(file) == true);
	zc_file_close(file);
	ck_assert(zc_file_isopened(file) == false);
}
END_TEST

START_TEST(test_zc_file_open_nonexistant)
{
	zc_file_new_from_filename(ctx, "doesnotexists.zip", &file);
	ck_assert(zc_file_isopened(file) == false);
	fail_if(zc_file_open(file) == 0,
		"Non-existant file reported having been opened.");
	ck_assert(zc_file_isopened(file) == false);
}
END_TEST

START_TEST(test_zc_file_close_opened)
{
	zc_file_new_from_filename(ctx, DATADIR "test.zip", &file);
	zc_file_open(file);
	fail_if(zc_file_close(file) != 0,
		"Closing existant file failed.");
}
END_TEST

/*
 * data/test.zip:
 * INDEX NAME              OFFSETS        SIZE CSIZE ENCRYPTED HEADER
 *     0 lib/test_crk.c    72   84   1297 4658 1225  f00e35670cf88aa5e98ae477
 *     1 lib/test_file.c   1386 1398 2596 4464 1210  b73dc9d1b67312692d069a33
 *     2 lib/test_pwgen.c  2686 2698 4072 6879 1386  dbe99c24b7b0836471782106
 *     3 lib/test_pwdict.c 4163 4175 5192 3165 1029  616f68a1e82c05651dc989e8
 */
START_TEST(test_zc_file_info_encrypted)
{
	const uint8_t header[4][12] = {
		{0xf0, 0x0e, 0x35, 0x67, 0x0c, 0xf8, 0x8a, 0xa5, 0xe9, 0x8a, 0xe4, 0x77},
		{0xb7, 0x3d, 0xc9, 0xd1, 0xb6, 0x73, 0x12, 0x69, 0x2d, 0x06, 0x9a, 0x33},
		{0xdb, 0xe9, 0x9c, 0x24, 0xb7, 0xb0, 0x83, 0x64, 0x71, 0x78, 0x21, 0x06},
		{0x61, 0x6f, 0x68, 0xa1, 0xe8, 0x2c, 0x05, 0x65, 0x1d, 0xc9, 0x89, 0xe8}
	};
	const uint32_t info_size[4] = {4658, 4464, 6879, 3165};
	const uint32_t info_csize[4] = {1225, 1210, 1386, 1029};
	const long info_offset[4] = {84, 1398, 2698, 4175};
	const long info_crypt[4] = {72, 1386, 2686, 4163};
	const char *info_filename[4] = {"lib/test_crk.c",
					"lib/test_file.c",
					"lib/test_pwgen.c",
					"lib/test_pwdict.c"
				       };
	struct zc_info *info;
	const uint8_t *buf;

	zc_file_new_from_filename(ctx, DATADIR "test.zip", &file);
	zc_file_open(file);

	int i = 0;
	info = zc_file_info_next(file, NULL);
	do {
		fail_if(strcmp(zc_file_get_filename(file), info_filename[i]) == 0);
		ck_assert(zc_file_info_size(info) == info_size[i]);
		ck_assert(zc_file_info_compressed_size(info) == info_csize[i]);
		ck_assert(zc_file_info_offset_begin(info) == info_offset[i]);
		ck_assert(zc_file_info_crypt_header_offset(info) == info_crypt[i]);
		ck_assert(zc_file_info_idx(info) == i);
		buf = zc_file_info_enc_header(info);
		for (int j = 0; j < 12; ++j)
			ck_assert(buf[j] == header[i][j]);
		info = zc_file_info_next(file, info);
		++i;
	} while (info);

	ck_assert_int_eq(i, 4);

	zc_file_close(file);
}
END_TEST

/*
 * data/test_non_encrypted.zip:
 * INDEX NAME        OFFSETS       SIZE  CSIZE ENCRYPTED HEADER
 *     0 config.h    -1 66   1006  2898  940   000000000000000000000000
 *     1 config.h.in -1 1075 1929  2647  854   000000000000000000000000
 *     2 config.log  -1 1997 10537 31002 8540  000000000000000000000000
 */
START_TEST(test_zc_file_info_non_encrypted)
{
	const uint32_t info_size[3] = {2898, 2647, 31002};
	const uint32_t info_csize[3] = {940, 854, 8540};
	const long info_offset[3] = {66, 1075, 1997};
	const char *info_filename[3] = {"config.h",
					"config.h.in",
					"config.log"
				       };
	struct zc_info *info;
	const uint8_t *buf;

	zc_file_new_from_filename(ctx, DATADIR "test_non_encrypted.zip", &file);
	zc_file_open(file);

	int i = 0;
	info = zc_file_info_next(file, NULL);
	do {
		fail_if(strcmp(zc_file_get_filename(file), info_filename[i]) == 0);
		ck_assert(zc_file_info_size(info) == info_size[i]);
		ck_assert(zc_file_info_compressed_size(info) == info_csize[i]);
		ck_assert(zc_file_info_offset_begin(info) == info_offset[i]);
		ck_assert(zc_file_info_crypt_header_offset(info) == -1);
		ck_assert(zc_file_info_idx(info) == i);
		buf = zc_file_info_enc_header(info);
		for (int j = 0; j < 12; ++j)
			ck_assert(buf[j] == 0);
		info = zc_file_info_next(file, info);
		++i;
	} while (info);

	ck_assert_int_eq(i, 3);

	zc_file_close(file);
}
END_TEST

Suite *file_suite(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("File");

	tc_core = tcase_create("Core");

	tcase_add_checked_fixture(tc_core, setup, teardown);
	tcase_add_test(tc_core, test_zc_file_new);
	tcase_add_test(tc_core, test_zc_file_open_existant);
	tcase_add_test(tc_core, test_zc_file_open_nonexistant);
	tcase_add_test(tc_core, test_zc_file_close_opened);
	tcase_add_test(tc_core, test_zc_file_info_encrypted);
	tcase_add_test(tc_core, test_zc_file_info_non_encrypted);
	suite_add_tcase(s, tc_core);

	return s;
}

int main(void)
{
	int number_failed;
	Suite *s;
	SRunner *sr;

	s = file_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_NORMAL);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
