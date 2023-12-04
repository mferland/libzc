/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2021 Marc Ferland
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
	zc_file_new_from_filename(ctx, DATADIR "test.zip", &file);
	ck_assert_msg(strcmp(zc_file_get_filename(file), DATADIR "test.zip") == 0,
		      "Filename does not match.");
	ck_assert(zc_file_isopened(file) == false);
}
END_TEST

START_TEST(test_zc_file_open_existant)
{
	zc_file_new_from_filename(ctx, DATADIR "test.zip", &file);
	ck_assert(zc_file_isopened(file) == false);
	ck_assert_msg(zc_file_open(file) == 0,
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
	ck_assert_msg(zc_file_open(file) != 0,
		      "Non-existant file reported having been opened.");
	ck_assert(zc_file_isopened(file) == false);
}
END_TEST

START_TEST(test_zc_file_close_opened)
{
	zc_file_new_from_filename(ctx, DATADIR "test.zip", &file);
	zc_file_open(file);
	ck_assert_msg(zc_file_close(file) == 0,
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
 * data/test_zyx.zip:
INDEX NAME          OFFSETS              SIZE   CSIZE  ENCRYPTED HEADER
    0 config.guess  70     82     13527  45297  13457  99b22b7def611384fb0f777d
    1 config.h      13609  13621  14388  2331   779    9cb0097b818d14925d82be44
    2 config.h.in   14473  14485  15163  2092   690    c58b0ab4922bb4e72e9c83b8
    3 config.log    15247  15259  23584  33463  8337   0577d617d5a2564eccdea54a
    4 config.status 23671  23683  42786  61989  19115  a42b61ddedb141ea112be7f9
    5 config.sub    42870  42882  52989  35564  10119  1c97f36a3e8d4b2607ee7eda
    6 configure     53072  53084  154479 453798 101407 b253554f291f7bf4fb40ea58
    7 configure.ac  154565 154577 155414 2034   849    28869d160f08532eed9648f7
 */
START_TEST(test_zc_file_info_encrypted_2)
{
	const uint8_t header[8][12] = {
		{0x99, 0xb2, 0x2b, 0x7d, 0xef, 0x61, 0x13, 0x84, 0xfb, 0x0f, 0x77, 0x7d},
		{0x9c, 0xb0, 0x09, 0x7b, 0x81, 0x8d, 0x14, 0x92, 0x5d, 0x82, 0xbe, 0x44},
		{0xc5, 0x8b, 0x0a, 0xb4, 0x92, 0x2b, 0xb4, 0xe7, 0x2e, 0x9c, 0x83, 0xb8},
		{0x05, 0x77, 0xd6, 0x17, 0xd5, 0xa2, 0x56, 0x4e, 0xcc, 0xde, 0xa5, 0x4a},
		{0xa4, 0x2b, 0x61, 0xdd, 0xed, 0xb1, 0x41, 0xea, 0x11, 0x2b, 0xe7, 0xf9},
		{0x1c, 0x97, 0xf3, 0x6a, 0x3e, 0x8d, 0x4b, 0x26, 0x07, 0xee, 0x7e, 0xda},
		{0xb2, 0x53, 0x55, 0x4f, 0x29, 0x1f, 0x7b, 0xf4, 0xfb, 0x40, 0xea, 0x58},
		{0x28, 0x86, 0x9d, 0x16, 0x0f, 0x08, 0x53, 0x2e, 0xed, 0x96, 0x48, 0xf7},
	};
	const uint32_t info_size[8] = {45297, 2331, 2092, 33463, 61989, 35564, 453798, 2034};
	const uint32_t info_csize[8] = {13457, 779, 690, 8337, 19115, 10119, 101407, 849};
	const long info_offset[8] = {82, 13621, 14485, 15259, 23683, 42882, 53084, 154577};
	const long info_crypt[8] = {70, 13609, 14473, 15247, 23671, 42870, 53072, 154565};
	const char *info_filename[8] = {"config.guess",
					"config.h",
					"config.h.in",
					"config.log",
					"config.status",
					"config.sub",
					"configure",
					"configure.ac"
				       };
	struct zc_info *info;
	const uint8_t *buf;

	zc_file_new_from_filename(ctx, DATADIR "test_zyx.zip", &file);
	ck_assert_msg(zc_file_open(file) == 0,
		      "zc_file_open() failed");

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

	ck_assert_int_eq(i, 8);

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
	tcase_add_test(tc_core, test_zc_file_info_encrypted_2);
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
