/*
 *  yazc - ZIP password recovery application
 *  Copyright (C) 2026 Marc Ferland
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <check.h>
#include <stdint.h>
#include <string.h>

#include "vulkan_search.h"

START_TEST(test_search_sanitizes_charset)
{
	struct zc_vulkan_search search;

	ck_assert_int_eq(zc_vulkan_search_init(&search, "caba", 3), 0);
	ck_assert_uint_eq(search.radix, 3);
	ck_assert_uint_eq(search.length, 3);
	ck_assert_uint_eq(search.alphabet[0], 'a');
	ck_assert_uint_eq(search.alphabet[1], 'b');
	ck_assert_uint_eq(search.alphabet[2], 'c');
}
END_TEST

START_TEST(test_search_rejects_invalid_configuration)
{
	struct zc_vulkan_search search;
	char too_long[ZC_CHARSET_MAXLEN + 2];

	memset(too_long, 'a', sizeof(too_long) - 1);
	too_long[sizeof(too_long) - 1] = '\0';
	ck_assert_int_eq(zc_vulkan_search_init(NULL, "a", 1), -1);
	ck_assert_int_eq(zc_vulkan_search_init(&search, NULL, 1), -1);
	ck_assert_int_eq(zc_vulkan_search_init(&search, "", 1), -1);
	ck_assert_int_eq(zc_vulkan_search_init(&search, "a", 0), -1);
	ck_assert_int_eq(zc_vulkan_search_init(&search, "a",
					       ZC_PW_MAXLEN + 1), -1);
	ck_assert_int_eq(zc_vulkan_search_init(&search, too_long, 1), -1);
}
END_TEST

START_TEST(test_search_password_order)
{
	struct zc_vulkan_search search;
	char password[ZC_PW_MAXLEN + 1];

	ck_assert_int_eq(zc_vulkan_search_init(&search, "cba", 3), 0);
	zc_vulkan_search_password(&search, 0, password);
	ck_assert_str_eq(password, "aaa");
	zc_vulkan_search_password(&search, 1, password);
	ck_assert_str_eq(password, "aab");
	zc_vulkan_search_password(&search, 3, password);
	ck_assert_str_eq(password, "aba");
	zc_vulkan_search_password(&search, 26, password);
	ck_assert_str_eq(password, "ccc");
}
END_TEST

START_TEST(test_search_set_length_resets_counter)
{
	struct zc_vulkan_search search;

	ck_assert_int_eq(zc_vulkan_search_init(&search, "ab", 2), 0);
	search.digits[0] = 1;
	search.digits[1] = 1;

	ck_assert_int_eq(zc_vulkan_search_set_length(&search, 3), 0);
	ck_assert_uint_eq(search.length, 3);
	for (size_t i = 0; i < ZC_PW_MAXLEN; ++i)
		ck_assert_uint_eq(search.digits[i], 0);

	ck_assert_int_eq(zc_vulkan_search_set_length(NULL, 1), -1);
	ck_assert_int_eq(zc_vulkan_search_set_length(&search, 0), -1);
	ck_assert_int_eq(zc_vulkan_search_set_length(
				&search, ZC_PW_MAXLEN + 1), -1);
}
END_TEST

START_TEST(test_search_add_carries_and_wraps)
{
	uint32_t digits[] = { 0, 1, 2 };

	ck_assert(!zc_vulkan_search_add(digits, 3, 3, 1));
	ck_assert_uint_eq(digits[0], 0);
	ck_assert_uint_eq(digits[1], 2);
	ck_assert_uint_eq(digits[2], 0);
	ck_assert(!zc_vulkan_search_add(digits, 3, 3, 18));
	ck_assert_uint_eq(digits[0], 2);
	ck_assert_uint_eq(digits[1], 2);
	ck_assert_uint_eq(digits[2], 0);
	ck_assert(zc_vulkan_search_add(digits, 3, 3, 3));
	ck_assert(zc_vulkan_search_add(digits, ZC_PW_MAXLEN + 1, 3, 1));
}
END_TEST

START_TEST(test_search_chunk_count)
{
	const uint32_t start[] = { 0, 0 };
	const uint32_t middle[] = { 1, 0 };
	const uint32_t last[] = { 1, 1 };

	ck_assert_uint_eq(zc_vulkan_search_chunk_count(start, 2, 2, 2), 2);
	ck_assert_uint_eq(zc_vulkan_search_chunk_count(start, 2, 2, 10), 4);
	ck_assert_uint_eq(zc_vulkan_search_chunk_count(middle, 2, 2, 10), 2);
	ck_assert_uint_eq(zc_vulkan_search_chunk_count(last, 2, 2, 10), 1);
	ck_assert_uint_eq(zc_vulkan_search_chunk_count(start, 2, 1, 10), 1);
	ck_assert_uint_eq(zc_vulkan_search_chunk_count(start, 0, 2, 10), 0);
	ck_assert_uint_eq(zc_vulkan_search_chunk_count(start, 2, 0, 10), 0);
	ck_assert_uint_eq(zc_vulkan_search_chunk_count(start, 2, 2, 0), 0);
}
END_TEST

START_TEST(test_search_large_offset)
{
	uint32_t digits[] = { 0, 0, 0, 0, 0 };

	ck_assert(!zc_vulkan_search_add(digits, 5, 96, UINT32_MAX));
	ck_assert_uint_eq(digits[0], 50);
	ck_assert_uint_eq(digits[1], 54);
	ck_assert_uint_eq(digits[2], 49);
	ck_assert_uint_eq(digits[3], 74);
	ck_assert_uint_eq(digits[4], 63);
}
END_TEST

static Suite *vulkan_search_suite(void)
{
	Suite *suite = suite_create("vulkan-search");
	TCase *core = tcase_create("core");

	tcase_add_test(core, test_search_sanitizes_charset);
	tcase_add_test(core, test_search_rejects_invalid_configuration);
	tcase_add_test(core, test_search_password_order);
	tcase_add_test(core, test_search_set_length_resets_counter);
	tcase_add_test(core, test_search_add_carries_and_wraps);
	tcase_add_test(core, test_search_chunk_count);
	tcase_add_test(core, test_search_large_offset);
	suite_add_tcase(suite, core);
	return suite;
}

int main(void)
{
	Suite *suite = vulkan_search_suite();
	SRunner *runner = srunner_create(suite);
	int failed;

	srunner_run_all(runner, CK_NORMAL);
	failed = srunner_ntests_failed(runner);
	srunner_free(runner);
	return failed ? 1 : 0;
}
