/*
 *  yazc - ZIP password recovery application
 *  Copyright (C) 2012-2026 Marc Ferland
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "vulkan_search.h"

static int compare_char(const void *a, const void *b)
{
	/* Match the CPU brute-force command's native-char ordering. */
	return *(const char *)a - *(const char *)b;
}

int zc_vulkan_search_init(struct zc_vulkan_search *search,
			  const char *charset, size_t length)
{
	char set[ZC_CHARSET_MAXLEN];
	size_t inlen;
	size_t outlen = 0;

	if (!search || !charset || length < ZC_PW_MINLEN ||
	    length > ZC_PW_MAXLEN)
		return -1;

	inlen = strnlen(charset, ZC_CHARSET_MAXLEN + 1);
	if (!inlen || inlen > ZC_CHARSET_MAXLEN)
		return -1;

	memcpy(set, charset, inlen);
	qsort(set, inlen, sizeof(set[0]), compare_char);

	/* Sort and remove duplicates exactly as the CPU command does.  Besides
	 * producing stable candidate order, this ensures each password appears
	 * only once in the GPU search space. */
	memset(search, 0, sizeof(*search));
	for (size_t i = 0; i < inlen; ++i) {
		if (outlen && (unsigned char)set[i] ==
		    search->alphabet[outlen - 1])
			continue;
		search->alphabet[outlen++] = (unsigned char)set[i];
	}

	search->radix = outlen;
	dbg("normalized Vulkan charset from %zu to %zu unique characters\n",
	    inlen, outlen);
	return zc_vulkan_search_set_length(search, length);
}

int zc_vulkan_search_set_length(struct zc_vulkan_search *search,
				size_t length)
{
	if (!search || !search->radix || length < ZC_PW_MINLEN ||
	    length > ZC_PW_MAXLEN)
		return -1;

	/* Every password length is an independent mixed-radix search space. */
	memset(search->digits, 0, sizeof(search->digits));
	search->length = length;
	dbg("reset Vulkan mixed-radix counter for length %zu\n", length);
	return 0;
}

bool zc_vulkan_search_add(uint32_t *digits, size_t length, uint32_t radix,
			  uint32_t offset)
{
	uint64_t carry = offset;

	if (!digits || !length || length > ZC_PW_MAXLEN || !radix)
		return true;

	/*
	 * Treat digits as a fixed-width mixed-radix integer.  With radix 3,
	 * adding 2 to [0, 2] ("ac") produces [1, 1] ("bb").  A carry left after
	 * the most significant digit means the search space wrapped.
	 */
	for (size_t pos = length; pos > 0 && carry; --pos) {
		uint64_t sum = digits[pos - 1] + carry;

		digits[pos - 1] = sum % radix;
		carry = sum / radix;
	}

	return carry != 0;
}

uint32_t zc_vulkan_search_chunk_count(const uint32_t *digits, size_t length,
				      uint32_t radix, uint32_t limit)
{
	uint32_t tmp[ZC_PW_MAXLEN];
	uint32_t low;
	uint32_t high;

	if (!digits || !length || length > ZC_PW_MAXLEN || !radix || !limit)
		return 0;

	/*
	 * The full limit fits, so no search is necessary in the common case.
	 * Otherwise find the first offset that wraps.  That offset is also the
	 * number of candidates remaining because offset zero is the current value.
	 */
	memcpy(tmp, digits, length * sizeof(*tmp));
	if (!zc_vulkan_search_add(tmp, length, radix, limit))
		return limit;

	low = 1;
	high = limit;
	while (low < high) {
		uint32_t mid = low + (high - low) / 2;

		memcpy(tmp, digits, length * sizeof(*tmp));
		if (zc_vulkan_search_add(tmp, length, radix, mid))
			high = mid;
		else
			low = mid + 1;
	}

	dbg("clamped final Vulkan chunk from %u to %u candidates\n",
	    limit, low);
	return low;
}

void zc_vulkan_search_password(const struct zc_vulkan_search *search,
			       uint32_t offset, char *password)
{
	uint32_t digits[ZC_PW_MAXLEN];

	/* Reconstruct only a survivor selected by the GPU; the hot path never
	 * materializes candidate strings in host memory. */
	memcpy(digits, search->digits, search->length * sizeof(*digits));
	(void)zc_vulkan_search_add(digits, search->length, search->radix,
				   offset);

	for (size_t i = 0; i < search->length; ++i)
		password[i] = search->alphabet[digits[i]];

	password[search->length] = '\0';
}
