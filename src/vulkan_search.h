/*
 * Host-side search-space helpers shared by the Vulkan engine and its tests.
 */

#ifndef VULKAN_SEARCH_H
#define VULKAN_SEARCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bruteforce.h"

struct zc_vulkan_search {
	/* alphabet maps a digit to its byte value; digits is the current base. */
	uint32_t alphabet[ZC_CHARSET_MAXLEN];
	uint32_t digits[ZC_PW_MAXLEN];
	uint32_t radix;
	uint32_t length;
};

/* Normalize charset and initialize the mixed-radix counter to password zero. */
int zc_vulkan_search_init(struct zc_vulkan_search *search,
			  const char *charset, size_t length);

/* Start a new fixed-length subspace at its first password. */
int zc_vulkan_search_set_length(struct zc_vulkan_search *search,
				size_t length);

/* Add offset to digits.  Return true when the mixed-radix value wraps. */
bool zc_vulkan_search_add(uint32_t *digits, size_t length, uint32_t radix,
			  uint32_t offset);

/* Number of candidates available from digits, capped at limit. */
uint32_t zc_vulkan_search_chunk_count(const uint32_t *digits, size_t length,
				      uint32_t radix, uint32_t limit);

void zc_vulkan_search_password(const struct zc_vulkan_search *search,
			       uint32_t offset, char *password);

#endif /* VULKAN_SEARCH_H */
