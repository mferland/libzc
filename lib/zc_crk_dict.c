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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libzc.h"
#include "libzc_private.h"

struct zc_crk_dict {
	struct zc_ctx *ctx;
	int refcount;
	char *filename;
	struct zc_header header[HEADER_MAX];
	size_t header_size;
	unsigned char *cipher;
	unsigned char *plaintext;
	unsigned char *inflate;
	struct zlib_state *zlib;
	size_t cipher_size;
	bool cipher_is_deflated;
	uint32_t original_crc;
	FILE *fd;
};

static inline void remove_trailing_newline(char *line)
{
	while (*line) {
		if (*line == '\n' || *line == '\r') {
			*line = '\0';
			return;
		}
		++line;
	}
}

ZC_EXPORT struct zc_crk_dict *zc_crk_dict_ref(struct zc_crk_dict *crk)
{
	if (!crk)
		return NULL;
	crk->refcount++;
	return crk;
}

ZC_EXPORT struct zc_crk_dict *zc_crk_dict_unref(struct zc_crk_dict *crk)
{
	if (!crk)
		return NULL;
	crk->refcount--;
	if (crk->refcount > 0)
		return crk;
	free(crk->filename);
	free(crk->cipher);
	free(crk->plaintext);
	free(crk->inflate);
	inflate_destroy(crk->zlib);
	free(crk);
	return NULL;
}

ZC_EXPORT int zc_crk_dict_new(struct zc_ctx *ctx, struct zc_crk_dict **crk)
{
	struct zc_crk_dict *tmp;

	tmp = calloc(1, sizeof(struct zc_crk_dict));
	if (!tmp)
		return -1;

	tmp->ctx = ctx;
	tmp->refcount = 1;

	*crk = tmp;

	return 0;
}

ZC_EXPORT int zc_crk_dict_init(struct zc_crk_dict *crk, const char *filename)
{
	int err;

	crk->inflate = malloc(INFLATE_CHUNK);
	if (!crk->inflate) {
		err(crk->ctx, "failed to allocate memory\n");
		return -1;
	}

	err = fill_header(crk->ctx, filename, crk->header, HEADER_MAX);
	if (err < 1) {
		err(crk->ctx, "failed to read validation data\n");
		return -1;
	}

	crk->header_size = err;

	err = fill_test_cipher(crk->ctx,
			       filename,
			       &crk->cipher,
			       &crk->cipher_size,
			       &crk->original_crc,
			       &crk->cipher_is_deflated);
	if (err) {
		err(crk->ctx, "failed to read cipher data\n");
		return -1;
	}

	crk->plaintext = malloc(crk->cipher_size);
	if (!crk->plaintext) {
		free(crk->inflate);
		free(crk->cipher);
		return -1;
	}

	crk->filename = strdup(filename);

	if (inflate_new(&crk->zlib) < 0) {
		free(crk->inflate);
		free(crk->cipher);
		free(crk->plaintext);
		free(crk->filename);
		return -1;
	}

	return 0;
}

static bool test_password(struct zc_crk_dict *crk, const char *pw)
{
	struct zc_key base;

	update_default_keys_from_array(&base, (uint8_t *)pw, strlen(pw));

	if (!decrypt_headers(&base, crk->header, crk->header_size))
		return false;

	decrypt(crk->cipher, crk->plaintext, crk->cipher_size, &base);
	int err;
	if (crk->cipher_is_deflated)
		err = inflate_buffer(crk->zlib,
				     &crk->plaintext[12],
				     crk->cipher_size - 12,
				     crk->inflate,
				     INFLATE_CHUNK,
				     crk->original_crc);
	else
		err = test_buffer_crc(&crk->plaintext[12],
				      crk->cipher_size - 12,
				      crk->original_crc);

	return err ? false : true;
}

ZC_EXPORT int zc_crk_dict_start(struct zc_crk_dict *crk, const char *dict,
				char *pw, size_t len)
{
	FILE *f;
	int err = 1;

	/* The fgets function reads at most one less than the number
	 * of characters specified by n from the stream pointed to by
	 * stream into the array pointed to by s. No additional
	 * characters are read after a new-line character (which is
	 * retained) or after end-of-file. A null character is written
	 * immediately after the last character read into the
	 * array. */
	if (len < 3 || !crk->header_size)
		return -1;

	if (dict) {
		f = fopen(dict, "r");
		if (!f) {
			err(crk->ctx, "fopen() failed: %s\n", strerror(errno));
			return -1;
		}
	} else
		f = stdin;

	while (1) {
		char *s = fgets(pw, len, f);
		if (!s) {
			err = -1;
			break;
		}

		remove_trailing_newline(s);

		if (test_password(crk, s)) {
			err = 0;
			break;
		}
	}

	fclose(f);
	return err;
}
