/*
 *  yazc - ZIP password recovery application
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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dictionary.h"
#include "inflate.h"
#include "log.h"
#include "zc.h"
#include "zip.h"

struct zc_dictionary {
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

void zc_dictionary_destroy(struct zc_dictionary *ctx)
{
	if (!ctx)
		return;
	free(ctx->filename);
	free(ctx->cipher);
	free(ctx->plaintext);
	free(ctx->inflate);
	if (ctx->zlib)
		inflate_destroy(ctx->zlib);
	free(ctx);
}

int zc_dictionary_new(struct zc_dictionary **ctx)
{
	*ctx = calloc(1, sizeof(struct zc_dictionary));
	if (!*ctx)
		return -1;

	return 0;
}

int zc_dictionary_init(struct zc_dictionary *ctx, const char *filename)
{
	int err;

	ctx->inflate = malloc(INFLATE_CHUNK);
	if (!ctx->inflate) {
		err("malloc() failed: %s\n", strerror(errno));
		goto err1;
	}

	err = zc_zip_fill_header(filename, ctx->header, HEADER_MAX);
	if (err < 1) {
		err("failed to read validation data\n");
		goto err2;
	}

	ctx->header_size = err;

	err = zc_zip_fill_test_cipher(filename, &ctx->cipher,
				      &ctx->cipher_size, &ctx->original_crc,
				      &ctx->cipher_is_deflated);
	if (err) {
		err("failed to read cipher data\n");
		goto err2;
	}

	ctx->plaintext = malloc(ctx->cipher_size);
	if (!ctx->plaintext)
		goto err3;

	ctx->filename = strdup(filename);

	if (inflate_new(&ctx->zlib) < 0)
		goto err4;

	return 0;
err4:
	free(ctx->filename);
	ctx->filename = NULL;
err3:
	free(ctx->cipher);
	ctx->cipher = NULL;
err2:
	free(ctx->inflate);
	ctx->inflate = NULL;
err1:
	return -1;
}

static bool test_password(struct zc_dictionary *ctx, const char *pw)
{
	struct zc_key base;

	update_default_keys_from_array(&base, (const uint8_t *)pw, strlen(pw));

	if (!decrypt_headers(&base, ctx->header, ctx->header_size))
		return false;

	decrypt(ctx->cipher, ctx->plaintext, ctx->cipher_size, &base);
	int err;
	if (ctx->cipher_is_deflated)
		err = inflate_buffer(ctx->zlib, &ctx->plaintext[12],
				     ctx->cipher_size - 12, ctx->inflate,
				     INFLATE_CHUNK, ctx->original_crc);
	else
		err = test_buffer_crc(&ctx->plaintext[12],
				      ctx->cipher_size - 12, ctx->original_crc);

	return err ? false : true;
}

int zc_dictionary_start(struct zc_dictionary *ctx, const char *dictionary_filename,
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
	if (len < 3 || !ctx->header_size)
		return -1;

	if (dictionary_filename) {
		f = fopen(dictionary_filename, "r");
		if (!f) {
			err("fopen() failed: %s\n", strerror(errno));
			return -1;
		}
	} else
		f = stdin;

	while (1) {
		char *s = fgets(pw, len, f);
		if (!s) {
			int tmp = errno;
			if (feof(f))
				err = 1;
			else if (ferror(f)) {
				err("fgets() failed: %s\n",
				    strerror(tmp));
				err = -1;
			} else {
				err("unknown failure, errno: %d\n",
				    tmp);
				err = -1;
			}
			break;
		}

		remove_trailing_newline(s);

		if (test_password(ctx, s)) {
			err = 0;
			break;
		}
	}

	fclose(f);
	return err;
}
