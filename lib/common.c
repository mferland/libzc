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

#include "libzc_private.h"
#include "decrypt_byte.h"

int fill_header(struct zc_ctx *ctx, const char *filename,
		struct zc_header *h,
		size_t len)
{
	struct zc_file *file;
	int err;

	err = zc_file_new_from_filename(ctx, filename, &file);
	if (err)
		return -1;

	err = zc_file_open(file);
	if (err) {
		zc_file_unref(file);
		return -1;
	}

	int size = read_zc_header(file, h, len);

	zc_file_close(file);
	zc_file_unref(file);

	return size;
}

int fill_test_cipher(struct zc_ctx *ctx, const char *filename,
		     unsigned char **buf, size_t *len,
		     uint32_t *original_crc, bool *is_deflated)
{
	struct zc_file *file;
	int err;

	err = zc_file_new_from_filename(ctx, filename, &file);
	if (err)
		goto err1;

	err = zc_file_open(file);
	if (err)
		goto err2;

	err = read_crypt_data(file, buf, len, original_crc, is_deflated);
	zc_file_close(file);
	zc_file_unref(file);

	return err ? -1 : 0;

err2:
	zc_file_unref(file);
err1:
	return -1;
}

void decrypt(const unsigned char *in, unsigned char *out, size_t len,
	     const struct zc_key *key)
{
	struct zc_key k = *key;

	for (size_t i = 0; i < len - 1; ++i) {
		out[i] = in[i] ^ decrypt_byte_lookup(k.key2);
		update_keys(out[i], &k, &k);
	}

	out[len - 1] = in[len - 1] ^ decrypt_byte_lookup(k.key2);
}

uint8_t decrypt_header(const uint8_t *buf, struct zc_key *k, uint8_t magic)
{
	for (size_t i = 0; i < ENC_HEADER_LEN - 1; ++i) {
		uint8_t c = buf[i] ^ decrypt_byte_lookup(k->key2);
		update_keys(c, k, k);
	}

	/* Returns the last byte of the decrypted header */
	return buf[ENC_HEADER_LEN - 1] ^ decrypt_byte_lookup(k->key2) ^ magic;
}

bool decrypt_headers(const struct zc_key *k, const struct zc_header *h, size_t len)
{
	struct zc_key tmp;

	for (size_t i = 0; i < len; ++i) {
		reset_encryption_keys(k, &tmp);
		if (decrypt_header(h[i].buf, &tmp, h[i].magic))
			return false;
	}

	return true;
}
