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

#ifndef ZIP_H
#define ZIP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct zc_header;
struct zc_zip;

void zc_zip_destroy(struct zc_zip *zip);
int zc_zip_new_from_filename(const char *filename, struct zc_zip **zip);
const char *zc_zip_get_filename(const struct zc_zip *zip);
int zc_zip_open(struct zc_zip *zip);
int zc_zip_close(struct zc_zip *zip);
bool zc_zip_isopened(const struct zc_zip *zip);

int zc_zip_fill_header(const char *filename, struct zc_header *header,
		       size_t len);
int zc_zip_fill_test_cipher(const char *filename, unsigned char **buf,
			    size_t *len, uint32_t *original_crc,
			    bool *is_deflated);

struct zc_zip_info;
const struct zc_zip_info *zc_zip_info_next(const struct zc_zip *zip,
					   const struct zc_zip_info *info);
const char *zc_zip_info_name(const struct zc_zip_info *info);
uint64_t zc_zip_info_size(const struct zc_zip_info *info);
uint64_t zc_zip_info_compressed_size(const struct zc_zip_info *info);
off_t zc_zip_info_offset_begin(const struct zc_zip_info *info);
off_t zc_zip_info_offset_end(const struct zc_zip_info *info);
off_t zc_zip_info_crypt_header_offset(const struct zc_zip_info *info);
const uint8_t *zc_zip_info_enc_header(const struct zc_zip_info *info);
int zc_zip_info_idx(const struct zc_zip_info *info);

#endif /* ZIP_H */
