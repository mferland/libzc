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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>

#include "libzc.h"
#include "libzc_private.h"
#include "list.h"

#define SIG                   0x04034b50
#define DATA_DESC_SIG         0x08074b50
#define STATIC_HEADER_LEN     30
#define GP_BIT_HAS_DATA_DESC  (1 << 3)
#define GP_BIT_ENCRYPTION     0x1
#define MAX_FNLENGTH          (4096 + 255)

struct zc_info {
	/* begin and end of the entry payload */
	long begin_offset;
	long end_offset;

	/* zip file entry info */
	uint16_t version_needed;
	uint16_t gen_bit_flag;
	uint16_t comp_method;
	uint16_t last_mod_time;
	uint16_t last_mod_date;
	uint32_t crc32;
	uint32_t comp_size;
	uint32_t uncomp_size;
	uint16_t filename_length;
	uint16_t extra_field_length;
	char *filename;

	/* encryption header */
	struct zc_header header;
	long header_offset;

	/* zip file entry index */
	int idx;

	struct list_head list;
};

/**
 * SECTION:file
 * @short_description: libzc zip file
 *
 * The file structure contains information about the targeted zip
 * file.
 */

/**
 * zc_file:
 *
 * Opaque object representing the zip file.
 */
struct zc_file {
	struct zc_ctx *ctx;
	int refcount;
	char *filename;
	FILE *stream;
	struct list_head info_head;
};

static uint16_t get_le16_at(const uint8_t *b, size_t i)
{
	return (uint16_t)b[i + 1] << 8 | (uint16_t)b[i];
}

static uint32_t get_le32_at(const uint8_t *b, size_t i)
{
	return (uint32_t)b[i + 3] << 24 |
		(uint32_t)b[i + 2] << 16 |
		(uint32_t)b[i + 1] << 8 |
		(uint32_t)b[i];
}

static bool is_encrypted(uint16_t flag)
{
	return !!(flag & GP_BIT_ENCRYPTION);
}

static bool has_data_desc(uint16_t flag)
{
	return !!(flag & GP_BIT_HAS_DATA_DESC);
}

static bool is_deflated(uint16_t flag)
{
	return flag == 0x8;
}

static bool is_stored(uint16_t flag)
{
	return flag == 0x0;
}

static uint8_t check_byte(const struct zc_info *e)
{
	if (has_data_desc(e->gen_bit_flag))
		return e->last_mod_time >> 8;
	return e->crc32 >> 24;
}

static void clear_info_list(struct zc_file *f)
{
	struct zc_info *i, *tmp;
	list_for_each_entry_safe(i, tmp, &f->info_head, list) {
		list_del(&i->list);
		free(i->filename);
		free(i);
	}
}

static int fill_info_list(struct zc_file *f)
{
	int ret, sig, idx = 0;
	uint8_t buf[STATIC_HEADER_LEN - 4];
	struct zc_info *info;

	rewind(f->stream);

	while (1) {

		/* read zip entry signature */
		ret = fread(buf, 4, 1, f->stream);
		if (ret != 1)
			return -1;

		sig = get_le32_at(buf, 0);
		if (sig != SIG)
			return idx == 0;

		info = calloc(1, sizeof(struct zc_info));
		if (!info)
			goto err1;

		/* static header */
		ret = fread(buf, STATIC_HEADER_LEN - 4, 1, f->stream);
		if (ret != 1)
			goto err2;

		info->version_needed = get_le16_at(buf, 0);
		info->gen_bit_flag = get_le16_at(buf, 2);
		info->comp_method = get_le16_at(buf, 4);
		info->last_mod_time = get_le16_at(buf, 6);
		info->last_mod_date = get_le16_at(buf, 8);
		info->crc32 = get_le32_at(buf, 10);
		info->comp_size = get_le32_at(buf, 14);
		info->uncomp_size = get_le32_at(buf, 18);
		info->filename_length = get_le16_at(buf, 22);
		info->extra_field_length = get_le16_at(buf, 24);

		/* encrypted files should always have a minimum
		 * compressed size of ENC_HEADER_LEN. See APPNOTE.txt
		 * 4.4.8. */
		if (is_encrypted(info->gen_bit_flag) &&
		    info->comp_size < ENC_HEADER_LEN) {
			goto err2;
		}

		/* filename (variable length) */
		if (!info->filename_length ||
		    info->filename_length > MAX_FNLENGTH)
			goto err2;

		info->filename = calloc(1, info->filename_length + 1);
		if (!info->filename)
			goto err2;

		ret = fread(info->filename, info->filename_length, 1, f->stream);
		if (ret != 1)
			goto err2;

		/* skip the extra field */
		ret = fseek(f->stream, info->extra_field_length, SEEK_CUR);
		if (ret < 0)
			goto err2;

		/* set offsets and read encrypted header */
		if (is_encrypted(info->gen_bit_flag)) {
			info->header.magic = check_byte(info);
			info->header_offset = ftell(f->stream);
			info->begin_offset = info->header_offset + ENC_HEADER_LEN;
			info->end_offset = info->header_offset + info->comp_size;
			ret = fread(info->header.buf, ENC_HEADER_LEN, 1, f->stream);
			if (ret != 1)
				goto err2;
		} else {
			info->header.magic = 0;
			info->header_offset = -1;
			info->begin_offset = ftell(f->stream);
			info->end_offset = info->begin_offset + info->comp_size;
		}

		/* seek to end of compressed stream */
		ret = fseek(f->stream, info->end_offset, SEEK_SET);
		if (ret)
			goto err2;

		/* seek data descriptor signature */
		if (has_data_desc(info->gen_bit_flag)) {
			int data_desc_sig;

			/*
			  signature                       4 bytes (optional)
			  crc-32                          4 bytes
			  compressed size                 4 bytes
			  uncompressed size               4 bytes
			*/

			ret = fread(buf, 4, 1, f->stream);
			if (ret != 1)
				goto err2;
			data_desc_sig = get_le32_at(buf, 0);
			ret = fseek(f->stream, data_desc_sig == DATA_DESC_SIG ? 12 : 8, SEEK_CUR);
			if (ret)
				goto err2;
		}

		info->idx = idx;

		list_add_tail(&info->list, &f->info_head);
		++idx;
	}

	return 0;

err2:
	free(info->filename);
	free(info);
err1:
	clear_info_list(f);
	return -1;
}

ZC_EXPORT struct zc_file *zc_file_ref(struct zc_file *file)
{
	if (!file)
		return NULL;
	file->refcount++;
	return file;
}

ZC_EXPORT struct zc_file *zc_file_unref(struct zc_file *file)
{
	if (!file)
		return NULL;
	file->refcount--;
	if (file->refcount > 0)
		return file;
	dbg(file->ctx, "file %p released\n", file);
	free(file->filename);
	free(file);
	return NULL;
}

/**
 * zc_file_new_from_filename:
 *
 * Allocate a new zc_file from the given filename. The file existence
 * is not verified at this stage.
 *
 * @retval 0      Success
 * @retval -1     Error
 */
ZC_EXPORT int zc_file_new_from_filename(struct zc_ctx *ctx,
					const char *filename, struct zc_file **file)
{
	struct zc_file *newfile;

	newfile = calloc(1, sizeof(struct zc_file));
	if (!newfile)
		return -1;

	newfile->ctx = ctx;
	newfile->refcount = 1;
	newfile->filename = strdup(filename);
	INIT_LIST_HEAD(&newfile->info_head);
	*file = newfile;
	dbg(ctx, "file %p created for %s\n", newfile, filename);
	return 0;
}

/**
 * zc_file_get_filename:
 *
 * @retval Filename of the passed zc_file object.
 */
ZC_EXPORT const char *zc_file_get_filename(const struct zc_file *file)
{
	return file->filename;
}

/**
 * zc_file_open:
 *
 * Open the file for reading.
 *
 * @retval Returns the fopen() return value.
 */
ZC_EXPORT int zc_file_open(struct zc_file *file)
{
	FILE *stream;

	if (zc_file_isopened(file))
		return -1;

	stream = fopen(file->filename, "r");
	if (!stream) {
		err(file->ctx, "fopen() failed: %s.\n", strerror(errno));
		return -1;
	}

	dbg(file->ctx, "file %p open returned: %p\n", file, stream);

	file->stream = stream;

	if (fill_info_list(file)) {
		err(file->ctx, "failure while reading headers.\n");
		goto err;
	}

	return 0;

err:
	fclose(file->stream);
	file->stream = NULL;
	return -1;
}

/**
 * zc_file_close:
 *
 * Close the file.
 *
 * @retval Returns the fclose() return value.
 */
ZC_EXPORT int zc_file_close(struct zc_file *file)
{
	if (!zc_file_isopened(file))
		return -1;

	clear_info_list(file);

	if (fclose(file->stream)) {
		err(file->ctx, "fclose() failed: %s.\n", strerror(errno));
		return -1;
	}

	dbg(file->ctx, "file %p closed\n", file);

	file->stream = NULL;

	return 0;
}

/**
 * zc_file_isopened:
 *
 * @retval Whether or not the file is opened.
 */
ZC_EXPORT bool zc_file_isopened(struct zc_file *file)
{
	return (file->stream != NULL);
}

static bool consider_file(struct zc_info *info)
{
	if (!is_encrypted(info->gen_bit_flag) ||
	    (!is_deflated(info->comp_method) &&
	     !is_stored(info->comp_method)))
		return false;
	return true;
}

/**
 * read_zc_header:
 *
 * Read the validation data from the file and store them in the header
 * array. At most nmemb elements will be stored in the array.
 *
 * The file must be opened before calling this function.
 *
 * @retval 0  No encryption data found in this file.
 * @retval >0 The number of encryption data objects read.
 */
size_t read_zc_header(struct zc_file *file, struct zc_header *h, size_t len)
{
	struct zc_info *info;
	size_t valid = 0;

	list_for_each_entry(info, &file->info_head, list) {
		if (!consider_file(info))
			continue;

		h[valid].magic = info->header.magic;
		memcpy(h[valid].buf, info->header.buf, ENC_HEADER_LEN);

		if (++valid == len)
			break;
	}

	return valid;
}

static struct zc_info *find_file_smallest(struct zc_file *file)
{
	struct zc_info *info, *ret = NULL;
	long s = LONG_MAX;

	list_for_each_entry(info, &file->info_head, list) {
		if (!consider_file(info))
			continue;
		long tmp = info->end_offset - info->begin_offset;
		if (tmp < s) {
			s = tmp;
			ret = info;
		}
	}

	return ret;
}

int read_crypt_data(struct zc_file *file, unsigned char **buf,
		    size_t *len, uint32_t *original_crc, bool *deflated)
{
	struct zc_info *info;
	size_t to_read;
	int err;

	info = find_file_smallest(file);
	if (!info)
		return -1;

	to_read = info->end_offset - info->header_offset;

	err = fseek(file->stream, info->header_offset, SEEK_SET);
	if (err) {
		err(file->ctx, "fseek(): %s\n", strerror(errno));
		return -1;
	}

	unsigned char *tmp = malloc(to_read);
	if (!tmp) {
		err(file->ctx, "malloc() failed(): %s\n", strerror(errno));
		return -1;
	}

	size_t ret = fread(tmp, 1, to_read, file->stream);
	if (ferror(file->stream)) {
		err(file->ctx, "fread() error.\n");
		goto err;
	} else if (feof(file->stream)) {
		err(file->ctx, "fread() read past eof. File corrupted?\n");
		goto err;
	}

	*buf = tmp;
	*len = ret;
	*original_crc = info->crc32;
	*deflated = is_deflated(info->comp_method);

	return 0;

err:
	free(tmp);
	return -1;
}

ZC_EXPORT struct zc_info *zc_file_info_next(struct zc_file *file,
					    struct zc_info *info)
{
	struct zc_info *i;

	if (!info) {
		i = list_entry(file->info_head.next, struct zc_info, list);
		return i;
	}

	if (info->list.next == &file->info_head)
		return NULL;

	i = list_entry(info->list.next, struct zc_info, list);

	return i;
}

ZC_EXPORT const char *zc_file_info_name(const struct zc_info *info)
{
	return info->filename;
}

ZC_EXPORT uint32_t zc_file_info_size(const struct zc_info *info)
{
	return info->uncomp_size;
}

ZC_EXPORT uint32_t zc_file_info_compressed_size(const struct zc_info *info)
{
	return info->comp_size;
}

ZC_EXPORT long zc_file_info_offset_begin(const struct zc_info *info)
{
	return info->begin_offset;
}

ZC_EXPORT long zc_file_info_offset_end(const struct zc_info *info)
{
	return info->end_offset;
}

ZC_EXPORT long zc_file_info_crypt_header_offset(const struct zc_info *info)
{
	return info->header_offset;
}

ZC_EXPORT const uint8_t *zc_file_info_enc_header(const struct zc_info *info)
{
	return info->header.buf;
}

ZC_EXPORT int zc_file_info_idx(const struct zc_info *info)
{
	return info->idx;
}
