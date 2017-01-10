/*
 *  zc - zip crack library
 *  Copyright (C) 2013  Marc Ferland
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
#include <endian.h>
#include <stdint.h>

#include "libzc.h"
#include "libzc_private.h"
#include "list.h"

#define ZIP_SIG               0x04034b50
#define ZIP_DATA_DESC_SIG     0x08074b50
#define ZIP_STATIC_HEADER_LEN 30
#define GP_BIT_HAS_DATA_DESC  (1 << 3)
#define GP_BIT_ENCRYPTION     0x1

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
    return b[i + 1] << 8 | b[i];
}

static uint32_t get_le32_at(const uint8_t *b, size_t i)
{
    return b[i + 3] << 24 | b[i + 2] << 16 | b[i + 1] << 8 | b[i];
}

static bool is_encrypted(uint16_t flag)
{
    return !!(flag & GP_BIT_ENCRYPTION);
}

static bool has_data_desc(uint16_t flag)
{
    return !!(flag & GP_BIT_HAS_DATA_DESC);
}

static uint8_t check_byte(const struct header *h)
{
    if (has_data_desc(h->gen_bit_flag))
        return h->last_mod_time >> 8;
    return h->crc32 >> 24;
}

void clear_header_list(struct zc_file *f)
{
    struct zc_info *i, *tmp;
    list_for_each_entry_safe(i, tmp, &f->info_head, header_list) {
        list_del(&i->header_list);
        free(i->header.filename);
        free(i);
    }
}

int fill_header_list(struct zc_file *f)
{
    int ret, sig, idx = 0;
    uint8_t buf[ZIP_STATIC_HEADER_LEN - 4];
    struct zc_info *info;

    rewind(f->stream);

    while (1) {

        /* read zip header signature */
        ret = fread(&sig, 4, 1, f->stream);
        if (ret != 1) {
            return -1;
        } else if (sig != ZIP_SIG) {
            return idx == 0;
        }

        info = calloc(1, sizeof(struct zc_info));
        if (!info)
            return -1;

        /* static header */
        ret = fread(buf, ZIP_STATIC_HEADER_LEN - 4, 1, f->stream);
        if (ret != 1)
            goto end;

        info->header.version_needed = get_le16_at(buf, 0);
        info->header.gen_bit_flag = get_le16_at(buf, 2);
        info->header.comp_method = get_le16_at(buf, 4);
        info->header.last_mod_time = get_le16_at(buf, 6);
        info->header.last_mod_date = get_le16_at(buf, 8);
        info->header.crc32 = get_le32_at(buf, 10);
        info->header.comp_size = get_le32_at(buf, 14);
        info->header.uncomp_size = get_le32_at(buf, 18);
        info->header.filename_length = get_le16_at(buf, 22);
        info->header.extra_field_length = get_le16_at(buf, 24);

        /* filename (variable length) */
        if (!info->header.filename_length)
            goto end;

        info->header.filename = calloc(1, info->header.filename_length + 1);
        if (!info->header.filename)
            goto end;

        ret = fread(info->header.filename, info->header.filename_length, 1, f->stream);
        if (ret != 1)
            goto end;

        /* skip the extra field */
        ret = fseek(f->stream, info->header.extra_field_length, SEEK_CUR);
        if (ret < 0)
            goto end;

        /* set offsets and read encrypted header */
        if (is_encrypted(info->header.gen_bit_flag)) {
            info->magic = check_byte(&info->header);
            info->enc_header_offset = ftell(f->stream);
            info->begin_offset = info->enc_header_offset + ZIP_ENCRYPTION_HEADER_LENGTH;
            info->end_offset = info->enc_header_offset + info->header.comp_size;
            ret = fread(info->enc_header, ZIP_ENCRYPTION_HEADER_LENGTH, 1, f->stream);
            if (ret != 1)
                goto end;
        } else {
            info->magic = 0;
            info->enc_header_offset = -1;
            info->begin_offset = ftell(f->stream);
            info->end_offset = info->begin_offset + info->header.comp_size;
        }

        /* seek to end of compressed stream */
        fseek(f->stream, info->end_offset, SEEK_SET);

        /* seek data descriptor signature */
        if (has_data_desc(info->header.gen_bit_flag)) {
            int data_desc_sig;

            /*
              signature                       4 bytes (optional)
              crc-32                          4 bytes
              compressed size                 4 bytes
              uncompressed size               4 bytes
            */

            ret = fread(&data_desc_sig, 4, 1, f->stream);
            if (ret != 1)
                goto end;
            fseek(f->stream, data_desc_sig == ZIP_DATA_DESC_SIG ? 12 : 8, SEEK_CUR);
        }

        info->idx = idx;

        list_add_tail(&info->header_list, &f->info_head);
        ++idx;
    }

    return 0;

end:
    free(info->header.filename);
    free(info);
    clear_header_list(f);
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
ZC_EXPORT int zc_file_new_from_filename(struct zc_ctx *ctx, const char *filename, struct zc_file **file)
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
        err(file->ctx, "open() failed: %s.\n", strerror(errno));
        return -1;
    }

    dbg(file->ctx, "file %p open returned: %p\n", file, stream);

    file->stream = stream;

    int ret = fill_header_list(file);
    if (ret < 0)
        err(file->ctx, "failure while reading headers.\n");
    return ret;
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

    clear_header_list(file);

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

struct list_head * zc_file_get_info_head(struct zc_file *file)
{
    return &file->info_head;
}

/**
 * zc_file_read_validation_data:
 *
 * Read the validation data from the file and store them in the vdata
 * array. At most nmemb elements will be stored in the array.
 *
 * The file must be opened before calling this function.
 *
 * @retval 0  No encryption data found in this file.
 * @retval >0 The number of encryption data objects read.
 */
size_t zc_file_read_validation_data(struct zc_file *file, struct zc_validation_data *vdata, size_t nmemb)
{
    struct zc_info *info;
    size_t valid_files = 0;

    list_for_each_entry(info, &file->info_head, header_list) {
        if (!is_encrypted(info->header.gen_bit_flag))
            continue;

        vdata[valid_files].magic = info->magic;
        memcpy(vdata[valid_files].encryption_header,
               info->enc_header,
               ZIP_ENCRYPTION_HEADER_LENGTH);

        if (++valid_files == nmemb)
            break;
    }

    return valid_files;
}

/**
 * zc_file_test_password_ext:
 *
 * Test the given password using the unzip command line tool. This
 * should be used exclusively for discarding false positives returned
 * by the cracker.
 *
 * @retval true The file was successfully decrypted (password found).
 * @retval false The file can't be decrypted (false positive).
 */
ZC_EXPORT bool zc_file_test_password_ext(const char *filename, const char *pw)
{
    char cmd[128];
    sprintf(cmd, "unzip -qqtP \"%s\" \"%s\" >/dev/null 2>&1", pw, filename);
    return (system(cmd) == EXIT_SUCCESS);
}

ZC_EXPORT struct zc_info *zc_file_info_next(struct zc_file *file, struct zc_info *info)
{
    struct zc_info *i;

    if (!info) {
        i = list_entry((&file->info_head)->next, typeof(*i), header_list);
        return i;
    }

    i = list_entry(info->header_list.next, struct zc_info, header_list);

    if (&i->header_list == &file->info_head)
        return NULL;

    return i;
}

ZC_EXPORT const char *zc_file_info_name(const struct zc_info *info)
{
    return info->header.filename;
}

ZC_EXPORT uint32_t zc_file_info_size(const struct zc_info *info)
{
    return info->header.uncomp_size;
}

ZC_EXPORT long zc_file_info_offset(const struct zc_info *info)
{
    return info->begin_offset;
}

ZC_EXPORT long zc_file_info_crypt_header_offset(const struct zc_info *info)
{
    return info->enc_header_offset;
}

ZC_EXPORT const uint8_t *zc_file_info_enc_header(const struct zc_info *info)
{
    return info->enc_header;
}

ZC_EXPORT int zc_file_info_idx(const struct zc_info *info)
{
    return info->idx;
}
