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
#include "zip.h"
#include "libzc_private.h"

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
    FILE *fd;
};

struct zc_info {
    struct zc_file *file;
    struct zip_header *header;
    int refcount;
    int idx;
    long enc_header_offset;
    long begin_offset;
    long end_offset;
};

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
 * @retval ENOMEM Insufficient memory was available.
 */
ZC_EXPORT int zc_file_new_from_filename(struct zc_ctx *ctx, const char *filename, struct zc_file **file)
{
    struct zc_file *newfile;

    newfile = calloc(1, sizeof(struct zc_file));
    if (!newfile)
        return -ENOMEM;

    newfile->ctx = ctx;
    newfile->refcount = 1;
    newfile->filename = strdup(filename);
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
    FILE *fd = fopen(file->filename, "r");
    if (!fd) {
        err(file->ctx, "open() failed: %s.\n", strerror(errno));
        return -1;
    }
    dbg(file->ctx, "file %p open returned: %p\n", file, fd);
    file->fd = fd;
    return 0;
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
    if (fclose(file->fd)) {
        err(file->ctx, "fclose() failed: %s.\n", strerror(errno));
        return -1;
    }
    dbg(file->ctx, "file %p closed\n", file);
    file->fd = NULL;
    return 0;
}

/**
 * zc_file_isopened:
 *
 * @retval Whether or not the file is opened.
 */
ZC_EXPORT bool zc_file_isopened(struct zc_file *file)
{
    return (file->fd != NULL);
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
ZC_EXPORT size_t zc_file_read_validation_data(struct zc_file *file, struct zc_validation_data *vdata, size_t nmemb)
{
    struct zip_header *zip_header;
    size_t valid_files = 0;

    rewind(file->fd);

    if (zip_header_new(&zip_header))
        return 0;

    while (zip_header_read(file->fd, zip_header) == 0 && valid_files < nmemb) {
        if (zip_header_has_encryption_bit(zip_header)) {
            vdata[valid_files].magic = zip_header_encryption_magic(zip_header);
            if (zip_encryption_header_read(file->fd, vdata[valid_files].encryption_header)) {
                zip_header_free(zip_header);
                return 0;
            }
            ++valid_files;
        }

        if (zip_skip_to_next_header(file->fd, zip_header)) {
            zip_header_free(zip_header);
            return 0;
        }
    }

    zip_header_free(zip_header);
    return valid_files;
}

/**
 * zc_file_test_password:
 *
 * Test the given password using the unzip command line tool. This
 * should be used exclusively for discarding false positives returned
 * by the cracker.
 *
 * @retval true The file was successfully decrypted (password found).
 * @retval false The file can't be decrypted (false positive).
 */
ZC_EXPORT bool zc_file_test_password(const char *filename, const char *pw)
{
    char cmd[128];
    sprintf(cmd, "unzip -qqtP \"%s\" \"%s\" >/dev/null 2>&1", pw, filename);
    return (system(cmd) == EXIT_SUCCESS);
}

ZC_EXPORT int zc_info_new_from_file(struct zc_file *file, struct zc_info **info)
{
    struct zc_info *tmp;

    tmp = calloc(1, sizeof(struct zc_info));
    if (!tmp)
        return -ENOMEM;

    if (zip_header_new(&tmp->header)) {
        free(tmp);
        return -ENOMEM;
    }

    tmp->refcount = 1;
    tmp->file = zc_file_ref(file);
    tmp->idx = -1;
    tmp->enc_header_offset = -1;
    tmp->begin_offset = -1;
    tmp->end_offset = -1;

    *info = tmp;
    dbg(file->ctx, "info %p created for %s\n", info, file->filename);
    return 0;
}

ZC_EXPORT void zc_info_free(struct zc_info *info)
{
    zc_file_unref(info->file);
    zip_header_free(info->header);
    free(info);
}

ZC_EXPORT void zc_info_reset(struct zc_info *info)
{
    rewind(info->file->fd);
    info->idx = -1;
    info->enc_header_offset = -1;
    info->begin_offset = -1;
    info->end_offset = -1;
}

ZC_EXPORT const char *zc_info_get_filename(const struct zc_info *info)
{
    if (info->idx == -1)
        return NULL;
    return zip_header_filename(info->header);
}

ZC_EXPORT uint32_t zc_info_get_data_size(const struct zc_info *info)
{
    return zip_header_comp_size(info->header);
}

ZC_EXPORT long zc_info_get_data_offset_begin(const struct zc_info *info)
{
    return info->begin_offset;
}

ZC_EXPORT long zc_info_get_data_offset_end(const struct zc_info *info)
{
    return info->end_offset;
}

ZC_EXPORT long zc_info_get_enc_header_offset(const struct zc_info *info)
{
    return info->enc_header_offset;
}

ZC_EXPORT int zc_info_get_idx(const struct zc_info *info)
{
    return info->idx;
}

ZC_EXPORT struct zc_info *zc_info_next(struct zc_info *info)
{
    FILE *fd = info->file->fd;

    if (zip_header_read(fd, info->header))
        goto reset;             /* error or EOF */

    if (zip_header_has_encryption_bit(info->header)) {
        info->enc_header_offset = ftell(fd);
        if (zip_encryption_header_skip(fd)) {
            err(info->file->ctx, "Error skipping encryption header.\n");
            goto reset;
        }
    } else
        info->enc_header_offset = -1L;

    if (zip_header_comp_size(info->header)) {
        info->begin_offset = ftell(fd);
        info->end_offset = info->begin_offset + zip_header_comp_size(info->header) - 1;
        if (zip_skip_to_next_header(info->file->fd, info->header)) {
            err(info->file->ctx, "Error skipping to next header file.\n");
            goto reset;
        }
    } else {
        info->begin_offset = -1L;
        info->end_offset = -1L;
    }

    info->idx++;

    return info;

reset:
    zc_info_reset(info);
    return NULL;
}
