/*
 *  zc - zip crack library
 *  Copyright (C) 2009  Marc Ferland
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

#ifndef _LIBZC_H_
#define _LIBZC_H_

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * zc_ctx:
 *
 * library user context - reads the config and system environment,
 * user variables, allows custom logging
 */
struct zc_ctx;
struct zc_ctx *zc_ref(struct zc_ctx *ctx);
struct zc_ctx *zc_unref(struct zc_ctx *ctx);
int zc_new(struct zc_ctx **inctx);
void zc_set_log_fn(struct zc_ctx *ctx,
                  void (*log_fn)(struct zc_ctx *ctx,
                                 int priority, const char *file, int line, const char *fn,
                                 const char *format, va_list args));
int zc_get_log_priority(struct zc_ctx *ctx);
void zc_set_log_priority(struct zc_ctx *ctx, int priority);

/**
 * zc_validation_data:
 *
 * Encrypted file header and magic number used for testing password
 * validity. The zip encryption header is always 12 bytes.
 */
struct zc_validation_data
{
   unsigned char encryption_header[12];
   unsigned char magic;
};

/**
 * zc_file:
 *
 * contains information about the zip file
 */
struct zc_file;
struct zc_file *zc_file_ref(struct zc_file *file);
struct zc_file *zc_file_unref(struct zc_file *file);
int zc_file_new_from_filename(struct zc_ctx *ctx, const char *filename, struct zc_file **file);
const char *zc_file_get_filename(const struct zc_file *file);
int zc_file_open(struct zc_file *file);
int zc_file_close(struct zc_file *file);
bool zc_file_isopened(struct zc_file *file);
size_t zc_file_read_validation_data(struct zc_file *file, struct zc_validation_data *vdata_array, size_t nmemb);
   // TODO: use the file->ctx to print info
#ifdef ENABLE_DEBUG
void zc_file_debug_print_headers(struct zc_ctx *ctx, struct zc_file *file);
#endif

/**
 * zc_pwgen:
 *
 * Generates passwords given different character sets.
 */
struct zc_pwgen;
struct zc_pwgen *zc_pwgen_ref(struct zc_pwgen *pwgen);
struct zc_pwgen *zc_pwgen_unref(struct zc_pwgen *pwgen);
int zc_pwgen_new(struct zc_ctx *ctx, struct zc_pwgen **gen);
int zc_pwgen_init(struct zc_pwgen *gen, const unsigned char *char_set, unsigned int max_pw_len);
int zc_pwgen_reset(struct zc_pwgen *gen, const unsigned char *pw);
void zc_pwgen_set_step(struct zc_pwgen *gen, unsigned int step);   
const char *zc_pwgen_generate(struct zc_pwgen *gen);
   
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
