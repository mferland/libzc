/*
 *  zc - zip crack library
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

#ifndef _LIBZC_PRIVATE_H_
#define _LIBZC_PRIVATE_H_

#include <stdbool.h>
#include <stdint.h>
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>

#include "config.h"
#include "crc32.h"
#include "libzc.h"

static inline void __attribute__((always_inline, format(printf, 2, 3)))
zc_log_null(struct zc_ctx *ctx __attribute__((__unused__)),
	    const char *format __attribute__((__unused__)),
	    ...) {}

#define zc_log_cond(ctx, prio, arg...)                                  \
   do {                                                                 \
      if (zc_get_log_priority(ctx) >= prio)                             \
         zc_log(ctx, prio, __FILE__, __LINE__, __FUNCTION__, ## arg);   \
   } while (0)

#ifdef ENABLE_LOGGING
#  ifdef ENABLE_DEBUG
#    define dbg(ctx, arg...) zc_log_cond(ctx, LOG_DEBUG, ## arg)
#  else
#    define dbg(ctx, arg...) zc_log_null(ctx, ## arg)
#  endif
#  define info(ctx, arg...) zc_log_cond(ctx, LOG_INFO, ## arg)
#  define err(ctx, arg...) zc_log_cond(ctx, LOG_ERR, ## arg)
#else
#  define dbg(ctx, arg...) zc_log_null(ctx, ## arg)
#  define info(ctx, arg...) zc_log_null(ctx, ## arg)
#  define err(ctx, arg...) zc_log_null(ctx, ## arg)
#endif

#define ZC_EXPORT __attribute__ ((visibility("default")))

void zc_log(struct zc_ctx *ctx,
	    int priority,
	    const char *file,
	    int line,
	    const char *fn,
	    const char *format,
	    ...) __attribute__((format(printf, 6, 7)));

static inline void fatal(const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);

	exit(EXIT_FAILURE);
}

#define MULT 134775813u
#define MULTINV 3645876429u  /* modular multiplicative inverse mod2^32 */
#define KEY0 0x12345678
#define KEY1 0x23456789
#define KEY2 0x34567890
#define ENC_HEADER_LEN 12
#define HEADER_MAX 5
#define INFLATE_CHUNK 16384

struct zc_header {
	uint8_t buf[12];
	uint8_t magic;
};

static inline
uint32_t pow2(uint32_t p)
{
	return (1 << p);
}

static inline
uint32_t mask_msb(uint32_t v)
{
	return (v & 0xff000000);
}

static inline
uint32_t mask_lsb(uint32_t v)
{
	return (v & 0x000000ff);
}

static inline
uint8_t msb(uint32_t v)
{
	return (v >> 24);
}

static inline
uint8_t lsb(uint32_t v)
{
	return (v & 0xff);
}

static inline
void update_keys(uint8_t c, struct zc_key *ksrc, struct zc_key *kdst)
{
	kdst->key0 = crc32(ksrc->key0, c);
	kdst->key1 = (ksrc->key1 + (kdst->key0 & 0xff)) * MULT + 1;
	kdst->key2 = crc32(ksrc->key2, kdst->key1 >> 24);
}

static inline
void set_default_encryption_keys(struct zc_key *k)
{
	k->key0 = KEY0;
	k->key1 = KEY1;
	k->key2 = KEY2;
}

static inline
void update_default_keys_from_array(struct zc_key *out,
				    const uint8_t *s,
				    size_t len)
{
	set_default_encryption_keys(out);

	for (size_t i = 0; i < len; ++i)
		update_keys(s[i], out, out);
}

static inline
void reset_encryption_keys(const struct zc_key *base, struct zc_key *k)
{
	*k = *base;
}

static inline
uint8_t decrypt_byte(uint32_t k)
{
	k |= 2;
	return ((k * (k ^ 1)) >> 8) & 0xff;
}

uint8_t decrypt_header(const uint8_t *buf,
		       struct zc_key *k,
		       uint8_t magic);

bool decrypt_headers(const struct zc_key *k,
		     const struct zc_header *h,
		     size_t len);

size_t threads_to_create(long forced);

int fill_header(struct zc_ctx *ctx,
		const char *filename,
		struct zc_header *h,
		size_t len);

int fill_test_cipher(struct zc_ctx *ctx,
		     const char *filename,
		     unsigned char **buf,
		     size_t *len,
		     uint32_t *original_crc,
		     bool *is_deflated);

size_t read_zc_header(struct zc_file *file,
		      struct zc_header *h,
		      size_t len);

int read_crypt_data(struct zc_file *file,
		    unsigned char **buf,
		    size_t *len,
		    uint32_t *original_crc,
		    bool *is_deflated);

void decrypt(const unsigned char *in,
	     unsigned char *out,
	     size_t len,
	     const struct zc_key *key);

/* zlib stuff */
struct zlib_state;

int inflate_new(struct zlib_state **zlib);

void inflate_destroy(struct zlib_state *zlib);

int inflate_buffer(struct zlib_state *zlib,
		   const unsigned char *in,
		   size_t inlen,
		   unsigned char *out,
		   size_t outlen,
		   uint32_t original_crc);

int test_buffer_crc(unsigned char *in,
		    size_t inlen,
		    uint32_t original_crc);

#endif	/* _LIBZC_PRIVATE_H_ */
