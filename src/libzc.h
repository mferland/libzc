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

#ifndef _LIBZC_H_
#define _LIBZC_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void zc_log_init(void);
int zc_get_log_priority(void);

struct zc_file;
void zc_file_destroy(struct zc_file *file);
int zc_file_new_from_filename(const char *filename, struct zc_file **file);
const char *zc_file_get_filename(const struct zc_file *file);
int zc_file_open(struct zc_file *file);
int zc_file_close(struct zc_file *file);
bool zc_file_isopened(const struct zc_file *file);

struct zc_info;
struct zc_info *zc_file_info_next(struct zc_file *, struct zc_info *info);
const char *zc_file_info_name(const struct zc_info *info);
uint64_t zc_file_info_size(const struct zc_info *info);
uint64_t zc_file_info_compressed_size(const struct zc_info *info);
off_t zc_file_info_offset_begin(const struct zc_info *info);
off_t zc_file_info_offset_end(const struct zc_info *info);
off_t zc_file_info_crypt_header_offset(const struct zc_info *info);
const uint8_t *zc_file_info_enc_header(const struct zc_info *info);
int zc_file_info_idx(const struct zc_info *info);

struct zc_mask {
	size_t minlen;		/* 0 --> use mask length */
	size_t maxlen;		/* 0 --> use mask length */
	const char *str;
};

struct zc_crk_dict;
void zc_crk_dict_destroy(struct zc_crk_dict *crk);
int zc_crk_dict_new(struct zc_crk_dict **crk);
int zc_crk_dict_init(struct zc_crk_dict *crk, const char *filename);
int zc_crk_dict_start(struct zc_crk_dict *crk, const char *dict, char *pw,
		      size_t len);

#define ZC_PW_MINLEN	  1
#define ZC_PW_MAXLEN	  16
#define ZC_CHARSET_MAXLEN 96
struct zc_crk_pwcfg {
	char set[ZC_CHARSET_MAXLEN + 1];
	size_t setlen;
	size_t maxlen;
	char initial[ZC_PW_MAXLEN + 1];
	struct zc_mask mask;
};
struct zc_crk_bforce;
void zc_crk_bforce_destroy(struct zc_crk_bforce *bforce);
int zc_crk_bforce_new(struct zc_crk_bforce **bforce);
int zc_crk_bforce_init(struct zc_crk_bforce *bforce, const char *fname,
		       const struct zc_crk_pwcfg *cfg);
const char *zc_crk_bforce_sanitized_charset(const struct zc_crk_bforce *bforce);
void zc_crk_bforce_force_threads(struct zc_crk_bforce *bforce, long w);
int zc_crk_bforce_start(struct zc_crk_bforce *bforce, char *out_pw,
			size_t out_pw_size);

struct zc_key {
	uint32_t key0;
	uint32_t key1;
	uint32_t key2;
};
struct zc_crk_ptext;
void zc_crk_ptext_destroy(struct zc_crk_ptext *ptext);
int zc_crk_ptext_new(struct zc_crk_ptext **ptext, long force_threads);
int zc_crk_ptext_set_text(struct zc_crk_ptext *ptext, const uint8_t *plaintext,
			  const uint8_t *ciphertext, size_t size);
int zc_crk_ptext_key2_reduction(struct zc_crk_ptext *ptext);
size_t zc_crk_ptext_key2_count(const struct zc_crk_ptext *ptext);
int zc_crk_ptext_attack(struct zc_crk_ptext *ptext, struct zc_key *out_key);
int zc_crk_ptext_find_internal_rep(const struct zc_key *start_key,
				   const uint8_t *ciphertext, size_t size,
				   struct zc_key *internal_rep);
int zc_crk_ptext_find_password(struct zc_crk_ptext *ptext,
			       const struct zc_key *internal_rep, char *out,
			       size_t len);

void zc_passw_to_internal_rep(const uint8_t *pw, size_t len, struct zc_key *out_key);

#endif /* _LIBZC_H_ */
