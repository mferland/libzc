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

#include <stddef.h>

void zc_log_init(void);
int zc_get_log_priority(void);

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

#endif /* _LIBZC_H_ */
