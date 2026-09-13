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

#ifndef BRUTEFORCE_H
#define BRUTEFORCE_H

#include <stddef.h>

#define ZC_PW_MINLEN	  1
#define ZC_PW_MAXLEN	  16
#define ZC_CHARSET_MAXLEN 96

struct zc_mask {
	size_t minlen;		/* 0 --> use mask length */
	size_t maxlen;		/* 0 --> use mask length */
	const char *str;
};

struct zc_bruteforce_config {
	char set[ZC_CHARSET_MAXLEN + 1];
	size_t setlen;
	size_t maxlen;
	char initial[ZC_PW_MAXLEN + 1];
	struct zc_mask mask;
};

struct zc_bruteforce;

void zc_bruteforce_destroy(struct zc_bruteforce *ctx);
int zc_bruteforce_new(struct zc_bruteforce **ctx);
int zc_bruteforce_init(struct zc_bruteforce *ctx, const char *fname,
		       const struct zc_bruteforce_config *cfg);
const char *zc_bruteforce_sanitized_charset(const struct zc_bruteforce *ctx);
void zc_bruteforce_force_threads(struct zc_bruteforce *ctx, long w);
int zc_bruteforce_start(struct zc_bruteforce *ctx, char *out_pw,
			size_t out_pw_size);

#endif /* BRUTEFORCE_H */
