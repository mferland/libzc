/*
 *  yazc - Yet Another Zip Cracker
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

#ifndef _YAZC_H_
#define _YAZC_H_

#include <stddef.h>
#include <sys/time.h>

enum yazc_charset_flags {
	YAZC_CHARSET_LOWER = 1 << 0,
	YAZC_CHARSET_UPPER = 1 << 1,
	YAZC_CHARSET_NUMERIC = 1 << 2,
	YAZC_CHARSET_SPECIAL = 1 << 3,
};

struct yazc_cmd {
	const char *name;
	int (*cmd)(int argc, char *argv[]);
	const char *help;
};

int print_runtime_stats(const struct timeval *begin, const struct timeval *end);
char *yazc_make_charset(unsigned int flags, char *out, size_t outlen);

extern const struct yazc_cmd yazc_cmd_bruteforce;
extern const struct yazc_cmd yazc_cmd_dictionary;
extern const struct yazc_cmd yazc_cmd_plaintext;
extern const struct yazc_cmd yazc_cmd_vulkan;
extern const struct yazc_cmd yazc_cmd_info;

#endif /* _YAZC_H_ */
