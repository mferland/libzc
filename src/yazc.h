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

#include <sys/time.h>

#include "config.h"

#define LOG_ERR   0
#define LOG_INFO  1
#define LOG_DEBUG 2

struct yazc_cmd {
	const char *name;
	int (*cmd)(int argc, char *argv[]);
	const char *help;
};

#ifndef WIN32
void yazc_log(int prio, const char *format, ...)
	__attribute__((format(printf, 2, 3)));

static inline void __attribute__((always_inline, format(printf, 2, 3)))
yazc_log_null(__attribute__((__unused__)) int prio,
	      __attribute__((__unused__)) const char *format, ...)
{
}
#else
void yazc_log(int prio, const char *format, ...)
	__attribute__((format(gnu_printf, 2, 3)));

static inline void __attribute__((always_inline, format(gnu_printf, 2, 3)))
yazc_log_null(__attribute__((__unused__)) int prio,
	      __attribute__((__unused__)) const char *format, ...)
{
}
#endif

#define err(arg...)  yazc_log(LOG_ERR, ##arg)
#define info(arg...) yazc_log(LOG_INFO, ##arg)

#ifdef ENABLE_DEBUG
#define dbg(arg...) yazc_log(LOG_DEBUG, ## arg)
#else
#define dbg(arg...) yazc_log_null(LOG_DEBUG, ## arg)
#endif

int print_runtime_stats(const struct timeval *begin, const struct timeval *end);

extern const struct yazc_cmd yazc_cmd_bruteforce;
extern const struct yazc_cmd yazc_cmd_dictionary;
extern const struct yazc_cmd yazc_cmd_plaintext;
extern const struct yazc_cmd yazc_cmd_info;

#endif /* _YAZC_H_ */
