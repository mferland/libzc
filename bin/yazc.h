/*
 *  yazc - Yet Another Zip Cracker
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

#ifndef _YAZC_H_
#define _YAZC_H_

#include <stdlib.h>
#include "libzc.h"

struct yazc_cmd {
    const char *name;
    int (*cmd)(int argc, char *argv[]);
    const char *help;
};

#define fatal(arg...)                                           \
   do {                                                         \
      yazc_log(__FILE__, __LINE__, __FUNCTION__, ## arg);       \
      exit(EXIT_FAILURE);                                       \
   } while (0)

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

void yazc_log(const char *file, int line, const char *fn, const char *format, ...)
__attribute__((format(printf, 4, 5)));
void yazc_err(const char *format, ...)
__attribute__((format(printf, 1, 2)));

extern const struct yazc_cmd yazc_cmd_compat_bruteforce;
extern const struct yazc_cmd yazc_cmd_compat_dictionary;
extern const struct yazc_cmd yazc_cmd_compat_plaintext;
extern const struct yazc_cmd yazc_cmd_info;

size_t fill_validation_data(struct zc_ctx *ctx, const char *filename,
                            struct zc_validation_data *vdata, size_t nmemb);

#endif /* _YAZC_H_ */
