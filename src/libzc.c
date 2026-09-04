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

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libzc.h"
#include "libzc_private.h"

static int current_log_priority = LOG_ERR;
static bool log_initialized;

void zc_log(int priority __attribute__((__unused__)),
	    const char *file __attribute__((__unused__)),
	    int line __attribute__((__unused__)), const char *fn,
	    const char *format, ...)
{
	va_list args;

	va_start(args, format);
	fprintf(stderr, "yazc: %s: ", fn);
	vfprintf(stderr, format, args);
	va_end(args);
}

void zc_trace(const char *file, int line, const char *fn, const char *format,
	      ...)
{
	va_list args;

	va_start(args, format);
	fprintf(stderr, "trace: %s:%d:%s: ", file, line, fn);
	vfprintf(stderr, format, args);
	va_end(args);
}

static int log_priority(const char *priority)
{
	char *endptr;
	int prio;

	prio = strtol(priority, &endptr, 10);
	if (endptr[0] == '\0' || isspace(endptr[0]))
		return prio;
	if (strncmp(priority, "err", 3) == 0)
		return LOG_ERR;
	if (strncmp(priority, "info", 4) == 0)
		return LOG_INFO;
	if (strncmp(priority, "debug", 5) == 0)
		return LOG_DEBUG;
	return 0;
}

void zc_log_init(void)
{
	const char *env;

	if (log_initialized)
		return;
	log_initialized = true;

	env = getenv("ZC_LOG");
	if (env)
		current_log_priority = log_priority(env);

	dbg("log_priority=%d\n", current_log_priority);
}

int zc_get_log_priority(void)
{
	return current_log_priority;
}
