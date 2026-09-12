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

#ifndef LOG_H
#define LOG_H

#include <stddef.h>

#include "config.h"

#ifndef WIN32
#include <syslog.h>
#endif

#ifdef WIN32
#define LOG_EMERG   0 /* system is unusable */
#define LOG_ALERT   1 /* action must be taken immediately */
#define LOG_CRIT    2 /* critical conditions */
#define LOG_ERR     3 /* error conditions */
#define LOG_WARNING 4 /* warning conditions */
#define LOG_NOTICE  5 /* normal but significant condition */
#define LOG_INFO    6 /* informational */
#define LOG_DEBUG   7 /* debug-level messages */
#endif

#ifdef __MINGW64__
#define __ZC_PRINTF_FORMAT __MINGW_PRINTF_FORMAT
#else
#define __ZC_PRINTF_FORMAT printf
#endif

static inline void __attribute__((always_inline, format(__ZC_PRINTF_FORMAT, 1, 2)))
zc_log_null(const char *format __attribute__((__unused__)), ...)
{
}

void zc_log_init(void);
int zc_get_log_priority(void);

void zc_log(int priority, const char *file, int line, const char *fn,
	    const char *format, ...)
__attribute__((format(__ZC_PRINTF_FORMAT, 5, 6)));

void zc_trace(const char *file, int line, const char *fn, const char *format,
	      ...) __attribute__((format(__ZC_PRINTF_FORMAT, 4, 5)));

void fatal(const char *format, ...)
__attribute__((format(__ZC_PRINTF_FORMAT, 1, 2), noreturn));

/*
 * User-facing command messages are deliberately not filtered by ZC_LOG.
 * Passing no source context keeps their established error:/info:/dbg: form,
 * while engine diagnostics below retain their function-name context.
 */
#define cli_err(arg...)  zc_log(LOG_ERR, NULL, 0, NULL, ##arg)
#define cli_info(arg...) zc_log(LOG_INFO, NULL, 0, NULL, ##arg)

#ifdef ENABLE_DEBUG
#define cli_dbg(arg...) zc_log(LOG_DEBUG, NULL, 0, NULL, ##arg)
#else
#define cli_dbg(arg...) zc_log_null(arg)
#endif

#define zc_log_cond(prio, arg...)                                           \
	do {                                                                \
		if (zc_get_log_priority() >= prio)                          \
			zc_log(prio, __FILE__, __LINE__, __FUNCTION__,      \
			       ##arg);                                      \
	} while (0)

#define zc_log_trace(arg...)                                     \
	do {                                                     \
		zc_trace(__FILE__, __LINE__, __FUNCTION__, arg); \
	} while (0)

#ifdef ENABLE_LOGGING
#  ifdef ENABLE_DEBUG
#    define dbg(arg...) zc_log_cond(LOG_DEBUG, ## arg)
#    define trace(arg...) zc_log_trace(arg)
#  else
#    define dbg(arg...) zc_log_null(arg)
#    define trace(arg...) zc_log_null(arg)
#  endif
#  define info(arg...) zc_log_cond(LOG_INFO, ## arg)
#  define err(arg...) zc_log_cond(LOG_ERR, ## arg)
#else
#  define dbg(arg...) zc_log_null(arg)
#  define info(arg...) zc_log_null(arg)
#  define err(arg...) zc_log_null(arg)
#  define trace(arg...) zc_log_null(arg)
#endif

#endif /* LOG_H */
