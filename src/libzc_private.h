/*
 *  zc - zip crack library
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

#ifndef _LIBZC_PRIVATE_H_
#define _LIBZC_PRIVATE_H_

#include <stdbool.h>
#include <syslog.h>

#include <libzc.h>

static inline void __attribute__((always_inline, format(printf, 2, 3)))
zc_log_null(struct zc_ctx *ctx, const char *format, ...) {}

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
            int priority, const char *file, int line, const char *fn,
            const char *format, ...)
   __attribute__((format(printf, 6, 7)));

#endif
