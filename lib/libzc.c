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

/**
 * SECTION:libzc
 * @short_description: libzc context
 *
 * The context contains the default values for the library user,
 * and is passed to all library operations.
 */

/**
 * zc_ctx:
 *
 * Opaque object representing the library context.
 */
struct zc_ctx {
	int refcount;
	void (*log_fn)(struct zc_ctx *ctx,
		       int priority, const char *file, int line, const char *fn,
		       const char *format, va_list args);
	int log_priority;
};

void zc_log(struct zc_ctx *ctx,
	    int priority, const char *file, int line, const char *fn,
	    const char *format, ...)
{
	va_list args;

	va_start(args, format);
	ctx->log_fn(ctx, priority, file, line, fn, format, args);
	va_end(args);
}

static void log_stderr(struct zc_ctx *ctx __attribute__((__unused__)),
		       int priority __attribute__((__unused__)),
		       const char *file __attribute__((__unused__)),
		       int line __attribute__((__unused__)),
		       const char *fn,
		       const char *format, va_list args)
{
	fprintf(stderr, "libzc: %s: ", fn);
	vfprintf(stderr, format, args);
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

/**
 * zc_new:
 * @inctx: zc library context
 *
 * Create a new library context.
 *
 * Returns: 0 on success, -1 on error.
 **/
ZC_EXPORT int zc_new(struct zc_ctx **inctx)
{
	const char *env;
	struct zc_ctx *ctx;

	ctx = calloc(1, sizeof(struct zc_ctx));
	if (!ctx)
		return -1;

	ctx->refcount = 1;
	ctx->log_fn = log_stderr;
	ctx->log_priority = LOG_ERR;

	/* environment overwrites config */
	env = getenv("ZC_LOG");
	if (env)
		zc_set_log_priority(ctx, log_priority(env));

	info(ctx, "ctx %p created\n", ctx);
	dbg(ctx, "log_priority=%d\n", ctx->log_priority);
	*inctx = ctx;

	return 0;
}

/**
 * zc_ref:
 * @ctx: zc library context
 *
 * Take a reference of the zc library context.
 *
 * Returns: the passed zc library context
 **/
ZC_EXPORT struct zc_ctx *zc_ref(struct zc_ctx *ctx)
{
	if (!ctx)
		return NULL;
	ctx->refcount++;
	return ctx;
}

/**
 * zc_unref:
 * @ctx: zc library context
 *
 * Drop a reference of the zc library context. If the refcount
 * reaches zero, the resources of the context will be released.
 *
 **/
ZC_EXPORT struct zc_ctx *zc_unref(struct zc_ctx *ctx)
{
	if (!ctx)
		return NULL;
	ctx->refcount--;
	if (ctx->refcount > 0)
		return ctx;
	info(ctx, "ctx %p released\n", ctx);
	free(ctx);
	return NULL;
}

/**
 * zc_set_log_fn:
 * @ctx: zc library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be
 * overridden by a custom function, to plug log messages
 * into the user's logging functionality.
 *
 **/
ZC_EXPORT void zc_set_log_fn(struct zc_ctx *ctx,
			     void (*log_fn)(struct zc_ctx *ctx,
					    int priority, const char *file,
					    int line, const char *fn,
					    const char *format, va_list args))
{
	ctx->log_fn = log_fn;
	info(ctx, "custom logging function %p registered\n", log_fn);
}

/**
 * zc_get_log_priority:
 * @ctx: zc library context
 *
 * Returns: the current logging priority
 **/
ZC_EXPORT int zc_get_log_priority(struct zc_ctx *ctx)
{
	return ctx->log_priority;
}

/**
 * zc_set_log_priority:
 * @ctx: zc library context
 * @priority: the new logging priority
 *
 * Set the current logging priority. The value controls which messages
 * are logged.
 **/
ZC_EXPORT void zc_set_log_priority(struct zc_ctx *ctx, int priority)
{
	ctx->log_priority = priority;
}
