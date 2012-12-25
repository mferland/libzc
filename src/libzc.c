/*
 *  zc - zip crack library
 *  Copyright (C) 2009  Marc Ferland
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
struct zc_ctx
{
   int refcount;
   void (*log_fn)(struct zc_ctx *ctx,
                  int priority, const char *file, int line, const char *fn,
                  const char *format, va_list args);
   void *userdata;
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

static void log_stderr(struct zc_ctx *ctx,
                       int priority, const char *file, int line, const char *fn,
                       const char *format, va_list args)
{
   fprintf(stderr, "libzc: %s: ", fn);
   vfprintf(stderr, format, args);
}
