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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "libzc.h"
#include "libzc-private.h"

/**
 * SECTION:file
 * @short_description: libzc zip file
 *
 * The file structure contains information about the targeted zip
 * file.
 */

/**
 * zc_file:
 *
 * Opaque object representing the zip file.
 */
struct zc_file
{
   struct zc_ctx *ctx;
   int refcount;
   char *filename;
   FILE *fd;
};

ZC_EXPORT struct zc_file *zc_file_ref(struct zc_file *file)
{
   if (!file)
      return NULL;
   file->refcount++;
   return file;
}

ZC_EXPORT struct zc_file *zc_file_unref(struct zc_file *file)
{
   if (!file)
      return NULL;
   file->refcount--;
   if (file->refcount > 0)
      return file;
   dbg(file->ctx, "file %p released\n", file);
   free(file->filename);
   free(file);
   return NULL;
}

ZC_EXPORT int zc_file_new_from_filename(struct zc_ctx *ctx, const char *filename, struct zc_file **file)
{
   struct zc_file *newfile;

   newfile = calloc(1, sizeof(struct zc_file));
   if (!newfile)
      return -ENOMEM;

   newfile->ctx = ctx;
   newfile->refcount = 1;
   newfile->filename = strdup(filename);
   *file = newfile;
   dbg(ctx, "file %p created for %s", newfile, filename);
   return 0;
}

ZC_EXPORT const char *zc_file_get_filename(const struct zc_file *file)
{
   return file->filename;
}

ZC_EXPORT int zc_file_open(struct zc_file *file)
{
   FILE *fd = fopen(file->filename, "r");
   dbg(file->ctx, "file %p open returned: %p\n", file, fd);
   if (fd == NULL)
      return errno;
   file->fd = fd;
   return 0;
}
