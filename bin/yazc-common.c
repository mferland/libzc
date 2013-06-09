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

#include <stdio.h>

#include "yazc.h"
#include "libzc.h"

size_t fill_validation_data(struct zc_ctx *ctx, const char *filename,
                            struct zc_validation_data *vdata, size_t nmemb)
{
   struct zc_file *file = NULL;
   int err;

   err = zc_file_new_from_filename(ctx, filename, &file);
   if (!file)
   {
      fputs("Error: zc_file_new_from_filename() failed!\n", stderr);
      return err;
   }

   err = zc_file_open(file);
   if (err)
   {
      fprintf(stderr, "Error: cannot open %s\n", filename);
      zc_file_unref(file);
      return err;
   }

   err = zc_file_read_validation_data(file, vdata, nmemb);
   if (err < 1)
      fputs("Error: file is not encrypted\n", stderr);
   
   zc_file_close(file);
   zc_file_unref(file);
   return err < 1 ? 0 : (size_t)err;
}
