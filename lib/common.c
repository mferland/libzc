/*
 *  zc - zip crack library
 *  Copyright (C) 2017  Marc Ferland
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

#include "libzc_private.h"

int fill_vdata(struct zc_ctx *ctx, const char *filename,
               struct zc_validation_data *vdata,
               size_t nmemb)
{
    struct zc_file *file;
    int err;

    err = zc_file_new_from_filename(ctx, filename, &file);
    if (err)
        return -1;

    err = zc_file_open(file);
    if (err) {
        zc_file_unref(file);
        return -1;
    }

    int size = zc_file_read_validation_data(file, vdata, nmemb);

    zc_file_close(file);
    zc_file_unref(file);

    return size;
}
