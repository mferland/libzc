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

#ifndef VULKAN_H
#define VULKAN_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct zc_vulkan;

struct zc_vulkan_config {
	/* The backend evaluates an inclusive length range for one character set. */
	const char *charset;
	size_t min_length;
	size_t max_length;
	uint32_t device_index;
};

/* Print one compute-capable device per line as "index: device name". */
int zc_vulkan_list_devices(FILE *stream);

/* Lifecycle mirrors the other attack engines: allocate, initialize, run,
 * then destroy.  zc_vulkan_destroy() also accepts a partially initialized
 * context after zc_vulkan_init() fails. */
int zc_vulkan_new(struct zc_vulkan **out);
void zc_vulkan_destroy(struct zc_vulkan *ctx);
int zc_vulkan_init(struct zc_vulkan *ctx, const char *filename,
		   const struct zc_vulkan_config *config);

/* Return 0 when a password is found, 1 when exhausted, and -1 on error. */
int zc_vulkan_start(struct zc_vulkan *ctx, char *password,
		    size_t password_size);

const char *zc_vulkan_device_name(const struct zc_vulkan *ctx);
const char *zc_vulkan_charset(const struct zc_vulkan *ctx);

#endif /* VULKAN_H */
