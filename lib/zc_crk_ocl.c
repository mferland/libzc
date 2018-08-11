/*
 *  zc - zip crack library
 *  Copyright (C) 2012-2018 Marc Ferland
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

#ifdef HAVE_CL_CL_H
#include <CL/cl.h>
#elif defined(HAVE_OPENCL_CL_H)
#include <OpenCL/cl.h>
#else
#error no cl.h
#endif

#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include "libzc_private.h"
#include "libzc.h"

#define ARRAY_SIZE(array) (sizeof(array) / sizeof(array[0]))

struct platform {
	cl_platform_id id;
	cl_device_id *dev;
	cl_uint dev_count;
};

struct zc_crk_ocl {
	struct zc_ctx *ctx;
	int refcount;
	struct platform *platform;
	cl_uint platform_count;
	cl_context context;
};

inline static bool OCLERR(cl_int err)
{
	return err != CL_SUCCESS;
}

static int probe_platforms(struct zc_crk_ocl *crk)
{
	cl_int ret;
	cl_uint n;

	/* first call to get number of platforms */
	ret = clGetPlatformIDs(0, NULL, &n);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetPlatformIDs() failed\n");
		return -1;
	}

	if (!n) {
		err(crk->ctx, "No platforms found!\n");
		return -1;
	}

	cl_platform_id *id = calloc(n, sizeof(cl_platform_id));
	if (!id) {
		err(crk->ctx, "calloc() failed: %s\n", strerror(errno));
		return -1;
	}

	ret = clGetPlatformIDs(n, id, NULL);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetPlatformIDs() failed\n");
		goto err1;
	}

	struct platform *p = calloc(n, sizeof(struct platform));
	if (!p) {
		err(crk->ctx, "calloc() failed: %s\n", strerror(errno));
		goto err1;
	}

	for (cl_uint i = 0; i < n; ++i)
		p[i].id = id[i];

	crk->platform_count = n;
	crk->platform = p;

	info(crk->ctx, "%d platforms found.\n", n);

	return 0;
 err1:
	free(id);
	return -1;
}

static int probe_devices(struct zc_crk_ocl *crk, struct platform *p)
{
	cl_int ret;
	cl_uint dev_count;

	ret = clGetDeviceIDs(p->id, CL_DEVICE_TYPE_ALL, 0, NULL, &dev_count);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetDevicesIDs() failed\n");
		return -1;
	}

	cl_device_id *tmp = calloc(dev_count, sizeof(cl_device_id));
	if (!tmp) {
		err(crk->ctx, "calloc() failed: %s\n", strerror(errno));
		return -1;
	}

	ret = clGetDeviceIDs(p->id, CL_DEVICE_TYPE_ALL, dev_count, tmp, NULL);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetDevicesIDs() failed\n");
		free(tmp);
		return -1;
	}

	p->dev = tmp;
	p->dev_count = dev_count;

	info(crk->ctx, "%d devices found.\n", dev_count);

	return 0;
}

static void free_platform(struct zc_crk_ocl *crk)
{
	for (size_t i = 0; i < crk->platform_count; ++i) {
		free(crk->platform[i].dev);
	}
	free(crk->platform);
}

static int probe_all(struct zc_crk_ocl *crk)
{
	int err;

	/* probe devices */
	err = probe_platforms(crk);
	if (err)
		return -1;

	for (cl_uint i = 0; i < crk->platform_count; ++i) {
		if (probe_devices(crk, &crk->platform[i])) {
			free_platform(crk);
			return -1;
		}
	}

	return 0;
}

static int device_info_cl_str(struct zc_crk_ocl *crk, cl_device_id dev, char **buf,
			      cl_device_info name)
{
	size_t size;
	cl_int ret;

	ret = clGetDeviceInfo(dev, name, 0, NULL, &size);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetDeviceInfo() failed\n");
		return -1;
	}

	char *tmp = calloc(1, size);
	if (!tmp) {
		err(crk->ctx, "calloc() failed: %s\n", strerror(errno));
		return -1;
	}

	ret = clGetDeviceInfo(dev, name, size, tmp, NULL);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetDeviceInfo() failed\n");
		free(tmp);
		return -1;
	}

	*buf = tmp;

	return 0;
}

static int device_info_cl_uint(struct zc_crk_ocl *crk, cl_device_id dev, char **buf,
			       cl_device_info name)
{
	cl_uint value;
	int ret;

	ret = clGetDeviceInfo(dev, name, sizeof(value), &value, NULL);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetDeviceInfo() failed\n");
		return -1;
	}

	char *tmp = calloc(1, 256); /* 256 should be enough */
	if (!tmp) {
		err(crk->ctx, "calloc() failed: %s\n", strerror(errno));
		return -1;
	}

	ret = snprintf(tmp, 256, "%d", value);
	if (ret < 0) {
		err(crk->ctx, "vsnprintf() failed: %s\n", strerror(errno));
		free(tmp);
		return -1;
	} else if ((size_t)ret >= 256) {
		err(crk->ctx, "vsnprintf() failed: output truncated\n");
		free(tmp);
		return -1;
	}

	*buf = tmp;

	return 0;
}

static int print_device_info(struct zc_crk_ocl *crk, cl_device_id id)
{
	struct dev_info {
		cl_device_info name;
		char *prefix;
		int (*tostr)(struct zc_crk_ocl *crk, cl_device_id dev, char **buf,
			     cl_device_info name);
	} d[] = {
		{ .name = CL_DEVICE_NAME,
		  .prefix = "Device Name",
		  .tostr = device_info_cl_str },
		{ .name = CL_DEVICE_PROFILE,
		  .prefix = "Device Profile",
		  .tostr = device_info_cl_str },
		{ .name = CL_DEVICE_VENDOR,
		  .prefix = "Device Vendor",
		  .tostr = device_info_cl_str },
		{ .name = CL_DEVICE_VERSION,
		  .prefix = "Device Version",
		  .tostr = device_info_cl_str },
		{ .name = CL_DRIVER_VERSION,
		  .prefix = "Driver Version",
		  .tostr = device_info_cl_str },
		{ .name = CL_DEVICE_OPENCL_C_VERSION,
		  .prefix = "Device OpenCL C Version",
		  .tostr = device_info_cl_str },
		{ .name = CL_DEVICE_MAX_COMPUTE_UNITS,
		  .prefix = "Max Compute Units",
		  .tostr = device_info_cl_uint },
		{ .name = CL_DEVICE_EXTENSIONS,
		  .prefix = "Device Extensions",
		  .tostr = device_info_cl_str },
	};

	char *str;

	for (size_t i = 0; i < ARRAY_SIZE(d); ++i) {
		if (d[i].tostr(crk, id, &str, d[i].name))
			return -1;
		printf("\t%s: %s\n", d[i].prefix, str);
		free(str);
	}

	return 0;
}

static int platform_info_cl_str(struct zc_crk_ocl *crk, cl_platform_id id, char **buf,
				cl_platform_info name)
{
	size_t size;
	cl_int ret;

	ret = clGetPlatformInfo(id, name, 0, NULL, &size);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetPlatformInfo() failed\n");
		return -1;
	}

	char *tmp = calloc(1, size);
	if (!tmp) {
		err(crk->ctx, "calloc() failed: %s\n", strerror(errno));
		return -1;
	}

	ret = clGetPlatformInfo(id, name, size, tmp, NULL);
	if (OCLERR(ret)) {
		err(crk->ctx, "clGetPlatformInfo() failed\n");
		free(tmp);
		return -1;
	}

	*buf = tmp;

	return 0;
}

static int print_platform_info(struct zc_crk_ocl *crk, cl_platform_id id)
{
	struct plat_info {
		cl_platform_info name;
		char *prefix;
		int (*tostr)(struct zc_crk_ocl *crk, cl_platform_id dev, char **buf,
			     cl_platform_info name);
	} p[] = {
		{ .name = CL_PLATFORM_PROFILE,
		  .prefix = "Platform Profile",
		  .tostr = platform_info_cl_str },
		{ .name = CL_PLATFORM_VERSION,
		  .prefix = "Platform Version",
		  .tostr = platform_info_cl_str },
		{ .name = CL_PLATFORM_NAME,
		  .prefix = "Platform Name",
		  .tostr = platform_info_cl_str },
		{ .name = CL_PLATFORM_VENDOR,
		  .prefix = "Platform Vendor",
		  .tostr = platform_info_cl_str },
		{ .name = CL_PLATFORM_EXTENSIONS,
		  .prefix = "Platform Extensions",
		  .tostr = platform_info_cl_str },
	};

	char *str;

	for (size_t i = 0; i < ARRAY_SIZE(p); ++i) {
		if (p[i].tostr(crk, id, &str, p[i].name))
			return -1;
		printf("%s: %s\n", p[i].prefix, str);
		free(str);
	}

	return 0;
}

static cl_uint get_gpu_devices_count(struct zc_crk_ocl *crk)
{
	cl_int err;
	cl_device_type type;
	cl_uint count = 0;

	for (cl_uint i = 0; i < crk->platform_count; ++i) {
		for (cl_uint j = 0; j < crk->platform[i].dev_count; ++j) {
			err = clGetDeviceInfo(crk->platform[i].dev[j],
					      CL_DEVICE_TYPE,
					      sizeof(cl_device_type),
					      &type,
					      NULL);
			if (OCLERR(err)) {
				err(crk->ctx, "clGetDeviceInfo() failed\n");
				return 0;
			}

			if (type == CL_DEVICE_TYPE_GPU)
				count++;
		}
	}

	return count;
}

static cl_uint get_gpu_devices(struct zc_crk_ocl *crk, cl_device_id *id, cl_uint count)
{
	cl_int err;
	cl_device_type type;
	cl_uint actual = 0;

	for (cl_uint i = 0; i < crk->platform_count; ++i) {
		for (cl_uint j = 0; j < crk->platform[i].dev_count; ++j) {
			err = clGetDeviceInfo(crk->platform[i].dev[j],
					      CL_DEVICE_TYPE,
					      sizeof(cl_device_type),
					      &type,
					      NULL);
			if (OCLERR(err)) {
				err(crk->ctx, "clGetDeviceInfo() failed\n");
				return 0;
			}

			if (actual == count) {
				err(crk->ctx, "More gpu devices than expected?\n");
				return 0;
			}

			if (type == CL_DEVICE_TYPE_GPU)
				id[actual++] = crk->platform[i].dev[j];
		}
	}

	return actual;
}

ZC_EXPORT int zc_crk_opencl_new(struct zc_ctx *ctx, struct zc_crk_ocl **crk)
{
	struct zc_crk_ocl *tmp;

	tmp = calloc(1, sizeof(struct zc_crk_ocl));
	if (!tmp)
		return -1;

	tmp->ctx = ctx;
	tmp->refcount = 1;

	*crk = tmp;

	dbg(ctx, "opencl cracker %p created\n", tmp);
	return 0;
}

ZC_EXPORT struct zc_crk_ocl *zc_crk_opencl_ref(struct zc_crk_ocl *crk)
{
	if (!crk)
		return NULL;
	crk->refcount++;
	return crk;
}

ZC_EXPORT struct zc_crk_ocl *zc_crk_opencl_unref(struct zc_crk_ocl *crk)
{
	if (!crk)
		return NULL;
	crk->refcount--;
	if (crk->refcount > 0)
		return crk;
	free(crk);
	return NULL;
}

ZC_EXPORT int zc_crk_opencl_start(struct zc_crk_ocl *crk, char *pw, size_t len)
{
	int err;

	(void)pw;
	(void)len;

	err = probe_all(crk);
	if (err)
		return -1;

	for (cl_uint i = 0; i < crk->platform_count; ++i) {
		print_platform_info(crk, crk->platform[i].id);
		for (cl_uint j = 0; j < crk->platform[i].dev_count; ++j)
			print_device_info(crk, crk->platform[i].dev[j]);
	}

	/* get gpu devices */
	cl_uint gpu_count = get_gpu_devices_count(crk);
	printf("GPU Devices Count: %d\n", gpu_count);
	cl_device_id *dev = calloc(gpu_count, sizeof(cl_device_id));
	gpu_count = get_gpu_devices(crk, dev, gpu_count);
	printf("GPU Devices Count: %d\n", gpu_count);

	cl_context ctx = clCreateContext(0, gpu_count, dev, NULL, NULL, &err);

	return 0;
}
