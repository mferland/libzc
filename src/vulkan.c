/*
 *  yazc - ZIP password recovery application
 *  Copyright (C) 2012-2026 Marc Ferland
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#include <inttypes.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "inflate.h"
#include "log.h"
#include "vulkan.h"
#include "vulkan_search.h"
#include "zc.h"
#include "zip.h"

#ifdef HAVE_VULKAN

#include <vulkan/vulkan.h>

/*
 * Keep each dispatch large enough to amortize command submission, fence waits,
 * and result readback while still bounding the time spent in one command
 * buffer.  Searches larger than this continue in later dispatches.
 */
#define WORKGROUP_SIZE 64u
#define CHUNK_LIMIT (1u << 26)
#define AMD_VENDOR_ID 0x1002u
#define DEVICE_EXTENSION_CAPACITY 2u

/* Zero leaves subgroup selection to the driver.  Thirty-two requests wave32
 * where VK_EXT_subgroup_size_control (or its Vulkan 1.3 core form) permits it. */
#ifndef ZC_VULKAN_SUBGROUP_SIZE
#define ZC_VULKAN_SUBGROUP_SIZE 32u
#endif

/*
 * A wrong password passes one encrypted-header check with probability 1/256.
 * Multiple ZIP entries make an overflow very unlikely, but it is still
 * handled correctly by splitting and retrying the range in search_range().
 */
#define RESULT_CAPACITY 8192u

/*
 * Input storage-buffer layout, expressed in 32-bit words:
 *
 *   0 .. 4                         dispatch metadata
 *   5 .. 5 + ZC_PW_MAXLEN - 1     first candidate as radix digits
 *   ...                            character set (one byte per uint32_t)
 *   ...                            256-entry ZipCrypto CRC table
 *   ...                            encrypted headers and validation bytes
 *
 * The GLSL shader has the same constants.  Keeping every field uint32_t means
 * the shader works with core Vulkan 1.0 and requires neither 8-bit storage nor
 * 64-bit integer support.
 */
#define INPUT_CANDIDATE_COUNT 0u
#define INPUT_LENGTH 1u
#define INPUT_CHARSET_LENGTH 2u
#define INPUT_HEADER_COUNT 3u
#define INPUT_RESULT_CAPACITY 4u
#define INPUT_BASE_DIGITS 5u
#define INPUT_CHARSET (INPUT_BASE_DIGITS + ZC_PW_MAXLEN)
#define INPUT_CRC_TABLE (INPUT_CHARSET + ZC_CHARSET_MAXLEN)
#define INPUT_HEADERS (INPUT_CRC_TABLE + 256u)
#define HEADER_WORDS (ENC_HEADER_LEN + 1u)
#define INPUT_WORDS (INPUT_HEADERS + HEADER_MAX * HEADER_WORDS)

/* results[0] is an atomic survivor count; the remaining words are offsets. */
#define RESULT_WORDS (RESULT_CAPACITY + 1u)

_Static_assert(INPUT_WORDS <= RESULT_WORDS,
	       "the staging buffer must fit serialized dispatch input");

/* Specialization-constant IDs declared in vulkan-bruteforce.comp. */
#define SPEC_LENGTH_ID 0u
#define SPEC_RADIX_ID 1u
#define SPEC_HEADER_COUNT_ID 2u

static const uint32_t vulkan_shader[] =
#include "vulkan_shader.inc"
	;

struct zc_vk_buffer {
	VkBuffer buffer;
	VkDeviceMemory memory;
	VkMemoryPropertyFlags properties;
};

struct zc_vulkan {
	/* Search-space state shared with the host-side helper functions. */
	struct zc_vulkan_search search;
	char charset[ZC_CHARSET_MAXLEN + 1];
	uint32_t min_length;
	uint32_t max_length;

	/* ZIP material retained for GPU filtering and final CPU validation. */
	struct zc_header headers[HEADER_MAX];
	size_t header_count;
	unsigned char *cipher;
	unsigned char *plaintext;
	unsigned char *inflate;
	size_t cipher_size;
	uint32_t original_crc;
	bool cipher_is_deflated;
	struct zlib_state *zlib;

	/* User-selected physical device. */
	uint32_t device_index;
	char device_name[VK_MAX_PHYSICAL_DEVICE_NAME_SIZE];

	/* Vulkan objects, listed roughly in creation order. */
	VkInstance instance;
	uint32_t instance_api_version;
	VkPhysicalDevice physical_device;
	VkDevice device;
	VkQueue queue;
	uint32_t queue_family;
	uint32_t timestamp_valid_bits;
	uint32_t required_subgroup_size;
	float timestamp_period;
	VkCommandPool command_pool;
	VkCommandBuffer command_buffer;
	VkFence fence;
	VkQueryPool timestamp_pool;
	VkDescriptorSetLayout descriptor_layout;
	VkDescriptorPool descriptor_pool;
	VkDescriptorSet descriptor_set;
	VkPipelineLayout pipeline_layout;
	VkShaderModule shader_module;
	VkPipeline generic_pipeline;
	VkPipeline specialized_pipelines[ZC_PW_MAXLEN + 1];
	VkPipeline active_pipeline;
	bool pipeline_executable_info;
#ifdef VK_KHR_pipeline_executable_properties
	PFN_vkGetPipelineExecutablePropertiesKHR get_executable_properties;
	PFN_vkGetPipelineExecutableStatisticsKHR get_executable_statistics;
#endif

	/*
	 * input and result stay in device-local memory.  staging is the one
	 * host-visible buffer used for uploads and downloads.
	 */
	struct zc_vk_buffer input;
	struct zc_vk_buffer result;
	struct zc_vk_buffer staging;

	/* Device-limit-clamped number of candidates in one dispatch. */
	uint32_t max_chunk;
	uint64_t dispatch_count;
	uint64_t passwords_tested;
	double gpu_compute_nanoseconds;
};

/*
 * Optional device features must remain alive until vkCreateDevice() returns.
 * Keeping their storage and pNext chain in one object makes that lifetime
 * explicit and keeps feature negotiation out of the core initialization path.
 */
struct zc_vk_device_config {
	const char *extensions[DEVICE_EXTENSION_CAPACITY];
	uint32_t extension_count;
	void *feature_chain;

#ifdef VK_EXT_subgroup_size_control
	VkPhysicalDeviceSubgroupSizeControlFeaturesEXT subgroup_size;
#endif
#ifdef VK_KHR_pipeline_executable_properties
	VkPhysicalDevicePipelineExecutablePropertiesFeaturesKHR pipeline_info;
#endif
};

/* -------------------------------------------------------------------------
 * Vulkan instance and device discovery
 * ------------------------------------------------------------------------- */

static const char *vk_result_name(VkResult result)
{
	switch (result) {
	case VK_SUCCESS:
		return "success";
	case VK_ERROR_OUT_OF_HOST_MEMORY:
		return "out of host memory";
	case VK_ERROR_OUT_OF_DEVICE_MEMORY:
		return "out of device memory";
	case VK_ERROR_INITIALIZATION_FAILED:
		return "initialization failed";
	case VK_ERROR_DEVICE_LOST:
		return "device lost";
	case VK_ERROR_MEMORY_MAP_FAILED:
		return "memory map failed";
	case VK_ERROR_FEATURE_NOT_PRESENT:
		return "feature not present";
	case VK_ERROR_INCOMPATIBLE_DRIVER:
		return "incompatible driver";
	default:
		return "unknown Vulkan error";
	}
}

static uint32_t supported_instance_version(void)
{
#ifdef VK_API_VERSION_1_1
	PFN_vkEnumerateInstanceVersion enumerate_version;
	uint32_t supported = VK_API_VERSION_1_0;
	uint32_t requested;

	enumerate_version = (PFN_vkEnumerateInstanceVersion)
			    vkGetInstanceProcAddr(VK_NULL_HANDLE, "vkEnumerateInstanceVersion");
	if (enumerate_version && enumerate_version(&supported) != VK_SUCCESS)
		supported = VK_API_VERSION_1_0;

#ifdef VK_API_VERSION_1_4
	requested = VK_API_VERSION_1_4;
#elif defined(VK_API_VERSION_1_3)
	requested = VK_API_VERSION_1_3;
#elif defined(VK_API_VERSION_1_2)
	requested = VK_API_VERSION_1_2;
#elif defined(VK_API_VERSION_1_1)
	requested = VK_API_VERSION_1_1;
#else
	requested = VK_API_VERSION_1_0;
#endif

	return supported < requested ? supported : requested;
#else
	return VK_API_VERSION_1_0;
#endif
}

static VkResult create_instance(VkInstance *instance, uint32_t *api_version)
{
	uint32_t version = supported_instance_version();
	VkApplicationInfo app = {
		.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO,
		.pApplicationName = "yazc",
		.pEngineName = "yazc",
		.apiVersion = version,
	};
	VkInstanceCreateInfo create = {
		.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
		.pApplicationInfo = &app,
	};

	VkResult result = vkCreateInstance(&create, NULL, instance);

	if (result == VK_SUCCESS) {
		if (api_version)
			*api_version = version;
		dbg("created Vulkan %u.%u instance\n", version >> 22,
		    (version >> 12) & 0x3ff);
	}
	return result;
}

static bool find_compute_queue(VkPhysicalDevice device, uint32_t *index,
			       uint32_t *timestamp_valid_bits)
{
	VkQueueFamilyProperties *properties;
	uint32_t count = 0;
	bool found = false;

	vkGetPhysicalDeviceQueueFamilyProperties(device, &count, NULL);
	dbg("physical device exposes %u queue families\n", count);
	if (!count)
		return false;

	properties = calloc(count, sizeof(*properties));
	if (!properties)
		return false;

	vkGetPhysicalDeviceQueueFamilyProperties(device, &count, properties);
	for (uint32_t i = 0; i < count; ++i) {
		if (properties[i].queueCount &&
		    (properties[i].queueFlags & VK_QUEUE_COMPUTE_BIT)) {
			*index = i;
			if (timestamp_valid_bits)
				*timestamp_valid_bits =
					properties[i].timestampValidBits;
			found = true;
			dbg("using compute queue family %u: queues=%u flags=0x%x "
			    "timestamp-bits=%u\n",
			    i, properties[i].queueCount,
			    properties[i].queueFlags,
			    properties[i].timestampValidBits);
			break;
		}
	}

	free(properties);
	return found;
}

/*
 * stream != NULL selects listing mode.  Otherwise wanted is an index in the
 * filtered list of compute-capable devices, not necessarily the Vulkan
 * physical-device array.  This keeps --list-devices and --device consistent.
 */
static int enumerate_devices(FILE *stream, uint32_t wanted,
			     VkInstance instance, VkPhysicalDevice *selected,
			     uint32_t *selected_queue,
			     uint32_t *selected_timestamp_bits,
			     char *selected_name)
{
	VkPhysicalDevice *devices = NULL;
	VkResult result;
	uint32_t count = 0;
	uint32_t suitable = 0;
	int ret = -1;

	result = vkEnumeratePhysicalDevices(instance, &count, NULL);
	if (result != VK_SUCCESS) {
		err("vkEnumeratePhysicalDevices failed: %s (%d)\n",
		    vk_result_name(result), result);
		return -1;
	}
	dbg("Vulkan reported %u physical devices\n", count);

	if (count) {
		devices = calloc(count, sizeof(*devices));
		if (!devices)
			return -1;

		result = vkEnumeratePhysicalDevices(instance, &count, devices);
		if (result != VK_SUCCESS)
			goto out;
	}

	for (uint32_t i = 0; i < count; ++i) {
		VkPhysicalDeviceProperties properties;
		uint32_t queue;
		uint32_t timestamp_bits;

		if (!find_compute_queue(devices[i], &queue, &timestamp_bits)) {
			dbg("skipping physical device %u: no compute queue\n", i);
			continue;
		}

		vkGetPhysicalDeviceProperties(devices[i], &properties);
		dbg("compute device %u maps to physical device %u: %s, queue %u\n",
		    suitable, i, properties.deviceName, queue);
		if (stream)
			fprintf(stream, "%u: %s\n", suitable,
				properties.deviceName);

		if (selected && suitable == wanted) {
			*selected = devices[i];
			*selected_queue = queue;
			if (selected_timestamp_bits)
				*selected_timestamp_bits = timestamp_bits;
			snprintf(selected_name, VK_MAX_PHYSICAL_DEVICE_NAME_SIZE,
				 "%s", properties.deviceName);
			ret = 0;
			dbg("selected Vulkan compute device %u\n", suitable);
		}
		++suitable;
	}

	if (stream)
		ret = suitable ? 0 : 1;

out:
	free(devices);
	return ret;
}

#if defined(VK_EXT_subgroup_size_control) || \
	defined(VK_KHR_pipeline_executable_properties)
static bool device_extension_supported(VkPhysicalDevice device,
				       const char *wanted)
{
	VkExtensionProperties *extensions = NULL;
	VkResult result;
	uint32_t count = 0;
	bool found = false;

	result = vkEnumerateDeviceExtensionProperties(device, NULL, &count, NULL);
	if (result != VK_SUCCESS || !count)
		return false;

	extensions = calloc(count, sizeof(*extensions));
	if (!extensions)
		return false;
	result = vkEnumerateDeviceExtensionProperties(device, NULL, &count,
						      extensions);
	if (result != VK_SUCCESS)
		goto out;

	for (uint32_t i = 0; i < count; ++i) {
		if (!strcmp(extensions[i].extensionName, wanted)) {
			found = true;
			break;
		}
	}
out:
	free(extensions);
	return found;
}
#endif

#ifdef VK_KHR_pipeline_executable_properties
static bool pipeline_statistics_requested(void)
{
#ifdef ENABLE_DEBUG
	return zc_get_log_priority() >= LOG_DEBUG;
#else
	return false;
#endif
}
#endif

int zc_vulkan_list_devices(FILE *stream)
{
	VkInstance instance = VK_NULL_HANDLE;
	VkResult result;
	int ret;

	dbg("enumerating Vulkan compute devices\n");
	result = create_instance(&instance, NULL);
	if (result != VK_SUCCESS) {
		err("vkCreateInstance failed: %s (%d)\n",
		    vk_result_name(result), result);
		return -1;
	}

	ret = enumerate_devices(stream, 0, instance, NULL, NULL, NULL, NULL);
	dbg("Vulkan device enumeration result=%d\n", ret);
	vkDestroyInstance(instance, NULL);
	return ret;
}

/* -------------------------------------------------------------------------
 * Buffer allocation and host-memory visibility
 * ------------------------------------------------------------------------- */

static bool find_memory_type(struct zc_vulkan *ctx, uint32_t bits,
			     VkMemoryPropertyFlags required, uint32_t *index,
			     VkMemoryPropertyFlags *properties)
{
	VkPhysicalDeviceMemoryProperties memory;

	vkGetPhysicalDeviceMemoryProperties(ctx->physical_device, &memory);
	for (uint32_t i = 0; i < memory.memoryTypeCount; ++i) {
		VkMemoryPropertyFlags flags = memory.memoryTypes[i].propertyFlags;

		if ((bits & (1u << i)) && (flags & required) == required) {
			*index = i;
			*properties = flags;
			return true;
		}
	}

	return false;
}

static VkResult create_buffer(struct zc_vulkan *ctx, VkDeviceSize size,
			      VkBufferUsageFlags usage,
			      VkMemoryPropertyFlags properties,
			      struct zc_vk_buffer *buffer)
{
	VkBufferCreateInfo create = {
		.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
		.size = size,
		.usage = usage,
		.sharingMode = VK_SHARING_MODE_EXCLUSIVE,
	};
	VkMemoryAllocateInfo allocate = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
	};
	VkMemoryRequirements requirements;
	VkResult result;
	uint32_t type;

	dbg("creating Vulkan buffer: requested=%" PRIu64
	    " bytes usage=0x%x memory=0x%x\n",
	    (uint64_t)size, usage, properties);
	result = vkCreateBuffer(ctx->device, &create, NULL, &buffer->buffer);
	if (result != VK_SUCCESS)
		return result;

	/* Buffer requirements constrain which physical-memory types are legal. */
	vkGetBufferMemoryRequirements(ctx->device, buffer->buffer,
				      &requirements);
	if (!find_memory_type(ctx, requirements.memoryTypeBits, properties,
			      &type, &buffer->properties)) {
		result = VK_ERROR_FEATURE_NOT_PRESENT;
		goto fail_buffer;
	}
	allocate.allocationSize = requirements.size;
	allocate.memoryTypeIndex = type;
	dbg("allocating Vulkan buffer memory: size=%" PRIu64
	    " bytes type=%u properties=0x%x alignment=%" PRIu64 "\n",
	    (uint64_t)requirements.size, type, buffer->properties,
	    (uint64_t)requirements.alignment);
	result = vkAllocateMemory(ctx->device, &allocate, NULL, &buffer->memory);
	if (result != VK_SUCCESS)
		goto fail_buffer;

	result = vkBindBufferMemory(ctx->device, buffer->buffer, buffer->memory, 0);
	if (result == VK_SUCCESS)
		return result;

	vkFreeMemory(ctx->device, buffer->memory, NULL);
	buffer->memory = VK_NULL_HANDLE;

fail_buffer:
	vkDestroyBuffer(ctx->device, buffer->buffer, NULL);
	buffer->buffer = VK_NULL_HANDLE;
	return result;
}

static void destroy_buffer(struct zc_vulkan *ctx, struct zc_vk_buffer *buffer)
{
	if (buffer->buffer)
		vkDestroyBuffer(ctx->device, buffer->buffer, NULL);
	if (buffer->memory)
		vkFreeMemory(ctx->device, buffer->memory, NULL);

	memset(buffer, 0, sizeof(*buffer));
}

static VkResult flush_memory(struct zc_vulkan *ctx,
			     const struct zc_vk_buffer *buffer)
{
	VkMappedMemoryRange range = {
		.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE,
		.memory = buffer->memory,
		.offset = 0,
		.size = VK_WHOLE_SIZE,
	};

	if (buffer->properties & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)
		return VK_SUCCESS;

	return vkFlushMappedMemoryRanges(ctx->device, 1, &range);
}

static VkResult invalidate_memory(struct zc_vulkan *ctx,
				  const struct zc_vk_buffer *buffer)
{
	VkMappedMemoryRange range = {
		.sType = VK_STRUCTURE_TYPE_MAPPED_MEMORY_RANGE,
		.memory = buffer->memory,
		.offset = 0,
		.size = VK_WHOLE_SIZE,
	};

	if (buffer->properties & VK_MEMORY_PROPERTY_HOST_COHERENT_BIT)
		return VK_SUCCESS;

	return vkInvalidateMappedMemoryRanges(ctx->device, 1, &range);
}

/* -------------------------------------------------------------------------
 * Descriptor and compute-pipeline construction
 * ------------------------------------------------------------------------- */

static VkResult create_compute_pipeline(
	struct zc_vulkan *ctx, const VkSpecializationInfo *specialization,
	VkPipeline *out)
{
#ifdef VK_EXT_subgroup_size_control
	VkPipelineShaderStageRequiredSubgroupSizeCreateInfoEXT subgroup_size = {
		.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_REQUIRED_SUBGROUP_SIZE_CREATE_INFO_EXT,
		.requiredSubgroupSize = ctx->required_subgroup_size,
	};
#endif
	VkPipelineShaderStageCreateInfo stage = {
		.sType = VK_STRUCTURE_TYPE_PIPELINE_SHADER_STAGE_CREATE_INFO,
		.stage = VK_SHADER_STAGE_COMPUTE_BIT,
		.module = ctx->shader_module,
		.pName = "main",
		.pSpecializationInfo = specialization,
	};

#ifdef VK_EXT_subgroup_size_control
	if (ctx->required_subgroup_size)
		stage.pNext = &subgroup_size;
#endif
	VkComputePipelineCreateInfo pipeline = {
		.sType = VK_STRUCTURE_TYPE_COMPUTE_PIPELINE_CREATE_INFO,
		.stage = stage,
		.layout = ctx->pipeline_layout,
	};

#ifdef VK_KHR_pipeline_executable_properties
	if (ctx->pipeline_executable_info)
		pipeline.flags |= VK_PIPELINE_CREATE_CAPTURE_STATISTICS_BIT_KHR;
#endif
	return vkCreateComputePipelines(ctx->device, VK_NULL_HANDLE, 1,
					&pipeline, NULL, out);
}

static VkResult create_descriptor_layout(struct zc_vulkan *ctx)
{
	VkDescriptorSetLayoutBinding bindings[2] = {
		{
			.binding = 0,
			.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
			.descriptorCount = 1,
			.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT,
		},
		{
			.binding = 1,
			.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
			.descriptorCount = 1,
			.stageFlags = VK_SHADER_STAGE_COMPUTE_BIT,
		},
	};
	VkDescriptorSetLayoutCreateInfo descriptor_layout = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_LAYOUT_CREATE_INFO,
		.bindingCount = 2,
		.pBindings = bindings,
	};

	/* Binding 0 is immutable dispatch input; binding 1 receives survivors. */
	return vkCreateDescriptorSetLayout(ctx->device, &descriptor_layout,
					   NULL, &ctx->descriptor_layout);
}

static VkResult create_pipeline_layout(struct zc_vulkan *ctx)
{
	VkPipelineLayoutCreateInfo pipeline_layout = {
		.sType = VK_STRUCTURE_TYPE_PIPELINE_LAYOUT_CREATE_INFO,
		.setLayoutCount = 1,
		.pSetLayouts = &ctx->descriptor_layout,
	};

	return vkCreatePipelineLayout(ctx->device, &pipeline_layout, NULL,
				      &ctx->pipeline_layout);
}

static VkResult create_shader_module(struct zc_vulkan *ctx)
{
	VkShaderModuleCreateInfo shader = {
		.sType = VK_STRUCTURE_TYPE_SHADER_MODULE_CREATE_INFO,
		.codeSize = sizeof(vulkan_shader),
		.pCode = vulkan_shader,
	};

	/* SPIR-V is embedded so installed builds do not need a shader compiler. */
	return vkCreateShaderModule(ctx->device, &shader, NULL,
				    &ctx->shader_module);
}

static VkResult create_pipeline_resources(struct zc_vulkan *ctx)
{
	VkResult result;

	dbg("creating generic Vulkan compute pipeline from %zu-byte embedded shader\n",
	    sizeof(vulkan_shader));

	result = create_descriptor_layout(ctx);
	if (result != VK_SUCCESS)
		return result;

	result = create_pipeline_layout(ctx);
	if (result != VK_SUCCESS)
		return result;

	result = create_shader_module(ctx);
	if (result != VK_SUCCESS)
		return result;

	/* No specialization data selects the shader's metadata-driven fallback. */
	result = create_compute_pipeline(ctx, NULL, &ctx->generic_pipeline);
	if (result == VK_SUCCESS)
		ctx->active_pipeline = ctx->generic_pipeline;
	return result;
}

#ifdef VK_KHR_pipeline_executable_properties
static void log_pipeline_statistic(
	const VkPipelineExecutableStatisticKHR *statistic)
{
	switch (statistic->format) {
	case VK_PIPELINE_EXECUTABLE_STATISTIC_FORMAT_BOOL32_KHR:
		dbg("Vulkan pipeline statistic %s=%s\n", statistic->name,
		    statistic->value.b32 ? "true" : "false");
		break;
	case VK_PIPELINE_EXECUTABLE_STATISTIC_FORMAT_INT64_KHR:
		dbg("Vulkan pipeline statistic %s=%" PRIi64 "\n",
		    statistic->name, statistic->value.i64);
		break;
	case VK_PIPELINE_EXECUTABLE_STATISTIC_FORMAT_UINT64_KHR:
		dbg("Vulkan pipeline statistic %s=%" PRIu64 "\n",
		    statistic->name, statistic->value.u64);
		break;
	case VK_PIPELINE_EXECUTABLE_STATISTIC_FORMAT_FLOAT64_KHR:
		dbg("Vulkan pipeline statistic %s=%.6f\n", statistic->name,
		    statistic->value.f64);
		break;
	default:
		dbg("Vulkan pipeline statistic %s has unknown format %d\n",
		    statistic->name, statistic->format);
		break;
	}
}

static void log_executable_statistics(struct zc_vulkan *ctx,
				      VkPipeline pipeline, uint32_t index)
{
	VkPipelineExecutableInfoKHR executable = {
		.sType = VK_STRUCTURE_TYPE_PIPELINE_EXECUTABLE_INFO_KHR,
		.pipeline = pipeline,
		.executableIndex = index,
	};
	VkPipelineExecutableStatisticKHR *statistics = NULL;
	VkResult result;
	uint32_t count = 0;

	result = ctx->get_executable_statistics(ctx->device, &executable,
						&count, NULL);
	if (result != VK_SUCCESS || !count)
		return;

	statistics = calloc(count, sizeof(*statistics));
	if (!statistics)
		return;

	for (uint32_t i = 0; i < count; ++i) {
		statistics[i].sType =
			VK_STRUCTURE_TYPE_PIPELINE_EXECUTABLE_STATISTIC_KHR;
	}

	result = ctx->get_executable_statistics(ctx->device, &executable,
						&count, statistics);
	if (result == VK_SUCCESS) {
		for (uint32_t i = 0; i < count; ++i)
			log_pipeline_statistic(&statistics[i]);
	}

	free(statistics);
}

static void log_pipeline_statistics(struct zc_vulkan *ctx,
				    VkPipeline pipeline, const char *description)
{
	VkPipelineInfoKHR pipeline_info = {
		.sType = VK_STRUCTURE_TYPE_PIPELINE_INFO_KHR,
		.pipeline = pipeline,
	};
	VkPipelineExecutablePropertiesKHR *executables = NULL;
	VkResult result;
	uint32_t executable_count = 0;

	if (!ctx->pipeline_executable_info)
		return;
	dbg("Vulkan %s pipeline compiler statistics:\n", description);

	result = ctx->get_executable_properties(ctx->device, &pipeline_info,
						&executable_count, NULL);
	if (result != VK_SUCCESS || !executable_count) {
		dbg("Vulkan pipeline executable query failed: %s (%d)\n",
		    vk_result_name(result), result);
		return;
	}

	executables = calloc(executable_count, sizeof(*executables));
	if (!executables)
		return;
	for (uint32_t i = 0; i < executable_count; ++i)
		executables[i].sType =
			VK_STRUCTURE_TYPE_PIPELINE_EXECUTABLE_PROPERTIES_KHR;
	result = ctx->get_executable_properties(ctx->device, &pipeline_info,
						&executable_count, executables);
	if (result != VK_SUCCESS)
		goto out;

	for (uint32_t i = 0; i < executable_count; ++i) {
		dbg("Vulkan pipeline executable %u: %s, subgroup-size=%u\n",
		    i, executables[i].name, executables[i].subgroupSize);
		log_executable_statistics(ctx, pipeline, i);
	}
out:
	if (result != VK_SUCCESS)
		dbg("Vulkan pipeline statistics query failed: %s (%d)\n",
		    vk_result_name(result), result);
	free(executables);
}
#else
static void log_pipeline_statistics(struct zc_vulkan *ctx,
				    VkPipeline pipeline, const char *description)
{
	(void)ctx;
	(void)pipeline;
	(void)description;
}
#endif

static void select_specialized_pipeline(struct zc_vulkan *ctx,
					uint32_t length)
{
	struct specialization_data {
		uint32_t length;
		uint32_t radix;
		uint32_t header_count;
	} data = {
		.length = length,
		.radix = ctx->search.radix,
		.header_count = (uint32_t)ctx->header_count,
	};
	VkSpecializationMapEntry entries[] = {
		{
			.constantID = SPEC_LENGTH_ID,
			.offset = offsetof(struct specialization_data, length),
			.size = sizeof(data.length),
		},
		{
			.constantID = SPEC_RADIX_ID,
			.offset = offsetof(struct specialization_data, radix),
			.size = sizeof(data.radix),
		},
		{
			.constantID = SPEC_HEADER_COUNT_ID,
			.offset = offsetof(struct specialization_data, header_count),
			.size = sizeof(data.header_count),
		},
	};
	VkSpecializationInfo specialization = {
		.mapEntryCount = sizeof(entries) / sizeof(entries[0]),
		.pMapEntries = entries,
		.dataSize = sizeof(data),
		.pData = &data,
	};
	VkPipeline *pipeline = &ctx->specialized_pipelines[length];

	if (!*pipeline) {
		VkResult result;

		result = create_compute_pipeline(ctx, &specialization, pipeline);
		if (result != VK_SUCCESS) {
			dbg("Vulkan pipeline specialization failed for length %u: "
			    "%s (%d); using generic pipeline\n",
			    length, vk_result_name(result), result);
			ctx->active_pipeline = ctx->generic_pipeline;
			return;
		}

		dbg("created specialized Vulkan pipeline: length=%u radix=%u "
		    "headers=%u\n", data.length, data.radix,
		    data.header_count);
		log_pipeline_statistics(ctx, *pipeline, "specialized");
	}

	ctx->active_pipeline = *pipeline;
}

static VkResult allocate_descriptor_set(struct zc_vulkan *ctx)
{
	VkDescriptorPoolSize pool_size = {
		.type = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
		.descriptorCount = 2,
	};
	VkDescriptorPoolCreateInfo pool = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO,
		.maxSets = 1,
		.poolSizeCount = 1,
		.pPoolSizes = &pool_size,
	};
	VkDescriptorSetAllocateInfo allocate = {
		.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_SET_ALLOCATE_INFO,
		.descriptorSetCount = 1,
		.pSetLayouts = &ctx->descriptor_layout,
	};
	VkResult result;

	result = vkCreateDescriptorPool(ctx->device, &pool, NULL,
					&ctx->descriptor_pool);
	if (result != VK_SUCCESS)
		return result;

	allocate.descriptorPool = ctx->descriptor_pool;
	return vkAllocateDescriptorSets(ctx->device, &allocate,
					&ctx->descriptor_set);
}

static void update_descriptor_set(struct zc_vulkan *ctx)
{
	VkDescriptorBufferInfo buffers[2] = {
		{
			.buffer = ctx->input.buffer,
			.range = INPUT_WORDS * sizeof(uint32_t),
		},
		{
			.buffer = ctx->result.buffer,
			.range = RESULT_WORDS * sizeof(uint32_t),
		},
	};
	VkWriteDescriptorSet writes[2] = {
		{
			.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
			.dstSet = ctx->descriptor_set,
			.dstBinding = 0,
			.descriptorCount = 1,
			.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
			.pBufferInfo = &buffers[0],
		},
		{
			.sType = VK_STRUCTURE_TYPE_WRITE_DESCRIPTOR_SET,
			.dstSet = ctx->descriptor_set,
			.dstBinding = 1,
			.descriptorCount = 1,
			.descriptorType = VK_DESCRIPTOR_TYPE_STORAGE_BUFFER,
			.pBufferInfo = &buffers[1],
		},
	};

	vkUpdateDescriptorSets(ctx->device, 2, writes, 0, NULL);
}

static VkResult create_descriptors(struct zc_vulkan *ctx)
{
	VkResult result = allocate_descriptor_set(ctx);

	if (result != VK_SUCCESS)
		return result;

	update_descriptor_set(ctx);
	dbg("bound Vulkan input and result storage buffers\n");
	return VK_SUCCESS;
}

/* -------------------------------------------------------------------------
 * Device lifetime
 * ------------------------------------------------------------------------- */

#if defined(VK_EXT_subgroup_size_control) || \
	defined(VK_KHR_pipeline_executable_properties)
static bool add_device_extension(struct zc_vk_device_config *config,
				 const char *extension)
{
	if (config->extension_count >= DEVICE_EXTENSION_CAPACITY)
		return false;

	config->extensions[config->extension_count++] = extension;
	return true;
}

static PFN_vkGetPhysicalDeviceFeatures2
get_physical_device_features2(const struct zc_vulkan *ctx)
{
	if (ctx->instance_api_version < VK_API_VERSION_1_1)
		return NULL;

	return (PFN_vkGetPhysicalDeviceFeatures2)vkGetInstanceProcAddr(
		       ctx->instance, "vkGetPhysicalDeviceFeatures2");
}
#endif

#ifdef VK_EXT_subgroup_size_control
static void configure_subgroup_size(
	struct zc_vulkan *ctx, const VkPhysicalDeviceProperties *properties,
	PFN_vkGetPhysicalDeviceFeatures2 get_features2,
	struct zc_vk_device_config *config)
{
	const uint32_t requested = ZC_VULKAN_SUBGROUP_SIZE;
	PFN_vkGetPhysicalDeviceProperties2 get_properties2;
	VkPhysicalDeviceFeatures2 supported_features = {
		.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2,
		.pNext = &config->subgroup_size,
	};
	VkPhysicalDeviceSubgroupSizeControlPropertiesEXT subgroup_properties = {
		.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_PROPERTIES_EXT,
	};
	VkPhysicalDeviceProperties2 supported_properties = {
		.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2,
		.pNext = &subgroup_properties,
	};
	bool core_feature = false;
	bool extension_feature;

	if (!requested || properties->vendorID != AMD_VENDOR_ID || !get_features2)
		return;

	get_properties2 = (PFN_vkGetPhysicalDeviceProperties2)
			  vkGetInstanceProcAddr(ctx->instance,
						"vkGetPhysicalDeviceProperties2");
	if (!get_properties2)
		return;

#ifdef VK_API_VERSION_1_3
	core_feature = ctx->instance_api_version >= VK_API_VERSION_1_3 &&
		       properties->apiVersion >= VK_API_VERSION_1_3;
#endif
	extension_feature = device_extension_supported(
				    ctx->physical_device, VK_EXT_SUBGROUP_SIZE_CONTROL_EXTENSION_NAME);
	if (!core_feature && !extension_feature)
		return;

	config->subgroup_size.sType =
		VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_SUBGROUP_SIZE_CONTROL_FEATURES_EXT;
	get_features2(ctx->physical_device, &supported_features);
	get_properties2(ctx->physical_device, &supported_properties);

	dbg("Vulkan subgroup-size control: feature=%u range=%u..%u "
	    "compute-stages=0x%x max-compute-subgroups=%u\n",
	    config->subgroup_size.subgroupSizeControl,
	    subgroup_properties.minSubgroupSize,
	    subgroup_properties.maxSubgroupSize,
	    subgroup_properties.requiredSubgroupSizeStages,
	    subgroup_properties.maxComputeWorkgroupSubgroups);

	if (!config->subgroup_size.subgroupSizeControl ||
	    !(subgroup_properties.requiredSubgroupSizeStages &
	      VK_SHADER_STAGE_COMPUTE_BIT) ||
	    requested < subgroup_properties.minSubgroupSize ||
	    requested > subgroup_properties.maxSubgroupSize ||
	    WORKGROUP_SIZE % requested != 0 ||
	    WORKGROUP_SIZE / requested >
	    subgroup_properties.maxComputeWorkgroupSubgroups) {
		dbg("Vulkan compute subgroup size %u is unsupported; "
		    "using the driver default\n", requested);
		return;
	}

	if (!core_feature &&
	    !add_device_extension(config,
				  VK_EXT_SUBGROUP_SIZE_CONTROL_EXTENSION_NAME))
		return;

	ctx->required_subgroup_size = requested;
	config->subgroup_size.subgroupSizeControl = VK_TRUE;
	config->subgroup_size.computeFullSubgroups = VK_FALSE;
	config->subgroup_size.pNext = config->feature_chain;
	config->feature_chain = &config->subgroup_size;
	dbg("requesting Vulkan compute subgroup size %u\n", requested);
}
#endif

#ifdef VK_KHR_pipeline_executable_properties
static void configure_pipeline_statistics(
	struct zc_vulkan *ctx, const VkPhysicalDeviceProperties *properties,
	PFN_vkGetPhysicalDeviceFeatures2 get_features2,
	struct zc_vk_device_config *config)
{
	VkPhysicalDeviceFeatures2 supported_features = {
		.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_FEATURES_2,
		.pNext = &config->pipeline_info,
	};

	/* Capturing compiler statistics can inhibit pipeline caching, so only
	 * enable the developer-oriented extension when debug output requested it.
	 * Vulkan 1.1 is sufficient for the core feature-query entry point. */
	if (!pipeline_statistics_requested() || !get_features2 ||
	    properties->apiVersion < VK_API_VERSION_1_1 ||
	    !device_extension_supported(
		    ctx->physical_device,
		    VK_KHR_PIPELINE_EXECUTABLE_PROPERTIES_EXTENSION_NAME))
		return;

	config->pipeline_info.sType =
		VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PIPELINE_EXECUTABLE_PROPERTIES_FEATURES_KHR;
	get_features2(ctx->physical_device, &supported_features);
	if (!config->pipeline_info.pipelineExecutableInfo ||
	    !add_device_extension(
		    config,
		    VK_KHR_PIPELINE_EXECUTABLE_PROPERTIES_EXTENSION_NAME))
		return;

	config->pipeline_info.pNext = config->feature_chain;
	config->feature_chain = &config->pipeline_info;
	ctx->pipeline_executable_info = true;
	dbg("enabling Vulkan pipeline executable statistics\n");
}
#endif

static void configure_device_features(
	struct zc_vulkan *ctx, const VkPhysicalDeviceProperties *properties,
	struct zc_vk_device_config *config)
{
#if defined(VK_EXT_subgroup_size_control) || \
	defined(VK_KHR_pipeline_executable_properties)
	PFN_vkGetPhysicalDeviceFeatures2 get_features2 =
		get_physical_device_features2(ctx);

#ifdef VK_EXT_subgroup_size_control
	configure_subgroup_size(ctx, properties, get_features2, config);
#endif
#ifdef VK_KHR_pipeline_executable_properties
	configure_pipeline_statistics(ctx, properties, get_features2, config);
#endif
#else
	(void)ctx;
	(void)properties;
	(void)config;
#endif
}

static VkResult select_physical_device(
	struct zc_vulkan *ctx, VkPhysicalDeviceProperties *properties)
{
	VkResult result;

	/* No presentation surface is needed, only a compute-capable queue. */
	result = create_instance(&ctx->instance, &ctx->instance_api_version);
	if (result != VK_SUCCESS)
		return result;

	if (enumerate_devices(NULL, ctx->device_index, ctx->instance,
			      &ctx->physical_device, &ctx->queue_family,
			      &ctx->timestamp_valid_bits, ctx->device_name)) {
		err("Vulkan device %u is unavailable or has no compute queue\n",
		    ctx->device_index);
		return VK_ERROR_INITIALIZATION_FAILED;
	}

	vkGetPhysicalDeviceProperties(ctx->physical_device, properties);
	ctx->timestamp_period = properties->limits.timestampPeriod;
	dbg("Vulkan device limits: workgroups-x=%u workgroup-size-x=%u "
	    "invocations=%u storage-buffer-range=%u\n",
	    properties->limits.maxComputeWorkGroupCount[0],
	    properties->limits.maxComputeWorkGroupSize[0],
	    properties->limits.maxComputeWorkGroupInvocations,
	    properties->limits.maxStorageBufferRange);

	return VK_SUCCESS;
}

#ifdef VK_KHR_pipeline_executable_properties
static void load_pipeline_statistics_functions(struct zc_vulkan *ctx)
{
	if (!ctx->pipeline_executable_info)
		return;

	ctx->get_executable_properties =
		(PFN_vkGetPipelineExecutablePropertiesKHR)vkGetDeviceProcAddr(
			ctx->device, "vkGetPipelineExecutablePropertiesKHR");
	ctx->get_executable_statistics =
		(PFN_vkGetPipelineExecutableStatisticsKHR)vkGetDeviceProcAddr(
			ctx->device, "vkGetPipelineExecutableStatisticsKHR");
	if (!ctx->get_executable_properties ||
	    !ctx->get_executable_statistics) {
		dbg("Vulkan pipeline executable entry points unavailable\n");
		ctx->pipeline_executable_info = false;
	}
}
#else
static void load_pipeline_statistics_functions(struct zc_vulkan *ctx)
{
	(void)ctx;
}
#endif

static VkResult create_logical_device(
	struct zc_vulkan *ctx, const VkPhysicalDeviceProperties *properties)
{
	struct zc_vk_device_config config = { 0 };
	float priority = 1.0f;
	VkDeviceQueueCreateInfo queue = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
		.queueFamilyIndex = ctx->queue_family,
		.queueCount = 1,
		.pQueuePriorities = &priority,
	};
	VkDeviceCreateInfo device = {
		.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
		.queueCreateInfoCount = 1,
		.pQueueCreateInfos = &queue,
	};
	VkResult result;

	configure_device_features(ctx, properties, &config);
	device.pNext = config.feature_chain;
	device.enabledExtensionCount = config.extension_count;
	device.ppEnabledExtensionNames = config.extension_count ?
					 config.extensions : NULL;

	result = vkCreateDevice(ctx->physical_device, &device, NULL, &ctx->device);
	if (result != VK_SUCCESS)
		return result;

	load_pipeline_statistics_functions(ctx);
	vkGetDeviceQueue(ctx->device, ctx->queue_family, 0, &ctx->queue);
	return VK_SUCCESS;
}

static VkResult create_command_resources(
	struct zc_vulkan *ctx, const VkPhysicalDeviceProperties *properties)
{
	VkCommandPoolCreateInfo pool = {
		.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
		.flags = VK_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT,
		.queueFamilyIndex = ctx->queue_family,
	};
	VkCommandBufferAllocateInfo command = {
		.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
		.level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
		.commandBufferCount = 1,
	};
	VkFenceCreateInfo fence = {
		.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO,
	};
	VkQueryPoolCreateInfo timestamp_pool = {
		.sType = VK_STRUCTURE_TYPE_QUERY_POOL_CREATE_INFO,
		.queryType = VK_QUERY_TYPE_TIMESTAMP,
		.queryCount = 2,
	};
	VkResult result;

	result = vkCreateCommandPool(ctx->device, &pool, NULL,
				     &ctx->command_pool);
	if (result != VK_SUCCESS)
		return result;

	command.commandPool = ctx->command_pool;
	result = vkAllocateCommandBuffers(ctx->device, &command,
					  &ctx->command_buffer);
	if (result != VK_SUCCESS)
		return result;

	result = vkCreateFence(ctx->device, &fence, NULL, &ctx->fence);
	if (result != VK_SUCCESS)
		return result;

	/* Timestamp queries are optional instrumentation. */
	if (!properties->limits.timestampComputeAndGraphics ||
	    !ctx->timestamp_valid_bits) {
		dbg("Vulkan compute timestamps are unavailable on this queue\n");
		return VK_SUCCESS;
	}

	result = vkCreateQueryPool(ctx->device, &timestamp_pool, NULL,
				   &ctx->timestamp_pool);
	if (result != VK_SUCCESS) {
		dbg("disabling Vulkan timestamps: %s (%d)\n",
		    vk_result_name(result), result);
		ctx->timestamp_pool = VK_NULL_HANDLE;
		return VK_SUCCESS;
	}

	dbg("enabled Vulkan timestamps: valid-bits=%u period=%.3f ns\n",
	    ctx->timestamp_valid_bits, ctx->timestamp_period);
	return VK_SUCCESS;
}

static bool set_max_chunk(struct zc_vulkan *ctx,
			  const VkPhysicalDeviceProperties *properties)
{
	uint64_t device_limit;
	uint64_t selected_limit = CHUNK_LIMIT;

	/* Convert the X-axis workgroup limit into prefix-batched candidates in
	 * 64 bits, then clamp it to the shader's uint32_t candidate counter. */
	device_limit =
		(uint64_t)properties->limits.maxComputeWorkGroupCount[0] *
		WORKGROUP_SIZE * ctx->search.radix;
	if (selected_limit > device_limit)
		selected_limit = device_limit;
	if (selected_limit > UINT32_MAX)
		selected_limit = UINT32_MAX;

	ctx->max_chunk = (uint32_t)selected_limit;

	/* Prefix sharing requires non-final dispatches to end at a radix
	 * boundary, leaving the next dispatch's final digit at zero. */
	ctx->max_chunk -= ctx->max_chunk % ctx->search.radix;
	return ctx->max_chunk != 0;
}

static bool device_limits_support_shader(
	const VkPhysicalDeviceProperties *properties, VkDeviceSize input_size,
	VkDeviceSize result_size)
{
	const VkPhysicalDeviceLimits *limits = &properties->limits;

	if (limits->maxComputeWorkGroupInvocations < WORKGROUP_SIZE ||
	    limits->maxComputeWorkGroupSize[0] < WORKGROUP_SIZE) {
		err("Vulkan device cannot run %u-invocation compute workgroups\n",
		    WORKGROUP_SIZE);
		return false;
	}

	if (limits->maxComputeSharedMemorySize < 256u * sizeof(uint32_t)) {
		err("Vulkan device lacks space for the shader CRC lookup table\n");
		return false;
	}

	if (input_size > limits->maxStorageBufferRange ||
	    result_size > limits->maxStorageBufferRange) {
		err("Vulkan device storage-buffer range is too small\n");
		return false;
	}

	return true;
}

static VkResult create_data_resources(
	struct zc_vulkan *ctx, const VkPhysicalDeviceProperties *properties)
{
	const VkDeviceSize input_size = INPUT_WORDS * sizeof(uint32_t);
	const VkDeviceSize result_size = RESULT_WORDS * sizeof(uint32_t);
	const VkDeviceSize staging_size = result_size;
	VkResult result;

	if (!device_limits_support_shader(properties, input_size, result_size))
		return VK_ERROR_FEATURE_NOT_PRESENT;

	/* The frequently accessed buffers stay device-local.  One host-visible
	 * staging allocation is large enough for either transfer direction. */
	result = create_buffer(ctx, input_size,
			       VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
			       VK_BUFFER_USAGE_TRANSFER_DST_BIT,
			       VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, &ctx->input);
	if (result != VK_SUCCESS)
		return result;

	result = create_buffer(ctx, result_size,
			       VK_BUFFER_USAGE_STORAGE_BUFFER_BIT |
			       VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
			       VK_BUFFER_USAGE_TRANSFER_DST_BIT,
			       VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT, &ctx->result);
	if (result != VK_SUCCESS)
		return result;

	result = create_buffer(ctx, staging_size,
			       VK_BUFFER_USAGE_TRANSFER_SRC_BIT |
			       VK_BUFFER_USAGE_TRANSFER_DST_BIT,
			       VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT, &ctx->staging);
	if (result != VK_SUCCESS)
		return result;

	result = create_pipeline_resources(ctx);
	if (result != VK_SUCCESS)
		return result;
	log_pipeline_statistics(ctx, ctx->generic_pipeline, "generic");

	result = create_descriptors(ctx);
	if (result != VK_SUCCESS)
		return result;

	if (!set_max_chunk(ctx, properties))
		return VK_ERROR_INITIALIZATION_FAILED;

	dbg("Vulkan resources ready: input=%" PRIu64
	    " bytes result=%" PRIu64 " bytes staging=%" PRIu64
	    " bytes max-chunk=%u workgroup-size=%u\n",
	    (uint64_t)input_size, (uint64_t)result_size,
	    (uint64_t)staging_size, ctx->max_chunk, WORKGROUP_SIZE);
	return VK_SUCCESS;
}

static VkResult init_device(struct zc_vulkan *ctx)
{
	VkPhysicalDeviceProperties properties;
	VkResult result;

	result = select_physical_device(ctx, &properties);
	if (result != VK_SUCCESS)
		goto fail;

	result = create_logical_device(ctx, &properties);
	if (result != VK_SUCCESS)
		goto fail;

	/* Dispatches are serialized through one reusable command buffer and
	 * fence, so a single compute queue is sufficient. */
	result = create_command_resources(ctx, &properties);
	if (result != VK_SUCCESS)
		goto fail;

	result = create_data_resources(ctx, &properties);
	if (result != VK_SUCCESS)
		goto fail;

	info("Using Vulkan device %u: %s\n", ctx->device_index,
	     ctx->device_name);
	return VK_SUCCESS;

fail:
	err("Vulkan initialization failed: %s (%d)\n",
	    vk_result_name(result), result);
	return result;
}

static void destroy_pipeline_resources(struct zc_vulkan *ctx)
{
	if (ctx->descriptor_pool)
		vkDestroyDescriptorPool(ctx->device, ctx->descriptor_pool, NULL);

	for (size_t i = 0; i <= ZC_PW_MAXLEN; ++i) {
		if (ctx->specialized_pipelines[i]) {
			vkDestroyPipeline(ctx->device,
					  ctx->specialized_pipelines[i], NULL);
		}
	}

	if (ctx->generic_pipeline)
		vkDestroyPipeline(ctx->device, ctx->generic_pipeline, NULL);
	if (ctx->shader_module)
		vkDestroyShaderModule(ctx->device, ctx->shader_module, NULL);
	if (ctx->pipeline_layout)
		vkDestroyPipelineLayout(ctx->device, ctx->pipeline_layout, NULL);
	if (ctx->descriptor_layout) {
		vkDestroyDescriptorSetLayout(ctx->device, ctx->descriptor_layout,
					     NULL);
	}
}

static void deinit_device(struct zc_vulkan *ctx)
{
	/* All dispatches are synchronous today.  Waiting here also makes partial
	 * initialization failures safe to unwind through zc_vulkan_destroy(). */
	if (ctx->device) {
		dbg("waiting for Vulkan device before teardown\n");
		vkDeviceWaitIdle(ctx->device);
	}

	/* Destroy objects in reverse dependency order.  Vulkan destroy calls are
	 * null-safe only where explicitly guarded here. */
	destroy_pipeline_resources(ctx);

	if (ctx->timestamp_pool)
		vkDestroyQueryPool(ctx->device, ctx->timestamp_pool, NULL);

	destroy_buffer(ctx, &ctx->staging);
	destroy_buffer(ctx, &ctx->result);
	destroy_buffer(ctx, &ctx->input);

	if (ctx->fence)
		vkDestroyFence(ctx->device, ctx->fence, NULL);
	if (ctx->command_pool)
		vkDestroyCommandPool(ctx->device, ctx->command_pool, NULL);
	if (ctx->device)
		vkDestroyDevice(ctx->device, NULL);
	if (ctx->instance)
		vkDestroyInstance(ctx->instance, NULL);

	ctx->device = VK_NULL_HANDLE;
	ctx->instance = VK_NULL_HANDLE;
	dbg("Vulkan resources released\n");
}

/* -------------------------------------------------------------------------
 * Candidate verification and GPU input serialization
 * ------------------------------------------------------------------------- */

static bool test_password(struct zc_vulkan *ctx, const char *password)
{
	struct zc_key key;
	int result;

	/*
	 * The GPU deliberately performs only the inexpensive header filter.
	 * Recreate the keys here and use the existing CPU path to reject the
	 * extremely small number of false positives with a full CRC check.
	 */
	update_default_keys_from_array(&key, (const uint8_t *)password,
				       strlen(password));
	if (!decrypt_headers(&key, ctx->headers, ctx->header_count))
		return false;

	decrypt(ctx->cipher, ctx->plaintext, ctx->cipher_size, &key);
	if (ctx->cipher_is_deflated)
		result = inflate_buffer(ctx->zlib, ctx->plaintext + ENC_HEADER_LEN,
					ctx->cipher_size - ENC_HEADER_LEN,
					ctx->inflate, INFLATE_CHUNK,
					ctx->original_crc);
	else
		result = test_buffer_crc(ctx->plaintext + ENC_HEADER_LEN,
					 ctx->cipher_size - ENC_HEADER_LEN,
					 ctx->original_crc);

	return result == 0;
}

static void fill_input(const struct zc_vulkan *ctx, uint32_t *words,
		       uint32_t count)
{
	/* Metadata and unused fixed-capacity fields begin at zero. */
	memset(words, 0, INPUT_WORDS * sizeof(*words));

	words[INPUT_CANDIDATE_COUNT] = count;
	words[INPUT_LENGTH] = ctx->search.length;
	words[INPUT_CHARSET_LENGTH] = ctx->search.radix;
	words[INPUT_HEADER_COUNT] = ctx->header_count;
	words[INPUT_RESULT_CAPACITY] = RESULT_CAPACITY;

	/* The base digits identify candidate zero for this dispatch. */
	memcpy(words + INPUT_BASE_DIGITS, ctx->search.digits,
	       ctx->search.length * sizeof(*words));
	memcpy(words + INPUT_CHARSET, ctx->search.alphabet,
	       ctx->search.radix * sizeof(*words));

	/* Sharing the CPU's lookup table keeps ZipCrypto key updates identical. */
	memcpy(words + INPUT_CRC_TABLE, crc_32_tab, sizeof(crc_32_tab));

	/* Each header occupies twelve encrypted bytes followed by its expected
	 * validation byte. */
	for (size_t i = 0; i < ctx->header_count; ++i) {
		uint32_t *header = words + INPUT_HEADERS + i * HEADER_WORDS;

		for (size_t j = 0; j < ENC_HEADER_LEN; ++j)
			header[j] = ctx->headers[i].buf[j];
		header[ENC_HEADER_LEN] = ctx->headers[i].magic;
	}
}

static int compare_index(const void *a, const void *b)
{
	uint32_t av = *(const uint32_t *)a;
	uint32_t bv = *(const uint32_t *)b;

	return (av > bv) - (av < bv);
}

static uint32_t dispatch_invocation_count(const struct zc_vulkan *ctx,
					  uint32_t candidates)
{
	return (uint32_t)(((uint64_t)candidates + ctx->search.radix - 1) /
			  ctx->search.radix);
}

static uint32_t dispatch_workgroup_count(const struct zc_vulkan *ctx,
					 uint32_t candidates)
{
	uint32_t invocations = dispatch_invocation_count(ctx, candidates);

	return (uint32_t)(((uint64_t)invocations + WORKGROUP_SIZE - 1) /
			  WORKGROUP_SIZE);
}

/* -------------------------------------------------------------------------
 * One GPU dispatch: upload -> compute -> download
 * ------------------------------------------------------------------------- */

static VkResult upload_dispatch_input(struct zc_vulkan *ctx, uint32_t count)
{
	void *mapped;
	VkResult result;

	result = vkMapMemory(ctx->device, ctx->staging.memory, 0,
			     VK_WHOLE_SIZE, 0, &mapped);
	if (result != VK_SUCCESS)
		return result;

	fill_input(ctx, mapped, count);
	result = flush_memory(ctx, &ctx->staging);

	vkUnmapMemory(ctx->device, ctx->staging.memory);
	return result;
}

static void record_dispatch_upload(struct zc_vulkan *ctx)
{
	VkBufferCopy input_copy = {
		.size = INPUT_WORDS * sizeof(uint32_t),
	};
	VkMemoryBarrier transfer_to_compute = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
		.srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
		.dstAccessMask = VK_ACCESS_SHADER_READ_BIT |
		VK_ACCESS_SHADER_WRITE_BIT,
	};

	/*
	 * Transfer the immutable input for this chunk and clear the survivor
	 * counter and offsets left by the previous dispatch.
	 */
	vkCmdCopyBuffer(ctx->command_buffer, ctx->staging.buffer,
			ctx->input.buffer, 1, &input_copy);
	vkCmdFillBuffer(ctx->command_buffer, ctx->result.buffer, 0,
			VK_WHOLE_SIZE, 0);

	/* Make both transfer writes visible to the compute shader. */
	vkCmdPipelineBarrier(ctx->command_buffer,
			     VK_PIPELINE_STAGE_TRANSFER_BIT,
			     VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT, 0,
			     1, &transfer_to_compute, 0, NULL, 0, NULL);
}

static void record_dispatch_compute(struct zc_vulkan *ctx, uint32_t count)
{
	if (ctx->timestamp_pool)
		vkCmdWriteTimestamp(ctx->command_buffer,
				    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
				    ctx->timestamp_pool, 0);

	vkCmdBindPipeline(ctx->command_buffer, VK_PIPELINE_BIND_POINT_COMPUTE,
			  ctx->active_pipeline);
	vkCmdBindDescriptorSets(ctx->command_buffer,
				VK_PIPELINE_BIND_POINT_COMPUTE,
				ctx->pipeline_layout, 0, 1,
				&ctx->descriptor_set, 0, NULL);
	vkCmdDispatch(ctx->command_buffer,
		      dispatch_workgroup_count(ctx, count), 1, 1);

	if (ctx->timestamp_pool)
		vkCmdWriteTimestamp(ctx->command_buffer,
				    VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
				    ctx->timestamp_pool, 1);
}

static void record_dispatch_download(struct zc_vulkan *ctx)
{
	VkBufferCopy result_copy = {
		.size = RESULT_WORDS * sizeof(uint32_t),
	};
	VkMemoryBarrier compute_to_transfer = {
		.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
		.srcAccessMask = VK_ACCESS_SHADER_WRITE_BIT,
		.dstAccessMask = VK_ACCESS_TRANSFER_READ_BIT,
	};

	/* Make shader-written survivor offsets visible to the result copy. */
	vkCmdPipelineBarrier(ctx->command_buffer,
			     VK_PIPELINE_STAGE_COMPUTE_SHADER_BIT,
			     VK_PIPELINE_STAGE_TRANSFER_BIT, 0,
			     1, &compute_to_transfer, 0, NULL, 0, NULL);
	vkCmdCopyBuffer(ctx->command_buffer, ctx->result.buffer,
			ctx->staging.buffer, 1, &result_copy);
}

static VkResult record_dispatch_commands(struct zc_vulkan *ctx,
					 uint32_t count)
{
	VkCommandBufferBeginInfo begin = {
		.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO,
		.flags = VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT,
	};
	VkResult result;

	result = vkResetCommandBuffer(ctx->command_buffer, 0);
	if (result != VK_SUCCESS)
		return result;

	result = vkBeginCommandBuffer(ctx->command_buffer, &begin);
	if (result != VK_SUCCESS)
		return result;

	if (ctx->timestamp_pool)
		vkCmdResetQueryPool(ctx->command_buffer, ctx->timestamp_pool,
				    0, 2);

	record_dispatch_upload(ctx);
	record_dispatch_compute(ctx, count);
	record_dispatch_download(ctx);

	return vkEndCommandBuffer(ctx->command_buffer);
}

static VkResult submit_dispatch(struct zc_vulkan *ctx)
{
	VkSubmitInfo submit = {
		.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO,
		.commandBufferCount = 1,
		.pCommandBuffers = &ctx->command_buffer,
	};
	VkResult result;

	result = vkResetFences(ctx->device, 1, &ctx->fence);
	if (result != VK_SUCCESS)
		return result;

	result = vkQueueSubmit(ctx->queue, 1, &submit, ctx->fence);
	if (result != VK_SUCCESS)
		return result;

	/* One command buffer reuses the same buffers, so completion is required
	 * before the host reads results or starts the next chunk. */
	return vkWaitForFences(ctx->device, 1, &ctx->fence, VK_TRUE,
			       UINT64_MAX);
}

static void accumulate_dispatch_timestamps(struct zc_vulkan *ctx)
{
	uint64_t timestamps[2];
	uint64_t elapsed;
	VkResult result;

	if (!ctx->timestamp_pool)
		return;

	result = vkGetQueryPoolResults(ctx->device, ctx->timestamp_pool, 0, 2,
				       sizeof(timestamps), timestamps,
				       sizeof(timestamps[0]),
				       VK_QUERY_RESULT_64_BIT);
	if (result != VK_SUCCESS) {
		dbg("Vulkan timestamp query failed: %s (%d)\n",
		    vk_result_name(result), result);
		return;
	}

	/* Timestamp counters may expose fewer than 64 valid bits and wrap between
	 * the two samples.  Masked subtraction handles both that case and the
	 * ordinary monotonically increasing counter. */
	if (ctx->timestamp_valid_bits < 64) {
		uint64_t mask = (UINT64_C(1) << ctx->timestamp_valid_bits) - 1;

		elapsed = (timestamps[1] - timestamps[0]) & mask;
	} else {
		elapsed = timestamps[1] - timestamps[0];
	}
	ctx->gpu_compute_nanoseconds += elapsed * ctx->timestamp_period;
	dbg("Vulkan dispatch GPU compute time: %.3f ms\n",
	    elapsed * ctx->timestamp_period / 1000000.0);
}

static VkResult download_dispatch_results(struct zc_vulkan *ctx,
					  uint32_t **result_words)
{
	void *mapped;
	VkResult result;

	result = vkMapMemory(ctx->device, ctx->staging.memory, 0,
			     VK_WHOLE_SIZE, 0, &mapped);
	if (result != VK_SUCCESS)
		return result;

	/* Non-coherent memory requires explicit invalidation before CPU reads. */
	result = invalidate_memory(ctx, &ctx->staging);
	if (result == VK_SUCCESS) {
		*result_words = malloc(RESULT_WORDS * sizeof(**result_words));
		if (!*result_words)
			result = VK_ERROR_OUT_OF_HOST_MEMORY;
	}

	if (result == VK_SUCCESS)
		memcpy(*result_words, mapped,
		       RESULT_WORDS * sizeof(**result_words));

	vkUnmapMemory(ctx->device, ctx->staging.memory);
	return result;
}

static int run_dispatch(struct zc_vulkan *ctx, uint32_t count,
			uint32_t **result_words)
{
	const char *phase = "input upload";
	VkResult result;
	uint32_t invocations = dispatch_invocation_count(ctx, count);
	uint32_t workgroups = dispatch_workgroup_count(ctx, count);

	++ctx->dispatch_count;
	dbg("Vulkan dispatch %" PRIu64 ": length=%u candidates=%u "
	    "invocations=%u workgroups=%u\n",
	    ctx->dispatch_count, ctx->search.length, count, invocations,
	    workgroups);

	result = upload_dispatch_input(ctx, count);
	if (result != VK_SUCCESS)
		goto fail;

	phase = "command recording";
	result = record_dispatch_commands(ctx, count);
	if (result != VK_SUCCESS)
		goto fail;

	phase = "queue submission";
	result = submit_dispatch(ctx);
	if (result != VK_SUCCESS)
		goto fail;

	accumulate_dispatch_timestamps(ctx);

	phase = "result download";
	result = download_dispatch_results(ctx, result_words);
	if (result != VK_SUCCESS)
		goto fail;

	return 0;

fail:
	err("Vulkan dispatch failed during %s: %s (%d)\n",
	    phase, vk_result_name(result), result);
	return -1;
}

/* -------------------------------------------------------------------------
 * Search orchestration and public API
 * ------------------------------------------------------------------------- */

static int search_range(struct zc_vulkan *ctx, uint32_t count,
			char *password);

static int search_split_range(struct zc_vulkan *ctx, uint32_t count,
			      char *password)
{
	struct zc_vulkan_search original = ctx->search;
	uint32_t first = count / 2;
	int result;

	/* Keep the second half's base aligned for prefix sharing.  An overflow
	 * requires more candidates than RESULT_CAPACITY, so an aligned, nonzero
	 * split should always be available. */
	first -= first % ctx->search.radix;
	if (!first) {
		err("Vulkan survivor buffer overflowed for one candidate\n");
		return -1;
	}

	dbg("splitting overflowing %u-candidate Vulkan range into %u and "
	    "%u candidates\n", count, first, count - first);

	result = search_range(ctx, first, password);
	if (result > 0) {
		ctx->search = original;
		if (zc_vulkan_search_add(ctx->search.digits,
					 ctx->search.length,
					 ctx->search.radix, first)) {
			result = -1;
		} else {
			result = search_range(ctx, count - first, password);
		}
	}

	/* Keep recursive retries invisible to the caller's search position. */
	ctx->search = original;
	return result;
}

static int verify_survivors(struct zc_vulkan *ctx, uint32_t *offsets,
			    uint32_t count, char *password)
{
	/* Atomic appends are unordered.  Sorting retains the CPU engine's
	 * lowest-candidate-first behavior. */
	qsort(offsets, count, sizeof(*offsets), compare_index);

	if (count)
		dbg("CPU-verifying %u Vulkan header survivors\n", count);

	for (uint32_t i = 0; i < count; ++i) {
		zc_vulkan_search_password(&ctx->search, offsets[i], password);
		if (!test_password(ctx, password))
			continue;

		dbg("Vulkan survivor offset %u passed full CPU validation\n",
		    offsets[i]);
		return 0;
	}

	if (count)
		dbg("CPU validation rejected all %u Vulkan header survivors\n",
		    count);
	return 1;
}

static int search_range(struct zc_vulkan *ctx, uint32_t count,
			char *password)
{
	uint32_t *results = NULL;
	uint32_t survivors;
	int result;

	result = run_dispatch(ctx, count, &results);
	if (result)
		return -1;

	/* results[0] counts every survivor, including offsets that did not fit
	 * in the fixed-capacity portion of the buffer. */
	survivors = results[0];
	dbg("Vulkan dispatch %" PRIu64 " returned %u header survivors\n",
	    ctx->dispatch_count, survivors);

	if (survivors > RESULT_CAPACITY) {
		free(results);
		return search_split_range(ctx, count, password);
	}

	/* Count only leaf ranges.  An overflowing parent is retried in two
	 * halves and must not be counted a second time. */
	ctx->passwords_tested += count;
	result = verify_survivors(ctx, results + 1, survivors, password);
	free(results);
	return result;
}

int zc_vulkan_new(struct zc_vulkan **out)
{
	struct zc_vulkan *ctx;

	if (!out)
		return -1;

	ctx = calloc(1, sizeof(*ctx));
	if (!ctx)
		return -1;

	*out = ctx;
	return 0;
}

void zc_vulkan_destroy(struct zc_vulkan *ctx)
{
	if (!ctx)
		return;

	/* Device teardown tolerates an object that failed partway through init. */
	deinit_device(ctx);

	if (ctx->zlib)
		inflate_destroy(ctx->zlib);
	free(ctx->inflate);
	free(ctx->plaintext);
	free(ctx->cipher);
	free(ctx);
}

static int load_validation_data(struct zc_vulkan *ctx, const char *filename)
{
	int result;

	/* Multiple headers make the GPU filter selective; one complete encrypted
	 * entry is retained for authoritative CPU verification. */
	result = zc_zip_fill_header(filename, ctx->headers, HEADER_MAX);
	if (result < 1) {
		err("failed to read validation data, no usable entry found\n");
		return -1;
	}
	ctx->header_count = result;
	dbg("loaded %zu encrypted headers for Vulkan filtering\n",
	    ctx->header_count);

	if (zc_zip_fill_test_cipher(filename, &ctx->cipher, &ctx->cipher_size,
				    &ctx->original_crc,
				    &ctx->cipher_is_deflated)) {
		err("failed to read cipher data\n");
		return -1;
	}
	dbg("loaded CPU validation entry: cipher=%zu bytes method=%s "
	    "crc=0x%08x\n",
	    ctx->cipher_size, ctx->cipher_is_deflated ? "deflate" : "stored",
	    ctx->original_crc);

	ctx->plaintext = malloc(ctx->cipher_size);
	ctx->inflate = malloc(INFLATE_CHUNK);
	if (!ctx->plaintext || !ctx->inflate || inflate_new(&ctx->zlib))
		return -1;
	return 0;
}

int zc_vulkan_init(struct zc_vulkan *ctx, const char *filename,
		   const struct zc_vulkan_config *config)
{
	if (config)
		dbg("initializing Vulkan attack: archive=%s charset=%s "
		    "lengths=%zu..%zu device=%u\n",
		    filename ? filename : "(null)",
		    config->charset ? config->charset : "(null)",
		    config->min_length, config->max_length,
		    config->device_index);

	if (!ctx || !filename || !config ||
	    config->min_length > config->max_length ||
	    config->max_length > ZC_PW_MAXLEN ||
	    zc_vulkan_search_init(&ctx->search, config->charset,
				  config->min_length))
		return -1;

	/* Preserve the normalized alphabet for statistics output. */
	for (size_t i = 0; i < ctx->search.radix; ++i)
		ctx->charset[i] = ctx->search.alphabet[i];

	ctx->min_length = config->min_length;
	ctx->max_length = config->max_length;
	ctx->device_index = config->device_index;

	if (load_validation_data(ctx, filename))
		return -1;

	if (init_device(ctx) != VK_SUCCESS)
		return -1;

	return 0;
}

static int search_password_length(struct zc_vulkan *ctx, uint32_t length,
				  char *password)
{
	if (zc_vulkan_search_set_length(&ctx->search, length))
		return -1;
	select_specialized_pipeline(ctx, length);
	dbg("searching Vulkan passwords of length %u\n", length);

	for (;;) {
		uint32_t count = zc_vulkan_search_chunk_count(
					 ctx->search.digits, ctx->search.length,
					 ctx->search.radix, ctx->max_chunk);
		int result;

		if (!count)
			return 1;

		result = search_range(ctx, count, password);
		if (result <= 0)
			return result;

		/* No password survived CPU verification.  Advance to the candidate
		 * immediately following this dispatch. */
		if (zc_vulkan_search_add(ctx->search.digits, ctx->search.length,
					 ctx->search.radix, count))
			return 1;
	}
}

int zc_vulkan_start(struct zc_vulkan *ctx, char *password,
		    size_t password_size)
{
	if (!ctx || !ctx->device || !password ||
	    password_size <= ctx->max_length)
		return -1;

	/*
	 * The complete mixed-radix counter lives on the host.  Each dispatch gets
	 * a base counter plus a uint32_t local offset, so the complete search can
	 * exceed both one dispatch and UINT32_MAX candidates.
	 */
	ctx->dispatch_count = 0;
	ctx->passwords_tested = 0;
	ctx->gpu_compute_nanoseconds = 0.0;
	dbg("starting Vulkan search: lengths=%u..%u radix=%u max-chunk=%u\n",
	    ctx->min_length, ctx->max_length, ctx->search.radix,
	    ctx->max_chunk);

	for (uint32_t length = ctx->min_length;
	     length <= ctx->max_length; ++length) {
		uint64_t first_dispatch = ctx->dispatch_count;
		int result = search_password_length(ctx, length, password);

		if (result <= 0)
			return result;

		dbg("exhausted Vulkan password length %u in %" PRIu64
		    " dispatches\n",
		    length, ctx->dispatch_count - first_dispatch);
	}

	dbg("Vulkan search exhausted all lengths after %" PRIu64
	    " dispatches\n", ctx->dispatch_count);
	return 1;
}

const char *zc_vulkan_device_name(const struct zc_vulkan *ctx)
{
	return ctx ? ctx->device_name : NULL;
}

const char *zc_vulkan_charset(const struct zc_vulkan *ctx)
{
	return ctx ? ctx->charset : NULL;
}

uint64_t zc_vulkan_passwords_tested(const struct zc_vulkan *ctx)
{
	return ctx ? ctx->passwords_tested : 0;
}

int zc_vulkan_gpu_runtime(const struct zc_vulkan *ctx, double *seconds)
{
	if (!ctx || !seconds || !ctx->timestamp_pool)
		return -1;

	*seconds = ctx->gpu_compute_nanoseconds / 1000000000.0;
	return 0;
}

#else /* !HAVE_VULKAN */

/* Keep the public lifecycle available in builds without the optional loader.
 * Every operational entry point reports that the backend is unavailable. */
struct zc_vulkan {
	int unused;
};

int zc_vulkan_list_devices(FILE *stream)
{
	(void)stream;

	err("yazc was built without Vulkan support\n");
	return -1;
}

int zc_vulkan_new(struct zc_vulkan **out)
{
	if (out)
		*out = NULL;

	err("yazc was built without Vulkan support\n");
	return -1;
}

void zc_vulkan_destroy(struct zc_vulkan *ctx)
{
	(void)ctx;
}

int zc_vulkan_init(struct zc_vulkan *ctx, const char *filename,
		   const struct zc_vulkan_config *config)
{
	(void)ctx;
	(void)filename;
	(void)config;

	return -1;
}

int zc_vulkan_start(struct zc_vulkan *ctx, char *password,
		    size_t password_size)
{
	(void)ctx;
	(void)password;
	(void)password_size;

	return -1;
}

const char *zc_vulkan_device_name(const struct zc_vulkan *ctx)
{
	(void)ctx;

	return NULL;
}

const char *zc_vulkan_charset(const struct zc_vulkan *ctx)
{
	(void)ctx;

	return NULL;
}

uint64_t zc_vulkan_passwords_tested(const struct zc_vulkan *ctx)
{
	(void)ctx;

	return 0;
}

int zc_vulkan_gpu_runtime(const struct zc_vulkan *ctx, double *seconds)
{
	(void)ctx;
	(void)seconds;

	return -1;
}

#endif /* HAVE_VULKAN */
