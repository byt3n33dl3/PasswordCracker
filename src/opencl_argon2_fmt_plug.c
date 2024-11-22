//-------------------------------------------------------------------------------------
// JtR OpenCL format to crack hashes from argon2.
//
// This software is copyright (c) 2023, Alain Espinosa <alainesp at gmail.com> and it
// is hereby released to the general public under the following terms:
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted.
//
// KeePass support copyright (c) 2024, magnum under the same license as above.
//
// Based on https://gitlab.com/omos/argon2-gpu with some ideas from the CPU format.
// TODO: Update this comment to either use lighter wording than "based on" (if
// no copyrightable material from those sources is left in here) or to add the
// proper copyright statements and license.
//-------------------------------------------------------------------------------------

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_argon2;
extern struct fmt_main fmt_opencl_keepass_argon2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_argon2);
john_register_one(&fmt_opencl_keepass_argon2);
#else

#include <string.h>
#include <assert.h>

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "argon2.h"
#include "argon2_core.h"
#include "argon2_encoding.h"
#include "blake2.h"
#include "opencl_common.h"
#include "opencl_helper_macros.h"

#define KEEPASS_ARGON2                  1
#define KEEPASS_REAL_COST_TEST_VECTORS  0
#include "keepass_common.h"

#define FORMAT_LABEL            "argon2-opencl"
#define FORMAT_NAME             "Argon2"
#define KP_ARGON_FORMAT_LABEL   "KeePass-Argon2-opencl"
#define KP_ARGON_FORMAT_NAME    ""
#define ALGORITHM_NAME          "BlaMka OpenCL"
#define FORMAT_TAG_d            "$argon2d$"
#define FORMAT_TAG_i            "$argon2i$"
#define FORMAT_TAG_id           "$argon2id$"

#define BENCHMARK_COMMENT       ""
#define BENCHMARK_LENGTH        0x107
#define PLAINTEXT_LENGTH        125
#define BINARY_SIZE             256
#define BINARY_ALIGN            sizeof(uint32_t)
#define SALT_SIZE               64
#define SALT_ALIGN              sizeof(uint32_t)

struct fmt_main fmt_opencl_argon2;
struct fmt_main fmt_opencl_keepass_argon2;
static struct fmt_main *argon2_self; // Points to one of the two above after init()

#define MIN_KEYS_PER_CRYPT              1
#define MAX_KEYS_PER_CRYPT              (argon2_self->params.max_keys_per_crypt)
#define MAX_KEYS_PER_CRYPT_ORIGINAL     256

static struct fmt_tests tests[] = {
	{"$argon2d$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$w9w3s5/zV8+PcAZlJhnTCOE+vBkZssmZf6jOq3dKv50", "password"},
	{"$argon2i$v=19$m=4096,t=3,p=1$ZGFtYWdlX2RvbmU$N59QwnpxDQZRj1/cO6bqm408dD6Z2Z9LKYpwFJSPVKA", "password"},
	{"$argon2d$v=19$m=4096,t=3,p=1$c2hvcnRfc2FsdA$zMrTcOAOUje6UqObRVh84Pe1K6gumcDqqGzRM0ILzYmj", "sacrificed"},
	{"$argon2i$v=19$m=4096,t=3,p=1$c2hvcnRfc2FsdA$1l4kAwUdAApoCbFH7ghBEf7bsdrOQzE4axIJ3PV0Ncrd", "sacrificed"},
	{"$argon2d$v=19$m=16384,t=3,p=1$c2hvcnRfc2FsdA$TLSTPihIo+5F67Y1vJdfWdB9", "blessed_dead"},
	{"$argon2i$v=19$m=16384,t=3,p=1$c2hvcnRfc2FsdA$vvjDVog22A5x9eljmB+2yC8y", "blessed_dead"},
	{"$argon2d$v=19$m=16384,t=4,p=3$YW5vdGhlcl9zYWx0$yw93eMxC8REPAwbQ0e/q43jR9+RI9HI/DHP75uzm7tQfjU734oaI3dzcMWjYjHzVQD+J4+MG+7oyD8dN/PtnmPCZs+UZ67E+rkXJ/wTvY4WgXgAdGtJRrAGxhy4rD7d5G+dCpqhrog", "death_dying"},
	{"$argon2i$v=19$m=16384,t=4,p=3$YW5vdGhlcl9zYWx0$K7unxwO5aeuZCpnIJ06FMCRKod3eRg8oIRzQrK3E6mGbyqlTvvl47jeDWq/5drF1COJkEF9Ty7FWXJZHa+vqlf2YZGp/4qSlAvKmdtJ/6JZU32iQItzMRwcfujHE+PBjbL5uz4966A", "death_dying"},
	{"$argon2id$v=19$m=4096,t=3,p=1$c2hvcmF0X3NhbHQ$K6/V3qNPJwVmLb/ELiD8gKGskLaFv5OweJYwSKUW1hE", "password"},
	{"$argon2id$v=19$m=16384,t=4,p=3$c2hvcmF0X3NhbHQ$hG83oaWEcftTjbiWJxoQs6gKCModwYAC+9EK8j/DUsk", "sacrificed"},
	{NULL}
};

// TODO: Backport many of the improvements to the CPU format

// If this struct is changed, corresponding changes needed in
// keepass_common.h as well as keepass_kernel.cl
struct argon2_salt {
	uint32_t t_cost, m_cost, lanes;
	uint32_t hash_size;
	uint32_t salt_length;
	char salt[SALT_SIZE];
	argon2_type type;
	argon2_version version;
};
static struct argon2_salt saved_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1] = NULL;
static int *saved_len = NULL;
static uint8_t (*crypted)[BINARY_SIZE] = NULL;

// GPU functions and memory
#define ARGON2_NUM_TYPES 2
static cl_kernel kernels[ARGON2_NUM_TYPES] = {NULL, NULL};
static cl_kernel pre_processing_kernel = NULL;
static cl_mem memory_buffer = NULL, memory_in = NULL;
static int DEVICE_USE_LOCAL_MEMORY = 1;

// CPU buffers to move data from and to the GPU
static uint8_t* blocks_in_out = NULL;

// Autotune params
struct kernel_run_params {
	uint32_t lanes_per_block;
	uint32_t jobs_per_block;
};
static struct kernel_run_params* best_kernel_params = NULL;
static uint32_t max_salt_lanes = 0;
static uint32_t max_segment_blocks = 0;

#define THREADS_PER_LANE 32

// keepass-argon2 specific stuff
typedef struct {
	uint32_t length;
	uint8_t v[KEEPASS_PLAINTEXT_LENGTH];
} kp_password_t;

typedef struct {
	uint32_t cracked;
} kp_result_t;

typedef struct {
	uint8_t  hash[32];
} kp_state_t;

static int new_keys;
static kp_password_t *keepass_inbuffer;
static kp_result_t *keepass_outbuffer;
static kp_state_t *keepass_statebuffer;
static cl_mem cl_keepass_in, cl_keepass_salt, cl_keepass_state, cl_keepass_out;
static cl_kernel keepass_init, keepass_final;
static size_t keepass_insize, keepass_statesize, keepass_outsize;
// End keepass-argon2 specific stuff

static uint32_t index_best_kernel_params(argon2_type type, uint32_t lanes, uint32_t segment_blocks)
{
	assert(best_kernel_params && type >= 0 && type < ARGON2_NUM_TYPES &&
		lanes > 0 && lanes <= max_salt_lanes &&
		segment_blocks > 0 && segment_blocks <= max_segment_blocks);

	uint32_t index = type * max_salt_lanes * max_segment_blocks + (lanes - 1) * max_segment_blocks + (segment_blocks - 1);

	assert(index >= 0 && index < ARGON2_NUM_TYPES * max_salt_lanes * max_segment_blocks);

	return index;
}

static int run_kernel_on_gpu(uint32_t count)
{
	uint32_t pass, slice;
	uint32_t lanes = saved_salt.lanes;
	uint32_t passes = saved_salt.t_cost;

	assert(lanes > 0 && passes > 0 && saved_salt.m_cost > 0);
		assert(gpu_id >= 0 && gpu_id < MAX_GPU_DEVICES && queue[gpu_id]);
		assert(blocks_in_out);

	// Calculate memory size
	uint32_t segment_blocks = MAX(saved_salt.m_cost / (saved_salt.lanes * ARGON2_SYNC_POINTS), 2);

	// Copy data to GPU
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], memory_in, CL_FALSE, 0, MAX_KEYS_PER_CRYPT * ARGON2_PREHASH_DIGEST_LENGTH, blocks_in_out, 0, NULL, NULL), "Copy data to gpu");

	// Pre-process keys
	size_t lws_multiple = get_kernel_preferred_multiple(gpu_id, pre_processing_kernel);
	size_t gws_pre_processing[] = {(MAX_KEYS_PER_CRYPT * 2 + lws_multiple - 1) / lws_multiple * lws_multiple, lanes};
	size_t lws_pre_processing[] = {lws_multiple, 1};
	size_t jobSize = segment_blocks * ARGON2_SYNC_POINTS * saved_salt.lanes * ARGON2_BLOCK_SIZE;
	cl_uint buffer_row_pitch = jobSize / sizeof(cl_ulong);
	cl_uint num_keys = MAX_KEYS_PER_CRYPT;
	HANDLE_CLERROR(clSetKernelArg(pre_processing_kernel, 2, sizeof(buffer_row_pitch), &buffer_row_pitch), "Error setting pre-processing kernel argument");
	HANDLE_CLERROR(clSetKernelArg(pre_processing_kernel, 3, sizeof(num_keys), &num_keys), "Error setting pre-processing kernel argument");
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], pre_processing_kernel, 2, NULL, gws_pre_processing, lws_pre_processing, 0, NULL, NULL), "Run pre-processing kernel");

	// Set parameters and execute kernel
	assert(saved_salt.type >= 0 && saved_salt.type < (ARGON2_NUM_TYPES + 1) && kernels[Argon2_d] && kernels[Argon2_i]);

	cl_uint argon2_type = saved_salt.type;
	if (saved_salt.type == Argon2_id) {
		// We use the two kernels => initialize both OpenCL kernel params
		HANDLE_CLERROR(clSetKernelArg(kernels[Argon2_d], 1, sizeof(passes), &passes), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[Argon2_d], 2, sizeof(lanes), &lanes), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[Argon2_d], 3, sizeof(segment_blocks), &segment_blocks), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[Argon2_d], 6, sizeof(argon2_type), &argon2_type), "Error setting kernel argument");

		HANDLE_CLERROR(clSetKernelArg(kernels[Argon2_i], 1, sizeof(passes), &passes), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[Argon2_i], 2, sizeof(lanes), &lanes), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[Argon2_i], 3, sizeof(segment_blocks), &segment_blocks), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[Argon2_i], 6, sizeof(argon2_type), &argon2_type), "Error setting kernel argument");

		for (pass = 0; pass < passes; pass++)
		for (slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
			// Select the type
			int selected_type = Argon2_d;
			if (pass == 0 && slice < ARGON2_SYNC_POINTS / 2)
					selected_type = Argon2_i;

			// Find the autotune params
			uint32_t index = index_best_kernel_params(selected_type, saved_salt.lanes, MAX(saved_salt.m_cost / (saved_salt.lanes * ARGON2_SYNC_POINTS), 2));
			uint32_t lanes_per_block = best_kernel_params[index].lanes_per_block;
			size_t jobs_per_block	= best_kernel_params[index].jobs_per_block;
			assert(lanes_per_block && jobs_per_block &&
				lanes_per_block <= lanes && lanes % lanes_per_block == 0 &&
				jobs_per_block <= MAX_KEYS_PER_CRYPT && MAX_KEYS_PER_CRYPT % jobs_per_block == 0);

			size_t global_range[2] = { THREADS_PER_LANE * lanes, (count + jobs_per_block - 1) / jobs_per_block * jobs_per_block };
			size_t local_range[2] = { THREADS_PER_LANE * lanes_per_block, jobs_per_block };

			if (DEVICE_USE_LOCAL_MEMORY) {
				size_t shmemSize = THREADS_PER_LANE * lanes_per_block * jobs_per_block * sizeof(cl_ulong);
				HANDLE_CLERROR(clSetKernelArg(kernels[selected_type], 7, shmemSize, NULL), "Error setting kernel argument");
			}
			HANDLE_CLERROR(clSetKernelArg(kernels[selected_type], 4, sizeof(pass), &pass), "Error setting kernel argument");
			HANDLE_CLERROR(clSetKernelArg(kernels[selected_type], 5, sizeof(slice), &slice), "Error setting kernel argument");
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], kernels[selected_type], 2, NULL, global_range, local_range, 0, NULL, NULL), "Run loop kernel");
			HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush");
			opencl_process_event();
		}
	} else { // Argon2_d || Argon2_i
		// Find the autotune params
		uint32_t index = index_best_kernel_params(argon2_type, saved_salt.lanes, MAX(saved_salt.m_cost / (saved_salt.lanes * ARGON2_SYNC_POINTS), 2));
		uint32_t lanes_per_block = best_kernel_params[index].lanes_per_block;
		size_t jobs_per_block	= best_kernel_params[index].jobs_per_block;
		assert(lanes_per_block && jobs_per_block &&
			lanes_per_block <= lanes && lanes % lanes_per_block == 0 &&
			jobs_per_block <= MAX_KEYS_PER_CRYPT && MAX_KEYS_PER_CRYPT % jobs_per_block == 0);

		size_t global_range[2] = { THREADS_PER_LANE * lanes, (count + jobs_per_block - 1) / jobs_per_block * jobs_per_block };
		size_t local_range[2] = { THREADS_PER_LANE * lanes_per_block, jobs_per_block };

		if (DEVICE_USE_LOCAL_MEMORY) {
			size_t shmemSize = THREADS_PER_LANE * lanes_per_block * jobs_per_block * sizeof(cl_ulong);
			HANDLE_CLERROR(clSetKernelArg(kernels[argon2_type], 7, shmemSize, NULL), "Error setting kernel argument");
		}
		HANDLE_CLERROR(clSetKernelArg(kernels[argon2_type], 1, sizeof(passes), &passes), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[argon2_type], 2, sizeof(lanes), &lanes), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[argon2_type], 3, sizeof(segment_blocks), &segment_blocks), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[argon2_type], 6, sizeof(argon2_type), &argon2_type), "Error setting kernel argument");

		for (pass = 0; pass < passes; pass++)
		for (slice = 0; slice < ARGON2_SYNC_POINTS; slice++) {
			HANDLE_CLERROR(clSetKernelArg(kernels[argon2_type], 4, sizeof(pass), &pass), "Error setting kernel argument");
			HANDLE_CLERROR(clSetKernelArg(kernels[argon2_type], 5, sizeof(slice), &slice), "Error setting kernel argument");
			BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], kernels[argon2_type], 2, NULL, global_range, local_range, 0, NULL, NULL), "Run loop kernel");
			HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush");
			opencl_process_event();
		}
	}

	// Copy data from GPU
	size_t copySize = saved_salt.lanes * ARGON2_BLOCK_SIZE;
	size_t zero3[3] = {0, 0, 0};
	size_t buffer_origin3[3] = {jobSize - copySize, 0, 0};
	size_t region3_out[3] = {copySize, MAX_KEYS_PER_CRYPT, 1};
	HANDLE_CLERROR(clEnqueueReadBufferRect(queue[gpu_id], memory_buffer, CL_TRUE,
		buffer_origin3, zero3,
		region3_out,
		jobSize, 0, copySize, 0, blocks_in_out, 0, NULL, NULL), "Copy data from gpu");

	return 0;
}

static void init(struct fmt_main *self)
{
	argon2_self = self;
	assert(gpu_id < MAX_GPU_DEVICES);
	opencl_prepare_dev(gpu_id);
}

static void done(void)
{
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(crypted);

	MEM_FREE(blocks_in_out);
	MEM_FREE(best_kernel_params);

	// Release OpenCL resources
	assert(gpu_id >= 0 && gpu_id < MAX_GPU_DEVICES);
	if (program[gpu_id]) {
		// Release kernels
		int i;
		for (i = 0; i < ARGON2_NUM_TYPES; i++) {
			assert(kernels[i]);
			HANDLE_CLERROR(clReleaseKernel(kernels[i]), "Release kernel");
			kernels[i] = NULL;
		}

		assert(pre_processing_kernel);
		HANDLE_CLERROR(clReleaseKernel(pre_processing_kernel), "Release pre-processing kernel");
		pre_processing_kernel = NULL;

		if (argon2_self == &fmt_opencl_keepass_argon2) {
			if (keepass_outbuffer) {
				RELEASEBUFFER(cl_keepass_in);
				RELEASEBUFFER(cl_keepass_salt);
				RELEASEBUFFER(cl_keepass_state);
				RELEASEBUFFER(cl_keepass_out);

				MEM_FREE(keepass_inbuffer);
				MEM_FREE(keepass_statebuffer);
				MEM_FREE(keepass_outbuffer);
			}

			HANDLE_CLERROR(clReleaseKernel(keepass_init), "Release kernel");
			//HANDLE_CLERROR(clReleaseKernel(keepass_argon2), "Release kernel");
			HANDLE_CLERROR(clReleaseKernel(keepass_final), "Release kernel");
		}

		// Release program
		clReleaseProgram(program[gpu_id]);
		program[gpu_id] = NULL;
	}

	// Release memory
	if (memory_buffer) {
		HANDLE_CLERROR(clReleaseMemObject(memory_buffer), "Release GPU memory");
		memory_buffer = NULL;
	}

	if (memory_in) {
		HANDLE_CLERROR(clReleaseMemObject(memory_in), "Release GPU memory");
		memory_in = NULL;
	}
}

// Autotune
/// @brief Check if the param is a power of two
/// @param x Should be > 0
static int is_power_of_two(uint32_t x)
{
	return (x & (x - 1)) == 0;
}

#define AUTOTUNE_HANDLE_CLERROR(cl_error, message) if (CL_SUCCESS != (cl_error)) return CL_OUT_OF_RESOURCES;

static cl_int autotune(argon2_type type, uint32_t lanes, uint32_t segment_blocks, cl_command_queue profiling_queue, cl_event* profiling_event)
{
	uint32_t index = index_best_kernel_params(type, lanes, segment_blocks);
	// If not, initialize
	if (best_kernel_params[index].lanes_per_block)
		return CL_SUCCESS;

	cl_ulong start_time, end_time, best_time = 0;
	uint32_t best_lanes_per_block = 1, best_jobs_per_block = 1, lpb, jpb;
	size_t global_range[2] = {THREADS_PER_LANE * lanes, MAX_KEYS_PER_CRYPT};
	HANDLE_CLERROR(clSetKernelArg(kernels[type], 2, sizeof(lanes), &lanes), "Error setting kernel argument");
	HANDLE_CLERROR(clSetKernelArg(kernels[type], 3, sizeof(segment_blocks), &segment_blocks), "Error setting kernel argument");

	assert(profiling_queue && profiling_event);

	uint32_t lws_multiple = get_kernel_preferred_multiple(gpu_id, kernels[type]);

	// If the device ask for a bigger LWS => try to give it to them
	if (THREADS_PER_LANE * best_lanes_per_block * best_jobs_per_block < lws_multiple) {
		best_lanes_per_block = lws_multiple / THREADS_PER_LANE / best_jobs_per_block;
		if (best_lanes_per_block > lanes || lanes % best_lanes_per_block != 0)
			best_lanes_per_block = lanes;
	}
	while (THREADS_PER_LANE * best_lanes_per_block * best_jobs_per_block < lws_multiple && MAX_KEYS_PER_CRYPT % (best_jobs_per_block * 2) == 0)
		best_jobs_per_block *= 2;
	while (is_power_of_two(lws_multiple) && (THREADS_PER_LANE * best_lanes_per_block * best_jobs_per_block) % lws_multiple != 0 && MAX_KEYS_PER_CRYPT % (best_jobs_per_block * 2) == 0)
		best_jobs_per_block *= 2;
	if (best_jobs_per_block > MAX_KEYS_PER_CRYPT)
		best_jobs_per_block = MAX_KEYS_PER_CRYPT;

	// Get basic kernel execution time
	{
		size_t local_range[2] = {THREADS_PER_LANE * best_lanes_per_block, best_jobs_per_block};
		if (DEVICE_USE_LOCAL_MEMORY) {
			size_t shmemSize = THREADS_PER_LANE * best_lanes_per_block * best_jobs_per_block * sizeof(cl_ulong);
			if (shmemSize > get_local_memory_size(gpu_id))
				printf("-- Overflowing %u KiB / %u KiB local device memory --\n",
					(uint32_t)(shmemSize / 1024),
					(uint32_t)(get_local_memory_size(gpu_id) / 1024));

			AUTOTUNE_HANDLE_CLERROR(clSetKernelArg(kernels[type], 7, shmemSize, NULL), "Error setting local memory size");
		}

		// Warm-up
		AUTOTUNE_HANDLE_CLERROR(clEnqueueNDRangeKernel(profiling_queue, kernels[type], 2, NULL, global_range, local_range, 0, NULL, NULL), "Error on kernel");
		AUTOTUNE_HANDLE_CLERROR(clFinish(profiling_queue), "Error profiling clFinish");

		// Profile
		AUTOTUNE_HANDLE_CLERROR(clEnqueueNDRangeKernel(profiling_queue, kernels[type], 2, NULL, global_range, local_range, 0, NULL, profiling_event), "Error on kernel");
		AUTOTUNE_HANDLE_CLERROR(clFinish(profiling_queue), "Error profiling clFinish");

		HANDLE_CLERROR(clGetEventProfilingInfo(*profiling_event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &start_time, NULL), "clGetEventProfilingInfo start");
		HANDLE_CLERROR(clGetEventProfilingInfo(*profiling_event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &end_time, NULL), "clGetEventProfilingInfo end");
		best_time = end_time - start_time;
	}

	// Optimize 'lanes_per_block'
	if (lanes > 1 && is_power_of_two(lanes))
	for (lpb = best_lanes_per_block; lpb <= lanes; lpb *= 2) {
		size_t local_range[2] = {THREADS_PER_LANE * lpb, best_jobs_per_block};

		if (DEVICE_USE_LOCAL_MEMORY) {
			size_t shmemSize = THREADS_PER_LANE * lpb * best_jobs_per_block * sizeof(cl_ulong);

			if (CL_SUCCESS != clSetKernelArg(kernels[type], 7, shmemSize, NULL))
				break;
		}

		// Warm-up
		if (CL_SUCCESS != clEnqueueNDRangeKernel(profiling_queue, kernels[type], 2, NULL, global_range, local_range, 0, NULL, NULL))
			break;
		if (CL_SUCCESS != clFinish(profiling_queue))
			break;

		// Profile
		if (CL_SUCCESS != clEnqueueNDRangeKernel(profiling_queue, kernels[type], 2, NULL, global_range, local_range, 0, NULL, profiling_event))
			break;
		if (CL_SUCCESS != clFinish(profiling_queue))
			break;

		HANDLE_CLERROR(clGetEventProfilingInfo(*profiling_event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &start_time, NULL), "clGetEventProfilingInfo start");
		HANDLE_CLERROR(clGetEventProfilingInfo(*profiling_event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &end_time, NULL), "clGetEventProfilingInfo end");

		// Select best params
		cl_ulong time = end_time - start_time;
		if (best_time > time) {
			best_time = time;
			best_lanes_per_block = lpb;
		}
	}

	// Optimize 'jobs_per_block'
	// Only tune jobs per block if we hit maximum lanes per block
	if (best_lanes_per_block == lanes && MAX_KEYS_PER_CRYPT > 1)
	for (jpb = best_jobs_per_block; jpb <= MAX_KEYS_PER_CRYPT && MAX_KEYS_PER_CRYPT % jpb == 0; jpb *= 2) {
		size_t local_range[2] = {THREADS_PER_LANE * best_lanes_per_block, jpb};

		if (DEVICE_USE_LOCAL_MEMORY) {
			size_t shmemSize = THREADS_PER_LANE * best_lanes_per_block * jpb * sizeof(cl_ulong);
			if (CL_SUCCESS != clSetKernelArg(kernels[type], 7, shmemSize, NULL))
				break;
		}

		// Warm-up
		if (CL_SUCCESS != clEnqueueNDRangeKernel(profiling_queue, kernels[type], 2, NULL, global_range, local_range, 0, NULL, NULL))
			break;
		if (CL_SUCCESS != clFinish(profiling_queue))
			break;

		// Profile
		if (CL_SUCCESS != clEnqueueNDRangeKernel(profiling_queue, kernels[type], 2, NULL, global_range, local_range, 0, NULL, profiling_event))
			break;
		if (CL_SUCCESS != clFinish(profiling_queue))
			break;

		HANDLE_CLERROR(clGetEventProfilingInfo(*profiling_event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &start_time, NULL), "clGetEventProfilingInfo start");
		HANDLE_CLERROR(clGetEventProfilingInfo(*profiling_event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &end_time, NULL), "clGetEventProfilingInfo end");

		// Select best params
		cl_ulong time = end_time - start_time;
		if (best_time > time) {
			best_time = time;
			best_jobs_per_block = jpb;
		}
	}

	if (best_lanes_per_block != lanes && lanes > 1 && MAX_KEYS_PER_CRYPT > 1)
	for (jpb = best_jobs_per_block; jpb <= MAX_KEYS_PER_CRYPT && MAX_KEYS_PER_CRYPT % jpb == 0; jpb *= 2) {
		size_t local_range[2] = {THREADS_PER_LANE * lanes, jpb};

		if (DEVICE_USE_LOCAL_MEMORY) {
			size_t shmemSize = THREADS_PER_LANE * lanes * jpb * sizeof(cl_ulong);
			if (CL_SUCCESS != clSetKernelArg(kernels[type], 7, shmemSize, NULL))
				break;
		}

		// Warm-up
		if (CL_SUCCESS != clEnqueueNDRangeKernel(profiling_queue, kernels[type], 2, NULL, global_range, local_range, 0, NULL, NULL))
			break;
		if (CL_SUCCESS != clFinish(profiling_queue))
			break;

		// Profile
		if (CL_SUCCESS != clEnqueueNDRangeKernel(profiling_queue, kernels[type], 2, NULL, global_range, local_range, 0, NULL, profiling_event))
			break;
		if (CL_SUCCESS != clFinish(profiling_queue))
			break;

		HANDLE_CLERROR(clGetEventProfilingInfo(*profiling_event, CL_PROFILING_COMMAND_START, sizeof(cl_ulong), &start_time, NULL), "clGetEventProfilingInfo start");
		HANDLE_CLERROR(clGetEventProfilingInfo(*profiling_event, CL_PROFILING_COMMAND_END, sizeof(cl_ulong), &end_time, NULL), "clGetEventProfilingInfo end");

		// Select best params
		cl_ulong time = end_time - start_time;
		if (best_time > time) {
			best_time = time;
			best_jobs_per_block = jpb;
			best_lanes_per_block = lanes;
		}
	}

	// Save results
	best_kernel_params[index].lanes_per_block = best_lanes_per_block;
	best_kernel_params[index].jobs_per_block = best_jobs_per_block;

	if (best_time > 200000000ull) { // 200ms
		// Reduce MAX_KEYS_PER_CRYPT. This may not be needed
		//MAX_KEYS_PER_CRYPT = MAX(1, MAX_KEYS_PER_CRYPT * 200000000ull / best_time);
		//printf("Slow kernel %u ms MAX_KEYS_PER_CRYPT = %u\n", (uint32_t)(best_time / 1000000), MAX_KEYS_PER_CRYPT);
		// TODO: Need to change 'best_jobs_per_block' to a multiple of MAX_KEYS_PER_CRYPT for all
		//best_kernel_params[index].best_jobs_per_block = best_jobs_per_block = 1;
	}

	if (options.verbosity > VERB_LEGACY)
		printf("Autotune [type: %u, lanes: %u, segments: %u => (%u, %2u) => %02u ms] LWS: %3u Requested-Multiple:%3u\n",
			type, lanes, segment_blocks, best_lanes_per_block, best_jobs_per_block,
			(uint32_t)(best_time / 1000000),
			THREADS_PER_LANE * best_lanes_per_block * best_jobs_per_block, lws_multiple);

	return CL_SUCCESS;
}

static void reset(struct db_main *db)
{
	int i;

	assert(gpu_id >= 0 && gpu_id < MAX_GPU_DEVICES && db);

	// Select mode of operation
	uint32_t sm_version;
	get_compute_capability(gpu_id, &sm_version, NULL);
#ifdef __APPLE__
	DEVICE_USE_LOCAL_MEMORY = 1;
#else
	DEVICE_USE_LOCAL_MEMORY = !(gpu_nvidia(device_info[gpu_id]) && sm_version >= 3);
#endif

	// Find [max/min]_lanes and max_memory_size
	max_salt_lanes = 0;
	uint32_t min_salt_lanes = UINT32_MAX;
	max_segment_blocks = 0;
	size_t max_memory_size = 0;

	// Iterate on all salts
	struct db_salt *curr_salt = db->salts;
	for (i = 0; i < db->salt_count; i++) {
		assert(curr_salt && curr_salt->salt);
		struct argon2_salt *salt = (struct argon2_salt *)curr_salt->salt;

		uint32_t segment_blocks = MAX(salt->m_cost / (salt->lanes * ARGON2_SYNC_POINTS), 2);
		if (max_segment_blocks < segment_blocks)
			max_segment_blocks = segment_blocks;

		size_t memory_size = ((size_t)segment_blocks) * ARGON2_SYNC_POINTS * salt->lanes * ARGON2_BLOCK_SIZE;
		if (max_salt_lanes < salt->lanes)
			max_salt_lanes = salt->lanes;
		if (min_salt_lanes > salt->lanes)
			min_salt_lanes = salt->lanes;
		if (max_memory_size < memory_size)
			max_memory_size = memory_size;

		curr_salt = curr_salt->next;
	}

	assert(max_salt_lanes > 0 && min_salt_lanes > 0 && max_memory_size > 0);

	//----------------------------------------------------------------------------------------------------------------------------
	// Create OpenCL objects
	//----------------------------------------------------------------------------------------------------------------------------
	// Use almost all GPU memory by default
	unsigned int warps = 6, limit, target;
	if (gpu_amd(device_info[gpu_id])) {
		limit = get_max_mem_alloc_size(gpu_id) / max_memory_size;
	} else {
		if (gpu_nvidia(device_info[gpu_id])) {
			unsigned int major = 0, minor = 0;
			get_compute_capability(gpu_id, &major, &minor);
			if (major == 5) /* NVIDIA Maxwell */
				warps = 2;
		}
		limit = get_global_memory_size(gpu_id) * 31 / 32 / (max_memory_size + ARGON2_PREHASH_DIGEST_LENGTH);
	}
	unsigned int cores = get_processors_count(gpu_id);
	unsigned int threads_per_crypt = THREADS_PER_LANE;
	if (!benchmark_running)
		threads_per_crypt *= max_salt_lanes;
	do {
		target = (cores * warps + threads_per_crypt - 1) / threads_per_crypt;
	} while (target > limit && --warps > 1);
	if (target > limit)
		target = limit;
	if (target > 16)
		target -= target & (target > 128 ? 3 : 1); // Make it even or multiple of 4
	MAX_KEYS_PER_CRYPT = target;
	// Load GWS from config/command line
	opencl_get_user_preferences(FORMAT_NAME);
	if (global_work_size && !self_test_running)
		MAX_KEYS_PER_CRYPT = MAX(1, global_work_size / threads_per_crypt);
	MEM_FREE(saved_key);
	MEM_FREE(saved_len);
	MEM_FREE(crypted);
	saved_key = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(*saved_key));
	saved_len = mem_calloc(MAX_KEYS_PER_CRYPT, sizeof(int));
	crypted = mem_calloc(MAX_KEYS_PER_CRYPT, BINARY_SIZE);
	max_memory_size *= MAX_KEYS_PER_CRYPT;

	// OpenCL kernels compilation and retrival
	if (!program[gpu_id]) {
		// Create and build OpenCL kernels
		char build_opts[96];
		snprintf(build_opts, sizeof(build_opts), "-DUSE_WARP_SHUFFLE=%i", !DEVICE_USE_LOCAL_MEMORY); // Develop Nvidia: "-cl-nv-verbose -nv-line-info -cl-nv-maxrregcount=56"
		opencl_init("$JOHN/opencl/argon2_kernel.cl", gpu_id, build_opts);

		// Select OpenCL kernel
		char kernel_name[32];
		for (i = 0; i < ARGON2_NUM_TYPES; i++) {
			snprintf(kernel_name, sizeof(kernel_name), "argon2_kernel_segment_%i", i);
			assert(!kernels[i]);
			kernels[i] = clCreateKernel(program[gpu_id], kernel_name, &ret_code);
			HANDLE_CLERROR(ret_code, "Error creating kernel");
		}

		pre_processing_kernel = clCreateKernel(program[gpu_id], "pre_processing", &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating pre-processing kernel");

		if (argon2_self == &fmt_opencl_keepass_argon2) {
			size_t ret =
				snprintf(build_opts, sizeof(build_opts),
				         "-DKEEPASS_ARGON2 -DPLAINTEXT_LENGTH=%d -DMAX_CONTENT_SIZE=%d",
				         KEEPASS_PLAINTEXT_LENGTH, KEEPASS_MAX_CONTENT_SIZE);
			assert(ret < sizeof(build_opts));

			opencl_init("$JOHN/opencl/keepass_kernel.cl", gpu_id,  build_opts);

			CREATEKERNEL(keepass_init, "keepass_init");
			//CREATEKERNEL(keepass_argon2, "keepass_argon2");
			CREATEKERNEL(keepass_final, "keepass_final");
		}
	}

	assert(program[gpu_id] && kernels[Argon2_d] && kernels[Argon2_i] && pre_processing_kernel);

	//-----------------------------------------------------------------------------------------------------------
	// Autotune
	//-----------------------------------------------------------------------------------------------------------

	// Set common params
	uint32_t ZERO = 0;
	uint32_t PASSES = 1;
	for (i = 0; i < ARGON2_NUM_TYPES; i++) {
		// Set OpenCL kernel parameters
		HANDLE_CLERROR(clSetKernelArg(kernels[i], 1, sizeof(PASSES), &PASSES), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[i], 4, sizeof(ZERO), &ZERO), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[i], 5, sizeof(ZERO), &ZERO), "Error setting kernel argument");
		HANDLE_CLERROR(clSetKernelArg(kernels[i], 6, sizeof(PASSES), &PASSES), "Error setting kernel argument");
	}

	// Create OpenCL profiling objects
	cl_command_queue profiling_queue = clCreateCommandQueue(context[gpu_id], devices[gpu_id], CL_QUEUE_PROFILING_ENABLE, &ret_code);
	HANDLE_CLERROR(ret_code, "clCreateCommandQueue profiling");
	cl_event profiling_event = clCreateUserEvent(context[gpu_id], &ret_code);
	HANDLE_CLERROR(ret_code, "clCreateUserEvent profiling");

	// Autotune saved params
	MEM_FREE(best_kernel_params);
	best_kernel_params = mem_calloc(ARGON2_NUM_TYPES * max_salt_lanes * max_segment_blocks, sizeof(struct kernel_run_params));

	// Manage GPU memory
	int need_linefeed = benchmark_running;
	do {
		// CPU memory to transfer to and from the GPU
		if (memory_in) {
			HANDLE_CLERROR(clReleaseMemObject(memory_in), "Release GPU memory");
			memory_in = NULL;
		}
		memory_in = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, MAX_KEYS_PER_CRYPT * ARGON2_PREHASH_DIGEST_LENGTH, NULL, &ret_code);
		HANDLE_CLERROR(ret_code, "Error creating memory buffer");

		MEM_FREE(blocks_in_out);
		blocks_in_out = mem_calloc_align(MAX_KEYS_PER_CRYPT * max_salt_lanes * ARGON2_BLOCK_SIZE, sizeof(uint8_t), MEM_ALIGN_PAGE);

		// Create main GPU memory
		if (memory_buffer) {
			HANDLE_CLERROR(clReleaseMemObject(memory_buffer), "Release GPU memory");
			memory_buffer = NULL;
		}
		memory_buffer = clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, max_memory_size, NULL, &ret_code);
		if (ocl_always_show_ws || !self_test_running) {
			printf("%sTrying to compute %u hashes at a time using %u of %u MiB device memory\n",
				need_linefeed ? "\n" : "",
				MAX_KEYS_PER_CRYPT,
				(unsigned int)(max_memory_size / 0x100000),
				(uint32_t)(get_global_memory_size(gpu_id) / 0x100000));
			need_linefeed = 0;
		}

		// Check kernel execution
		if (ret_code == CL_SUCCESS) {
			// Set OpenCL kernel parameters
			for (i = 0; i < ARGON2_NUM_TYPES; i++)
				HANDLE_CLERROR(clSetKernelArg(kernels[i], 0, sizeof(memory_buffer), &memory_buffer), "Error setting kernel argument");
			// Pre-processing kernel
			HANDLE_CLERROR(clSetKernelArg(pre_processing_kernel, 0, sizeof(memory_in), &memory_in), "Error setting kernel argument");
			HANDLE_CLERROR(clSetKernelArg(pre_processing_kernel, 1, sizeof(memory_buffer), &memory_buffer), "Error setting kernel argument");

			ret_code = autotune(Argon2_i, 1, max_segment_blocks, profiling_queue, &profiling_event);
		}

		// Something like this reduce too much performance on Nvidia: get_max_mem_alloc_size(gpu_id)
		// The best option is to try and try again
		if (ret_code != CL_SUCCESS) {
			max_memory_size /= 2;
			MAX_KEYS_PER_CRYPT /= 2;
		}
	} while (ret_code != CL_SUCCESS);

	assert(MAX_KEYS_PER_CRYPT >= 1);
	assert(blocks_in_out && memory_buffer && memory_in);

	// Iterate on all salts and autotuned for each one
	curr_salt = db->salts;
	for (i = 0; i < db->salt_count; i++) {
		struct argon2_salt *salt = (struct argon2_salt *)curr_salt->salt;

		// LWS was given on command-line/config
		if (local_work_size && !self_test_running) {
			uint32_t segment_blocks = MAX(salt->m_cost / (salt->lanes * ARGON2_SYNC_POINTS), 2);
			uint32_t index_d = index_best_kernel_params(Argon2_d, salt->lanes, segment_blocks);
			uint32_t index_i = index_best_kernel_params(Argon2_i, salt->lanes, segment_blocks);

			best_kernel_params[index_d].lanes_per_block =
				best_kernel_params[index_d].jobs_per_block =
				best_kernel_params[index_i].lanes_per_block =
				best_kernel_params[index_i].jobs_per_block = 1;

			// Multiple cases
			if (local_work_size > THREADS_PER_LANE) {
				uint32_t lanes_per_block = MIN(salt->lanes, local_work_size / THREADS_PER_LANE);

				// Become a multiple of salt->lanes
				if (salt->lanes % lanes_per_block != 0)
					lanes_per_block = salt->lanes;

				best_kernel_params[index_d].lanes_per_block =
				best_kernel_params[index_i].lanes_per_block = lanes_per_block;

				if (local_work_size > THREADS_PER_LANE * lanes_per_block)
					best_kernel_params[index_d].jobs_per_block =
						best_kernel_params[index_i].jobs_per_block = MAX(1, local_work_size / THREADS_PER_LANE / salt->lanes);
			}
		} else { // Autotune
			// Special case that use both kernels
			if (salt->type == Argon2_id) {
				autotune(Argon2_d, salt->lanes, MAX(salt->m_cost / (salt->lanes * ARGON2_SYNC_POINTS), 2), profiling_queue, &profiling_event);
				autotune(Argon2_i, salt->lanes, MAX(salt->m_cost / (salt->lanes * ARGON2_SYNC_POINTS), 2), profiling_queue, &profiling_event);
			} else {
				autotune(salt->type, salt->lanes, MAX(salt->m_cost / (salt->lanes * ARGON2_SYNC_POINTS), 2), profiling_queue, &profiling_event);
			}
		}

		curr_salt = curr_salt->next;
	}

	// Release profiling objects
	HANDLE_CLERROR(clReleaseCommandQueue(profiling_queue), "Releasing Profiling CommandQueue");
	clReleaseEvent(profiling_event);

	// Report LWS/GWS
	if (ocl_always_show_ws || !self_test_running) {
		// Finding min/max LWS
		size_t min_local_work_size = SIZE_MAX;
		size_t max_local_work_size = 0;
		for (i = 0; i < ARGON2_NUM_TYPES * max_salt_lanes * max_segment_blocks; i++)
		if (best_kernel_params[i].jobs_per_block > 0 && best_kernel_params[i].lanes_per_block > 0) {
			size_t current_lws = THREADS_PER_LANE * best_kernel_params[i].lanes_per_block * best_kernel_params[i].jobs_per_block;
			if (min_local_work_size > current_lws)
				min_local_work_size = current_lws;
			if (max_local_work_size < current_lws)
				max_local_work_size = current_lws;
		}

		// GWS
		size_t min_global_work_size = THREADS_PER_LANE * min_salt_lanes * MAX_KEYS_PER_CRYPT;
		size_t max_global_work_size = THREADS_PER_LANE * max_salt_lanes * MAX_KEYS_PER_CRYPT;

		// Report GWS/LWS
		if (min_global_work_size == max_global_work_size && min_local_work_size == max_local_work_size)
			printf("LWS="Zu" GWS="Zu" ("Zu" blocks) => Mode: %s\n",
				min_local_work_size, min_global_work_size,
				min_global_work_size / max_local_work_size,
				DEVICE_USE_LOCAL_MEMORY ? "LOCAL_MEMORY" : "WARP_SHUFFLE");
		else
			printf("LWS=["Zu"-"Zu"] GWS=["Zu"-"Zu"] (["Zu"-"Zu"] blocks) => Mode: %s\n",
				min_local_work_size, max_local_work_size,
				min_global_work_size, max_global_work_size,
				// TODO: consider an exact calculation here instead of this approximation
				min_global_work_size / max_local_work_size, max_global_work_size / min_local_work_size,
				DEVICE_USE_LOCAL_MEMORY ? "LOCAL_MEMORY" : "WARP_SHUFFLE");
	}

	if (argon2_self == &fmt_opencl_keepass_argon2) {
		keepass_statesize = sizeof(kp_state_t) * MAX_KEYS_PER_CRYPT;
		keepass_insize = sizeof(kp_password_t) * MAX_KEYS_PER_CRYPT;
		keepass_outsize = sizeof(kp_result_t) * MAX_KEYS_PER_CRYPT;

		keepass_inbuffer = mem_calloc(1, keepass_insize);
		keepass_statebuffer = mem_alloc(keepass_statesize);
		keepass_outbuffer = mem_alloc(keepass_outsize);

		CLCREATEBUFFER(cl_keepass_in, CL_RO, keepass_insize);
		CLCREATEBUFFER(cl_keepass_salt, CL_RO, sizeof(keepass_salt_t));
		CLCREATEBUFFER(cl_keepass_state, CL_RW, keepass_statesize);
		CLCREATEBUFFER(cl_keepass_out, CL_WO, keepass_outsize);

		// Set kernel args
		CLKERNELARG(keepass_init, 0, cl_keepass_in);
		CLKERNELARG(keepass_init, 1, cl_keepass_salt);
		CLKERNELARG(keepass_init, 2, cl_keepass_state);

		//CLKERNELARG(keepass_argon2, 0, cl_keepass_state);
		//CLKERNELARG(keepass_argon2, 1, cl_keepass_salt);

		CLKERNELARG(keepass_final, 0, cl_keepass_state);
		CLKERNELARG(keepass_final, 1, cl_keepass_salt);
		CLKERNELARG(keepass_final, 2, cl_keepass_out);
	}
}

// Ciphertext management
static void ctx_init(argon2_context *ctx)
{
	static uint8_t out[BINARY_SIZE];
	static uint8_t salt[SALT_SIZE];

	memset(ctx, 0, sizeof(*ctx));
	ctx->out = out;
	ctx->outlen = sizeof(out);
	ctx->salt = salt;
	ctx->saltlen = sizeof(salt);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	argon2_context ctx;
	int res;

	ctx_init(&ctx);

	if (!strncmp(ciphertext, FORMAT_TAG_d, sizeof(FORMAT_TAG_d)-1))
		res = argon2_decode_string(&ctx, ciphertext, Argon2_d);
	else if (!strncmp(ciphertext, FORMAT_TAG_id, sizeof(FORMAT_TAG_id)-1))
		res = argon2_decode_string(&ctx, ciphertext, Argon2_id);
	else if (!strncmp(ciphertext, FORMAT_TAG_i, sizeof(FORMAT_TAG_i)-1))
		res = argon2_decode_string(&ctx, ciphertext, Argon2_i);
	else
		return 0;

	if (res != ARGON2_OK || ctx.outlen < 8)
		return 0;

	// TODO: Support ARGON2_VERSION_10
	if (ctx.version == ARGON2_VERSION_10) {
		printf("Format doesn't support ARGON2_VERSION_10\n");
		return 0;
	}

	return 1;
}

static void set_key(char *key, int index)
{
	assert(key);
	assert(index >= 0 && index < MAX_KEYS_PER_CRYPT);
	saved_len[index] = strnzcpyn(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	assert(index >= 0 && index < MAX_KEYS_PER_CRYPT);
	return saved_key[index];
}

static void kp_set_key(char *key, int index)
{
	uint32_t length = strlen(key);

	keepass_inbuffer[index].length = length;
	memcpy(keepass_inbuffer[index].v, key, length);
	new_keys = 1;
}

static char *kp_get_key(int index)
{
	static char ret[KEEPASS_PLAINTEXT_LENGTH + 1];
	uint32_t length = keepass_inbuffer[index].length;

	memcpy(ret, keepass_inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static void *get_binary(char *ciphertext)
{
	assert(ciphertext);

	static uint32_t out[(BINARY_SIZE + 3) / 4];
	argon2_context ctx;

	ctx_init(&ctx);

	if (!strncmp(ciphertext, FORMAT_TAG_d, sizeof(FORMAT_TAG_d)-1))
		argon2_decode_string(&ctx, ciphertext, Argon2_d);
	else if (!strncmp(ciphertext, FORMAT_TAG_id, sizeof(FORMAT_TAG_id)-1))
		argon2_decode_string(&ctx, ciphertext, Argon2_id);
	else
		argon2_decode_string(&ctx, ciphertext, Argon2_i);

	assert(ctx.outlen <= BINARY_SIZE);

	memset(out, 0, BINARY_SIZE);
	memcpy(out, ctx.out, ctx.outlen);

	return out;
}

static void *get_salt(char *ciphertext)
{
	assert(ciphertext);

	static struct argon2_salt salt;
	argon2_context ctx;

	memset(&salt, 0, sizeof(salt));

	ctx_init(&ctx);

	if (!strncmp(ciphertext, FORMAT_TAG_d, sizeof(FORMAT_TAG_d)-1)) {
		argon2_decode_string(&ctx, ciphertext, Argon2_d);
		salt.type = Argon2_d;
	} else if (!strncmp(ciphertext, FORMAT_TAG_id, sizeof(FORMAT_TAG_id)-1)) {
		argon2_decode_string(&ctx, ciphertext, Argon2_id);
		salt.type = Argon2_id;
	} else {
		argon2_decode_string(&ctx, ciphertext, Argon2_i);
		salt.type = Argon2_i;
	}

	assert(ctx.outlen <= BINARY_SIZE);
	assert(ctx.saltlen <= SALT_SIZE);
	assert(ctx.m_cost > 0 && ctx.t_cost > 0 && ctx.lanes > 0);

	salt.version = ctx.version;
	salt.salt_length = ctx.saltlen;
	salt.m_cost = ctx.m_cost;
	salt.t_cost = ctx.t_cost;
	salt.lanes = ctx.lanes;
	salt.hash_size = ctx.outlen;
	memcpy(salt.salt, ctx.salt, ctx.saltlen);

	return (void *)&salt;
}

static void set_salt(void *salt)
{
	assert(salt);
	memcpy(&saved_salt, salt, sizeof(struct argon2_salt));
}

static void kp_set_salt(void *salt)
{
	keepass_salt = salt;

	// The KeePass salt is piggy-backed on a plain Argon2 salt
	memcpy(&saved_salt, salt, sizeof(struct argon2_salt));

	CLWRITE(cl_keepass_salt, CL_FALSE, 0, sizeof(keepass_salt_t), keepass_salt, NULL);
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in keepass_set_salt()");
}

// Compare result hashes with db hashes
static int cmp_all(void *binary, int count)
{
	return 1;
}

static int cmp_one(void *binary, int index)
{
	assert(binary && index >=0 && index < MAX_KEYS_PER_CRYPT);
	return !memcmp(binary, crypted[index], saved_salt.hash_size);
}

static int kp_cmp_one(void *binary, int index)
{
	return keepass_outbuffer[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	assert(count > 0 && count <= MAX_KEYS_PER_CRYPT);
	struct argon2_salt* assert_salt = salt->salt;
	assert(salt && !memcmp(assert_salt, &saved_salt, sizeof(struct argon2_salt)));

	// Same context everywhere
	argon2_context context;
	context.out = (uint8_t *)NULL;
	context.secret = NULL;
	context.secretlen = 0;
	context.ad = NULL;
	context.adlen = 0;
	context.flags = ARGON2_DEFAULT_FLAGS;

	// Pre-processing on the CPU
	for (i = 0; i < count; i++) {
		// argon2_context initialization
		context.outlen = (uint32_t)saved_salt.hash_size;
		context.pwd = (uint8_t *)saved_key[i];
		context.pwdlen = (uint32_t)saved_len[i];
		context.salt = (uint8_t *)saved_salt.salt;
		context.saltlen = (uint32_t)saved_salt.salt_length;
		context.t_cost = saved_salt.t_cost;
		context.m_cost = saved_salt.m_cost;
		context.lanes = saved_salt.lanes;
		context.threads = saved_salt.lanes;
		context.version = saved_salt.version;

		/* 3. Initialization: Hashing inputs */
		uint8_t *blockhash = blocks_in_out + i * ARGON2_PREHASH_DIGEST_LENGTH;
		argon2_initial_hash(blockhash, &context, saved_salt.type);
	}

	// Run on the GPU
	run_kernel_on_gpu(count);

	// Post-processing on CPU
	// ProcessingUnit::getHash()
	// TODO: nicify this (or move it into the kernel (I mean, we currently have all lanes in one work-group...)
	for (i = 0; i < count; i++) {
		uint32_t l;
		size_t j;

		const block *cursor = (const block *)(blocks_in_out + i * saved_salt.lanes * ARGON2_BLOCK_SIZE);
		block xored = *cursor;
		for (l = 1; l < saved_salt.lanes; l++) {
			++cursor;
			for (j = 0; j < ARGON2_BLOCK_SIZE / 8; j++)
				xored.v[j] ^= cursor->v[j];
		}

		// TODO: Check if we need to save data as little-endian before this call
		blake2b_long(crypted[i], saved_salt.hash_size, &xored, ARGON2_BLOCK_SIZE);
	}

	return count;
}

static int kp_crypt_all(int *pcount, struct db_salt *salt)
{
	int i;
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;
	size_t gws = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy password candidates to gpu
	if (new_keys) {
		CLWRITE_CRYPT(cl_keepass_in, CL_FALSE, 0, keepass_insize, keepass_inbuffer, NULL);
		new_keys = 0;
	}

	// Run keepass init kernel to get keys for Argon2
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], keepass_init, 1, NULL, &gws, lws, 0, NULL, NULL),
	              "Run kernel");

	// Read keys back for host-side Argon2 pre-processing (duh!)
	CLREAD_CRYPT(cl_keepass_state, CL_TRUE, 0, keepass_statesize, keepass_statebuffer, NULL);

	// Pre-processing on CPU
	// Initialize common context
	argon2_context context = { .flags = ARGON2_DEFAULT_FLAGS, .outlen = 32, .pwdlen = 32, .saltlen = 32 };

	context.salt = keepass_salt->transf_randomseed;
	context.t_cost = keepass_salt->t_cost;
	context.m_cost = keepass_salt->m_cost;
	context.lanes = context.threads = keepass_salt->lanes;
	context.version = keepass_salt->version;

	/* Initialization: Hashing inputs */
	for (i = 0; i < count; i++) {
		uint8_t *blockhash = blocks_in_out + i * ARGON2_PREHASH_DIGEST_LENGTH;

		context.pwd = keepass_statebuffer[i].hash;
		argon2_initial_hash(blockhash, &context, keepass_salt->type);
	}

	// Run Argon2 on the GPU
	run_kernel_on_gpu(count);

	// Argon2 post-processing on CPU (duh!)
	for (i = 0; i < count; i++) {
		uint32_t l;
		size_t j;

		const block *cursor = (const block *)(blocks_in_out + i * keepass_salt->lanes * ARGON2_BLOCK_SIZE);
		block xored = *cursor;
		for (l = 1; l < keepass_salt->lanes; l++) {
			++cursor;
			for (j = 0; j < ARGON2_BLOCK_SIZE / 8; j++)
				xored.v[j] ^= cursor->v[j];
		}

		blake2b_long(keepass_statebuffer[i].hash, 32, &xored, ARGON2_BLOCK_SIZE);
	}

	// Push the completed Argon2 hashes back to GPU for final KeePass processing
	CLWRITE_CRYPT(cl_keepass_state, CL_FALSE, 0, keepass_statesize, keepass_statebuffer, NULL);

	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], keepass_final, 1, NULL, &gws, lws, 0, NULL, NULL),
	              "Run kernel");

	// Read the result back
	CLREAD_CRYPT(cl_keepass_out, CL_TRUE, 0, keepass_outsize, keepass_outbuffer, NULL);

	return count;
}

// Hash hash
#define COMMON_GET_HASH_VAR crypted
#include "common-get-hash.h"

static int salt_hash(void *_salt)
{
	uint32_t i;
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	unsigned int hash = 0;
	char *p = salt->salt;

	for (i = 0; i < salt->salt_length; i++) {
		hash <<= 1;
		hash += (unsigned char)*p++;
		if (hash >> SALT_HASH_LOG) {
			hash ^= hash >> SALT_HASH_LOG;
			hash &= (SALT_HASH_SIZE - 1);
		}
	}

	hash ^= hash >> SALT_HASH_LOG;
	hash &= (SALT_HASH_SIZE - 1);

	return hash;
}

// Tunable costs
#if FMT_MAIN_VERSION > 11
static unsigned int tunable_cost_t(void *_salt)
{
	assert(_salt);
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	return salt->t_cost;
}

static unsigned int tunable_cost_m(void *_salt)
{
	assert(_salt);
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	return salt->m_cost;
}

static unsigned int tunable_cost_p(void *_salt)
{
	assert(_salt);
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	return salt->lanes;
}

static unsigned int tunable_cost_type(void *_salt)
{
	assert(_salt);
	struct argon2_salt *salt = (struct argon2_salt *)_salt;
	return (int)salt->type;
}
#endif

struct fmt_main fmt_opencl_argon2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		sizeof(struct argon2_salt),
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT_ORIGINAL,
		FMT_CASE | FMT_8_BIT,
		{
			"t",
			"m",
			"p",
			"type [0:Argon2d 1:Argon2i 2:Argon2id]"
		},
		{0},
		tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			tunable_cost_t,
			tunable_cost_m,
			tunable_cost_p,
			tunable_cost_type,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash_0,
			fmt_default_binary_hash_1,
			fmt_default_binary_hash_2,
			fmt_default_binary_hash_3,
			fmt_default_binary_hash_4,
			fmt_default_binary_hash_5,
			fmt_default_binary_hash_6
		},
		salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

struct fmt_main fmt_opencl_keepass_argon2 = {
	{
		KP_ARGON_FORMAT_LABEL,
		KP_ARGON_FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
		KEEPASS_PLAINTEXT_LENGTH,
		KEEPASS_BINARY_SIZE,
		BINARY_ALIGN,
		KEEPASS_SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT_ORIGINAL,
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT,
		{
			"t",
			"m",
			"p",
			"KDF [0=Argon2d 2=Argon2id]",
		},
		{ KEEPASS_FORMAT_TAG },
		keepass_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		keepass_valid,
		fmt_default_split,
		fmt_default_binary,
		keepass_get_salt,
		{
			keepass_cost_t,
			keepass_cost_m,
			keepass_cost_p,
			keepass_kdf,
		},
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		kp_set_salt,
		kp_set_key,
		kp_get_key,
		fmt_default_clear_keys,
		kp_crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		kp_cmp_one,
		cmp_exact
	}
};

#endif	/* FMT_EXTERNS_H */
#endif	/* HAVE_OPENCL */
