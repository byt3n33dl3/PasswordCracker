/*
 * Format for cracking blockchain.info "My Wallet" format wallets. Hacked
 * together during June of 2013 by Dhiru Kholia <dhiru at openwall.com>.
 *
 * See https://blockchain.info/wallet/wallet-format

 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall.net>
 * and Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>, and it is
 * hereby released to the general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Improved detection, added iteration count and handle v2 hashes, Feb, 2015, JimF.
 */

#ifdef HAVE_OPENCL

#if FMT_EXTERNS_H
extern struct fmt_main fmt_opencl_blockchain;
#elif FMT_REGISTERS_H
john_register_one(&fmt_opencl_blockchain);
#else

#include <stdint.h>
#include <string.h>

#include "arch.h"
#include "formats.h"
#include "common.h"
#include "jumbo.h"
#include "opencl_common.h"
#include "options.h"
#include "blockchain_common.h"

#define FORMAT_LABEL            "blockchain-opencl"
#define FORMAT_NAME             "blockchain My Wallet"
#define ALGORITHM_NAME          "PBKDF2-SHA1 AES OpenCL"
#define BENCHMARK_COMMENT       " (v2 x5000)"
/*
 * We'd need to be benchmarking for Many vs. Only one salt if we move the v1
 * test vectors back to the start of the tests array.
 */
#define BENCHMARK_LENGTH        0x107
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      1
#define BINARY_SIZE             0
#define PLAINTEXT_LENGTH        64
#define SALT_SIZE               sizeof(struct custom_salt)
#define BINARY_ALIGN            MEM_ALIGN_WORD
#define SALT_ALIGN              4

/* PBKDF2 parameters */
#define KEYLEN  PLAINTEXT_LENGTH
#define OUTLEN  32
#define SALTLEN 64

typedef struct {
	uint32_t length;
	uint8_t  v[KEYLEN];
} pbkdf2_password;

typedef struct {
	uint32_t v[(OUTLEN+3)/4];
} pbkdf2_out;

typedef struct {
	uint32_t iterations;
	uint32_t outlen;
	uint32_t skip_bytes;
	uint8_t  length;
	uint8_t  salt[SALTLEN];
} pbkdf2_salt;

typedef struct {
	uint32_t cracked;
} blockchain_out;

typedef struct {
	pbkdf2_salt pbkdf2;
	uint8_t     data[SAFETY_FACTOR];
	uint32_t    length;
} blockchain_salt;

static struct custom_salt *cur_salt;

static cl_int cl_error;
static pbkdf2_password *inbuffer;
static blockchain_out *output;
static blockchain_salt currentsalt;
static cl_mem mem_in, mem_dk, mem_salt, mem_out;
static struct fmt_main *self;

static int new_keys;

static size_t insize, dksize, saltsize, outsize;

#define STEP			0
#define SEED			256

// This file contains auto-tuning routine(s). Has to be included after formats definitions.
#include "opencl_autotune.h"

static const char * warn[] = {
	"xfer: ",  ", crypt: ",  ", xfer: "
};

/* ------- Helper functions ------- */
static size_t get_task_max_work_group_size()
{
	return autotune_get_task_max_work_group_size(FALSE, 0, crypt_kernel);
}

static void release_clobj(void);

static void create_clobj(size_t gws, struct fmt_main *self)
{
	release_clobj();

	insize = sizeof(pbkdf2_password) * gws;
	dksize = sizeof(pbkdf2_out) * gws;
	saltsize = sizeof(blockchain_salt);
	outsize = sizeof(blockchain_out) * gws;

	inbuffer = mem_calloc(1, insize);
	output = mem_alloc(outsize);

	// Allocate memory
	mem_in =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, insize, NULL,
		&cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem in");
	mem_salt =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_ONLY, saltsize, NULL,
		&cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem salt");
	mem_dk =
		clCreateBuffer(context[gpu_id], CL_MEM_READ_WRITE, dksize, NULL,
		&cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating pbkdf2 out");
	mem_out =
		clCreateBuffer(context[gpu_id], CL_MEM_WRITE_ONLY, outsize, NULL,
		&cl_error);
	HANDLE_CLERROR(cl_error, "Error allocating mem out");

	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 0, sizeof(mem_in),
		&mem_in), "Error while setting mem_in kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 1, sizeof(mem_dk),
		&mem_dk), "Error while setting mem_dk kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 2, sizeof(mem_salt),
		&mem_salt), "Error while setting mem_salt kernel argument");
	HANDLE_CLERROR(clSetKernelArg(crypt_kernel, 3, sizeof(mem_out),
		&mem_out), "Error while setting mem_out kernel argument");
}

static void release_clobj(void)
{
	if (output) {
		HANDLE_CLERROR(clReleaseMemObject(mem_in), "Release mem in");
		HANDLE_CLERROR(clReleaseMemObject(mem_dk), "Release mem dk");
		HANDLE_CLERROR(clReleaseMemObject(mem_salt), "Release mem salt");
		HANDLE_CLERROR(clReleaseMemObject(mem_out), "Release mem out");

		MEM_FREE(inbuffer);
		MEM_FREE(output);
	}
}

static void done(void)
{
	if (program[gpu_id]) {
		release_clobj();

		HANDLE_CLERROR(clReleaseKernel(crypt_kernel), "Release kernel");
		HANDLE_CLERROR(clReleaseProgram(program[gpu_id]), "Release Program");

		program[gpu_id] = NULL;
	}
}

static void init(struct fmt_main *_self)
{
	self = _self;
	opencl_prepare_dev(gpu_id);
}

static void reset(struct db_main *db)
{
	if (!program[gpu_id]) {
		char build_opts[128];

		snprintf(build_opts, sizeof(build_opts),
		         "-DKEYLEN=%d -DSALTLEN=%d -DOUTLEN=%d -DSAFETY_FACTOR=%d",
		         PLAINTEXT_LENGTH, SALTLEN, OUTLEN, SAFETY_FACTOR);

		opencl_init("$JOHN/opencl/blockchain_kernel.cl", gpu_id, build_opts);

		crypt_kernel = clCreateKernel(program[gpu_id], "blockchain", &cl_error);
		HANDLE_CLERROR(cl_error, "Error creating kernel");
	}

	// Initialize openCL tuning (library) for this format.
	opencl_init_auto_setup(SEED, 0, NULL, warn, 1, self,
	                       create_clobj, release_clobj,
	                       sizeof(pbkdf2_password), 0, db);

	// Auto tune execution from shared/included code.
	autotune_run(self, 1, 0, 1000);
}

static void set_salt(void *salt)
{
	cur_salt = (struct custom_salt *)salt;

	memcpy((char*)currentsalt.pbkdf2.salt, cur_salt->data, 16);
	currentsalt.pbkdf2.length = 16;
	currentsalt.pbkdf2.iterations = cur_salt->iter;
	currentsalt.pbkdf2.outlen = 32;
	currentsalt.pbkdf2.skip_bytes = 0;

	memcpy((char*)currentsalt.data, cur_salt->data, SAFETY_FACTOR);
	HANDLE_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_salt,
		CL_FALSE, 0, saltsize, &currentsalt, 0, NULL, NULL),
	    "Salt transfer");
	HANDLE_CLERROR(clFlush(queue[gpu_id]), "clFlush failed in set_salt()");
}

static void set_key(char *key, int index)
{
	uint8_t length = strlen(key);

	inbuffer[index].length = length;
	memcpy(inbuffer[index].v, key, length);

	new_keys = 1;
}

static char *get_key(int index)
{
	static char ret[PLAINTEXT_LENGTH + 1];
	uint8_t length = inbuffer[index].length;

	memcpy(ret, inbuffer[index].v, length);
	ret[length] = '\0';
	return ret;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	size_t *lws = local_work_size ? &local_work_size : NULL;

	global_work_size = GET_NEXT_MULTIPLE(count, local_work_size);

	// Copy data to gpu
	if (new_keys) {
		BENCH_CLERROR(clEnqueueWriteBuffer(queue[gpu_id], mem_in, CL_FALSE, 0,
			insize, inbuffer, 0, NULL, multi_profilingEvent[0]),
				"Copy data to gpu");
		new_keys = 0;
	}

	// Run kernel
	BENCH_CLERROR(clEnqueueNDRangeKernel(queue[gpu_id], crypt_kernel, 1,
		NULL, &global_work_size, lws, 0, NULL,
	        multi_profilingEvent[1]), "Run kernel");

	// Read the result back
	BENCH_CLERROR(clEnqueueReadBuffer(queue[gpu_id], mem_out, CL_TRUE, 0,
		outsize, output, 0, NULL, multi_profilingEvent[2]), "Copy result back");

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (output[index].cracked)
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
	return output[index].cracked;
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

struct fmt_main fmt_opencl_blockchain = {
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
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_HUGE_INPUT,
/* FIXME: Should report iteration count as a tunable cost */
		{ NULL },
		{ FORMAT_TAG },
		blockchain_tests
	}, {
		init,
		done,
		reset,
		fmt_default_prepare,
		blockchain_common_valid,
		fmt_default_split,
		fmt_default_binary,
		blockchain_common_get_salt,
		{ NULL },
		fmt_default_source,
		{
			fmt_default_binary_hash
		},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			fmt_default_get_hash
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

#endif /* HAVE_OPENCL */
