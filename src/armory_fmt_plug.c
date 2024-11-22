/*
 * This file is part of John the Ripper password cracker,
 * Copyright (c) 2024 by Solar Designer
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * There's ABSOLUTELY NO WARRANTY, express or implied.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_armory;
#elif FMT_REGISTERS_H
john_register_one(&fmt_armory);
#else

#include <stdint.h>
#include <string.h>
#include <errno.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"
#include "johnswap.h"

#include "base64_convert.h"
#include "formats.h"
#include "loader.h"
#include "memory.h"
#include "crc32.h"
#include "sha2.h"
#include "aes.h"
#include "secp256k1.h"
#include "sph_ripemd.h"
#include "simd-intrinsics.h"

#define FORMAT_LABEL			"armory"
#define FORMAT_TAG			"YXI6"
#define FORMAT_TAG_LEN			(sizeof(FORMAT_TAG) - 1)
#define FORMAT_NAME			"Armory wallet"

#if defined(SIMD_COEF_64) && SIMD_PARA_SHA512 == 1
#define ALGORITHM_NAME			"SHA512/AES/secp256k1/SHA256/RIPEMD160 " SHA512_ALGORITHM_NAME
#else
#undef SIMD_COEF_64
#define ALGORITHM_NAME			"SHA512/AES/secp256k1/SHA256/RIPEMD160 " ARCH_BITS_STR "/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0x107

#define PLAINTEXT_LENGTH		125
#define CIPHERTEXT_LENGTH		156

struct custom_salt {
	uint8_t privkey[32], iv[16];
	uint32_t bytes_reqd, iter_count;
	uint8_t seed[32], crc[4];
};

#define BINARY_SIZE			20
#define BINARY_ALIGN			1
#define SALT_SIZE			sizeof(struct custom_salt)
#define SALT_ALIGN			sizeof(uint32_t)

#ifdef SIMD_COEF_64
#define MIN_KEYS_PER_CRYPT		(SIMD_COEF_64 * SIMD_PARA_SHA512)
#define MAX_KEYS_PER_CRYPT		(SIMD_COEF_64 * SIMD_PARA_SHA512)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif
#define OMP_SCALE			1

/*
 * These test vectors were extracted from test wallets by Christopher Gurnee's
 * btcrecover/extract-scripts/extract-armory-privkey.py
 */
static struct fmt_tests tests[] = {
	/* 8 MiB, 2 iterations */
	{"YXI6DKXVcrlt7I85ct/qzlUSXX1MCs+wbXVpJdtrw9RuXZpMowuOXmfqMiuFKj0/g/G2sQScLr6+dsiNrh/OOlsDzP4T60QAAIAAAgAAAIZidMeJWIXezaAL+WpoA5nbs9eGf5syXhOnHYF65Ftmo4p+jw==", "jtr-test-password1"},
	{"YXI6zkTV2lPsGMYFxUEZNZXClHnTrbjLMgETZIcdCiIJ9HywU8wOEPJeF+jo2VOxTXb+gkV4GXrBEgaq+jX8XWFWkszRmtUAAIAAAgAAAHa4aIO3jzsfckq1ETPaJx/qVasAPzV3R9gyjqHuFqpWwB+01A==", "jtr-test-password2"},
	/* 2 MiB, 4 iterations */
	{"YXI6r7mks1qvph4G+rRT7WlIptdr9qDqyFTfXNJ3ciuWJ12BgWX5Il+y28hLNr/u4Wl49hUi4JBeq6Jz9dVBX3vAJ6476FEAACAABAAAAGGwnwXRpPbBzC5lCOBVVWDu7mUJetBOBvzVAv0IbrboDXqA8A==", "btcr-test-password"},
	/* 4 MiB, 6 iterations, generated by Armory 0.95.1 */
	{"YXI6uOgnVa0B+Wx63/haI5oBRHkDf7ge3Kjc5LXnYXtnlIUHDD+J3u5ilyHfMmo7uaFaj1cbogHyjdZUhZj3a6XzdFE3NA0AAEAABgAAAARJgevrWUGCq2+5j8v3ei+vkZOpcUhdPDwrKTyXAU4znXCL2A==", "jtr-test-password"},
	/* 32 MiB, 3 iterations */
	{"YXI6q0bSuS3K6msHGDI5wSvD04RH7VqENEsIctti29xVGbyxLoqwIyGL53+qFOkW1Zqb6ZncatQZgX/3cf9XXxjFbSxGp4EAAAACAwAAAKKiUt8yakXdpwZ6SnbPFbwIsUzUUVMgwlySR02FFtMijFRpew==", "a3q92wz8"},
	{"YXI6AjyVtsaXWcRnwXXVg8wxXIojao8Qbg9h6O3geKo7wW9DU9IwieZ3P9Zrad25GfcKNj92Ku8Y+zas7SYkOVKbM158up0AAAACAwAAAA6ucY42OWUaxhXVn8KufVHLdLzl0K4qlBFX7PXgvaFYeMGp7g==", "test_pxYe6q1MT"},
	{NULL}
};

static struct custom_salt *saved_salt;

static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static uint8_t (*crypt_out)[BINARY_SIZE];

static int max_threads;
static region_t *memory;

static secp256k1_context *secp256k1_ctx;

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

#ifdef _OPENMP
	max_threads = omp_get_max_threads();
#else
	max_threads = 1;
#endif

	memory = mem_alloc(sizeof(*memory) * max_threads);
	int i;
	for (i = 0; i < max_threads; i++)
		init_region_t(&memory[i]);

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));

	/*
	 * Use a shared context as permitted by comment in secp256k1.h for
	 * calls that take a const pointer.
	 */
	if (!(secp256k1_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN))) {
		fprintf(stderr, "Failed to create secp256k1 context\n");
		error();
	}
}

static void done(void)
{
	int i;
	for (i = 0; i < max_threads; i++)
		free_region_t(&memory[i]);
	MEM_FREE(memory);

	MEM_FREE(saved_key);
	MEM_FREE(crypt_out);

	secp256k1_context_destroy(secp256k1_ctx);
}

/*
 * Free the tests' memory allocation before actual cracking, so that it doesn't
 * affect long-term memory usage in case the actual targets need less memory
 * than the tests.  However, don't do this when proceeding from self-test to
 * benchmark, so that memory (de)allocation time doesn't affect the speeds.
 */
void reset(struct db_main *db)
{
	if (benchmark_running)
		return;

	int i;
	for (i = 0; i < max_threads; i++)
		free_region_t(&memory[i]);
}

static void *get_salt(char *ciphertext)
{
	uint8_t decoded[BINARY_SIZE + SALT_SIZE];
	int err;

	ciphertext += FORMAT_TAG_LEN;
	if (base64_convert(ciphertext, e_b64_mime, strlen(ciphertext),
	    decoded, e_b64_raw, sizeof(decoded), flg_Base64_DONOT_NULL_TERMINATE, &err) != sizeof(decoded) || err)
		return NULL;

	static struct custom_salt salt;
	memcpy(&salt, &decoded[BINARY_SIZE], sizeof(salt));
#if !ARCH_LITTLE_ENDIAN
	salt.bytes_reqd = JOHNSWAP(salt.bytes_reqd);
	salt.iter_count = JOHNSWAP(salt.iter_count);
#endif

	if (salt.bytes_reqd < 1024 || (salt.bytes_reqd & (salt.bytes_reqd - 1)))
		return NULL;

	CRC32_t ctx;
	unsigned char crc[4];
	CRC32_Init(&ctx);
	CRC32_Update(&ctx, "ar:", 3);
	CRC32_Update(&ctx, decoded, sizeof(decoded) - sizeof(salt.crc));
	CRC32_Final(crc, ctx);
	if (memcmp(salt.crc, crc, sizeof(crc)))
		return NULL;

	return &salt;
}

static void *get_binary(char *ciphertext)
{
	static uint8_t binary[BINARY_SIZE];
	int err;

	ciphertext += FORMAT_TAG_LEN;
	if (base64_convert(ciphertext, e_b64_mime, strlen(ciphertext),
	    binary, e_b64_raw, sizeof(binary), flg_Base64_DONOT_NULL_TERMINATE, &err) != sizeof(binary) || err)
		return NULL;

	return binary;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) || strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;

	return get_salt(ciphertext) != NULL;
}

static void set_salt(void *salt)
{
	saved_salt = salt;
}

static void set_key(char *key, int index)
{
	char *p = saved_key[index];
	*p = 0;
	strncat(p, key, PLAINTEXT_LENGTH);
}

static char *get_key(int index)
{
	return saved_key[index];
}

typedef union {
	uint8_t u8[64];
	uint32_t u32[16];
	uint64_t u64[8];
} lut_item[MIN_KEYS_PER_CRYPT];

typedef union {
	uint8_t u8[32];
	uint64_t u64[4];
} derived_key;

/* Derive AES keys from password(s) starting at saved_key[index] */
static int derive_keys(region_t *memory, int index, derived_key *dk)
{
	uint8_t *mk[MIN_KEYS_PER_CRYPT];
	size_t mklen[MIN_KEYS_PER_CRYPT];
	int subindex;
	for (subindex = 0; subindex < MIN_KEYS_PER_CRYPT; subindex++) {
		mk[subindex] = (uint8_t *)saved_key[index + subindex];
		mklen[subindex] = strlen(saved_key[index + subindex]);
	}

	uint32_t n = saved_salt->bytes_reqd >> 6;
	lut_item *lut = memory->aligned;
	size_t bytes_reqd = (size_t)n * sizeof(*lut);
	if (!lut || memory->aligned_size < bytes_reqd) {
		if (free_region_t(memory) ||
		    !(lut = alloc_region_t(memory, bytes_reqd)))
			return -1;
	}

	uint32_t i = saved_salt->iter_count;
	do {
		for (subindex = 0; subindex < MIN_KEYS_PER_CRYPT; subindex++) {
			SHA512_CTX ctx;
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, mk[subindex], mklen[subindex]);
			SHA512_Update(&ctx, saved_salt->seed, sizeof(saved_salt->seed));
			SHA512_Final(lut[0][subindex].u8, &ctx);
		}

#ifdef SIMD_COEF_64
		JTR_ALIGN(64) uint64_t x[8][MIN_KEYS_PER_CRYPT];
		for (subindex = 0; subindex < MIN_KEYS_PER_CRYPT; subindex++) {
			uint32_t k;
			for (k = 0; k < 8; k++)
				x[k][subindex] = lut[0][subindex].u64[k] = JOHNSWAP64(lut[0][subindex].u64[k]);
		}

		SIMDSHA512body(x, lut[1][0].u64, lut[n][0].u64, SSEi_HALF_IN|SSEi_LOOP|SSEi_FLAT_OUT);

		uint32_t j = n >> 1;
		do {
			lut_item *pp[MIN_KEYS_PER_CRYPT];
			for (subindex = 0; subindex < MIN_KEYS_PER_CRYPT; subindex++) {
				uint32_t v = x[7][subindex];
				lut_item *p = pp[subindex] = &lut[JOHNSWAP(v) & (n - 1)];
				x[0][subindex] ^= (*p)[subindex].u64[0];
				x[1][subindex] ^= (*p)[subindex].u64[1];
				x[2][subindex] ^= (*p)[subindex].u64[2];
				x[3][subindex] ^= (*p)[subindex].u64[3];
			}

			for (subindex = 0; subindex < MIN_KEYS_PER_CRYPT; subindex++) {
				lut_item *p = pp[subindex];
				x[4][subindex] ^= (*p)[subindex].u64[4];
				x[5][subindex] ^= (*p)[subindex].u64[5];
				x[6][subindex] ^= (*p)[subindex].u64[6];
				x[7][subindex] ^= (*p)[subindex].u64[7];
			}

			SIMDSHA512body(x, x[0], NULL, SSEi_HALF_IN);
		} while (--j);

		for (subindex = 0; subindex < MIN_KEYS_PER_CRYPT; subindex++) {
			uint32_t k;
			for (k = 0; k < 4; k++)
				dk[subindex].u64[k] = JOHNSWAP64(x[k][subindex]);
			mk[subindex] = dk[subindex].u8;
			mklen[subindex] = 32;
		}
#elif MIN_KEYS_PER_CRYPT == 1
		lut_item *p = lut;
		SHA512_CTX ctx;
		do {
			SHA512_Init(&ctx);
			SHA512_Update(&ctx, p, 64);
			SHA512_Final((*++p)[0].u8, &ctx);
		} while (p < &lut[n - 1]);

		lut_item x;
		memcpy(x, *p, sizeof(x));

		uint32_t j = n >> 1;
		do {
			uint32_t v = x[0].u32[15];
#if !ARCH_LITTLE_ENDIAN
			v = JOHNSWAP(v);
#endif
			p = &lut[v & (n - 1)];

			x[0].u64[0] ^= (*p)[0].u64[0];
			x[0].u64[1] ^= (*p)[0].u64[1];
			x[0].u64[2] ^= (*p)[0].u64[2];
			x[0].u64[3] ^= (*p)[0].u64[3];
			x[0].u64[4] ^= (*p)[0].u64[4];
			x[0].u64[5] ^= (*p)[0].u64[5];
			x[0].u64[6] ^= (*p)[0].u64[6];
			x[0].u64[7] ^= (*p)[0].u64[7];

			SHA512_Init(&ctx);
			SHA512_Update(&ctx, &x, 64);
			SHA512_Final(x[0].u8, &ctx);
		} while (--j);

		for (subindex = 0; subindex < MIN_KEYS_PER_CRYPT; subindex++)
			memcpy(mk[subindex] = dk[subindex].u8, x[subindex].u8, mklen[subindex] = 32);
#else
#error "This code only supports either SIMD or MIN_KEYS_PER_CRYPT = 1"
#endif
	} while (--i);

	return 0;
}

/* Derive one address from one AES key derived above; clobbers dk */
static void derive_address(region_t *memory, derived_key *dk, uint8_t *da)
{
	/* AES CFB mode decryption */
	AES_KEY ak;
	AES_set_encrypt_key(dk->u8, 256, &ak);
	AES_encrypt(saved_salt->iv, dk->u8, &ak);
	uint64_t xor[2];
	memcpy(xor, saved_salt->privkey, sizeof(xor));
	dk->u64[0] ^= xor[0];
	dk->u64[1] ^= xor[1];
	AES_encrypt(saved_salt->privkey, &dk->u8[16], &ak);
	memcpy(xor, saved_salt->privkey + 16, sizeof(xor));
	dk->u64[2] ^= xor[0];
	dk->u64[3] ^= xor[1];

	/* Compute public key from decrypted private key */
	secp256k1_pubkey pubkey;
	if (secp256k1_ec_pubkey_create(secp256k1_ctx, &pubkey, dk->u8)) {
		unsigned char ser[65];
		size_t serlen = sizeof(ser);
		secp256k1_ec_pubkey_serialize(secp256k1_ctx, ser, &serlen, &pubkey, SECP256K1_EC_UNCOMPRESSED);

		/* Hash160 */
		{
			SHA256_CTX ctx;
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, ser, sizeof(ser));
			SHA256_Final(dk->u8, &ctx);
		}
		{
			sph_ripemd160_context ctx;
			sph_ripemd160_init(&ctx);
			sph_ripemd160(&ctx, dk->u8, 32);
			sph_ripemd160_close(&ctx, da);
		}
	} else {
		memset(da, 0, BINARY_SIZE);
	}
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	int failed = 0, cracked = !salt, count = *pcount, index;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(index) shared(count, failed, cracked, salt, max_threads, memory, saved_key, saved_salt, crypt_out)
#endif
	for (index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
#ifdef _OPENMP
		int t = omp_get_thread_num();
		if (t >= max_threads) {
			failed = -1;
			continue;
		}
#else
		const int t = 0;
#endif

		errno = 0;
		derived_key dk[MIN_KEYS_PER_CRYPT];
		if (derive_keys(&memory[t], index, dk)) {
			failed = errno ? errno : ENOMEM;
#ifndef _OPENMP
			break;
#endif
		}

		int subindex;
		for (subindex = 0; subindex < MIN_KEYS_PER_CRYPT; subindex++) {
			derive_address(memory, &dk[subindex], crypt_out[index + subindex]);

			if (salt) {
				struct db_password *pw = salt->list;
				do {
					if (!memcmp(pw->binary, crypt_out[index + subindex], BINARY_SIZE))
						cracked = -1;
				} while ((pw = pw->next));
			}
		}
	}

	if (failed) {
#ifdef _OPENMP
		if (failed < 0) {
			fprintf(stderr, "OpenMP thread number out of range\n");
			error();
		}
#endif
		fprintf(stderr, "Memory allocation failed: %s\n", strerror(failed));
		error();
	}

	return cracked ? count : 0;
}

static int cmp_all(void *binary, int count)
{
	return 1;
}

static int cmp_one(void *binary, int index)
{
	return !memcmp(binary, crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static unsigned int tunable_cost_memory(void *_salt)
{
	struct custom_salt *salt = (struct custom_salt *)_salt;
	return salt->bytes_reqd;
}

static unsigned int tunable_cost_iterations(void *_salt)
{
	struct custom_salt *salt = (struct custom_salt *)_salt;
	return salt->iter_count;
}

struct fmt_main fmt_armory = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		{"memory", "iterations"},
		{FORMAT_TAG},
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
		{tunable_cost_memory, tunable_cost_iterations},
		fmt_default_source,
		{fmt_default_binary_hash},
		fmt_default_salt_hash,
		NULL,
		set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{fmt_default_get_hash},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */
