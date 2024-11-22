/*
 * This software is
 *  Copyright (c) 2017-2024 magnum
 *  Copyright (c) 2016 Fist0urs <eddy.maaalou at gmail.com>, and
 *  Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis),
 *  Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Really old keepass apparently used RC4, or an "Arcfour variant".  We never got
 * support for it. There are also references to Salsa20 (predecessor of ChaCha).
 *
 * NOTE: Any of the three formats below can be appended with "*1*64*<32_bytes_hex>"
 *       which then is either the contents of a keyfile or the SHA-256 hash of it.
 *
 * KDBX2
 * $keepass$*1*<rounds>*<cipher>*<final_seed>*<trans_seed>*<iv>*<hash>*1*<data_size>*<data>
 *                      0 AES
 *                      1 TwoFish
 * KDBX3
 * $keepass$*2*<rounds>*<cipher>*<master_seed>*<trans_seed>*<iv>*<expected_start_bytes>*<data>
 *                      2 ChaCha
 *
 * KDBX4
 * $keepass$*4*<Argon2_T>*<kdf_uuid>*<Argon2_M>*<Argon2_V>*<Argon2_P>*<master_seed>*<trans_seed>*<header>*<header_hmac>
 *                       c9d9f39a AES
 *                       ef636ddf Argon2d
 *                       9e298b19 Argon2id
 *
 * KeePassXC 2.7.6 KDBX4
 * Default KDF is Argon2d, eg. ~10-35 rounds (aims for 1 sec), 64 MiB, 2 threads.
 * Defaults for Argon2id are same as for Argon2d.
 * Defaults for AES256 is eg. ~32M rounds (aims for 1 sec) rather than eg. 6000.
 *
 * KeePass' Argon2 implementation supports all parameters that are defined in the
 * official specification, but only the number of iterations, the memory size and
 * the degree of parallelism can be configured by the user in the database settings
 * dialog. For the other parameters, KeePass chooses reasonable defaults: a 256-bit
 * salt is generated each time the database is saved, the tag length is 256 bits,
 * no secret key or associated data. KeePass uses version 1.3 of Argon2.
 *
 * argon2_t == time == iterations == ~30
 * argon2_m == memory: Note that this field is in bytes (67108864 for 64 MB) but
 *             when given to the argon2 function it's expressed as KiB (65536 KB).
 * argon2_p == lanes == parallelism == threads == 2
 * argon2_v == version, 19 == 0x13 == 1.3
 *
 *****************************
 * Argon2d t=10 p=2 m=65536:
 *****************************
 *  2080ti              ~30 ms
 *  CPU                 ~83 ms
 *  Radeon Pro Vega 20 ~150 ms
 *  UHD Graphics 630   ~273 ms
 *****************************
 */

#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <errno.h>
#ifdef _OPENMP
#include <omp.h>
#ifndef OMP_SCALE
#define OMP_SCALE		1
#endif
#endif

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "options.h"

#define KEEPASS_COMMON_CODE	1
#include "keepass_common.h"

char (*keepass_key)[KEEPASS_PLAINTEXT_LENGTH + 1];
keepass_salt_t *keepass_salt;

// Iterations, or Argon2 t
unsigned int keepass_cost_t(void *salt)
{
	keepass_salt_t *ksalt = salt;

	if (ksalt->kdf == 0)
		return ksalt->key_transf_rounds;
	else
		return ksalt->t_cost;
}

// Argon2 m
// 67108864 (64 MiB) in the "hash" means 65536 (KiB) as argument to argon2_hash()
// and is the actual memory use per parallel calculation
unsigned int keepass_cost_m(void *salt)
{
	keepass_salt_t *ksalt = salt;

	if (ksalt->kdbx_ver < 4)
		return 0;
	return ksalt->m_cost;
}

// Argon2 p
unsigned int keepass_cost_p(void *salt)
{
	keepass_salt_t *ksalt = salt;

	if (ksalt->kdbx_ver < 4)
		return 0;
	return ksalt->lanes;
}

// 0=Argon2d 2=Argon2id 3=AES
unsigned int keepass_kdf(void *salt)
{
	keepass_salt_t *ksalt = salt;

	if (ksalt->kdf == 0)
		return 3;
	else
		return ksalt->type;
}
