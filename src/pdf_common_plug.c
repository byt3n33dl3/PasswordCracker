/*
 * PDF cracker patch for JtR. Hacked together during Monsoon of 2012 by
 * Dhiru Kholia <dhiru.kholia at gmail.com>.
 *
 * This software is
 * Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * Copyright (c) 2013, Shane Quigley
 * Copyright (c) 2024, magnum
 *
 * Uses code from pdfcrack, Sumatra PDF and MuPDF which are under GPL.
 */

#include "pdf_common.h"

pdf_salt_type* pdf_salt;
int* pdf_cracked;
int any_pdf_cracked;
size_t pdf_cracked_size;

const unsigned char pdf_padding[32] =
{
        0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41,
        0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
        0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80,
        0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a
};

struct fmt_tests pdf_tests[] = {
	/* R2 MD5 + RC4-40 */
	/* This hash exposed a problem with our id_len check */
	{"$pdf$1*2*40*-4*1*36*65623237393831382d636439372d343130332d613835372d343164303037316639386134*32*c7230519f7db63ab1676fa30686428f0f997932bf831f1c1dcfa48cfb3b7fe99*32*161cd2f7c95283ca9db930b36aad3571ee6f5fb5632f30dc790e19c5069c86b8", "vision"},
	/* This hash has unsigned permission value, and an id length of 0 */
	{"$pdf$1*2*40*4294967239*1*0**32*585e4cc4113bbd8ff4012dce92dd7df1e1216fb630b29cf5aeea10a820066c26*32*b1db56a883cab5a22dd5fc390618a0f8e16cab8af14e67ccba5f90837aac898b", "123456"},
	/* Old format hashes */
	{"$pdf$Standard*9a1156c38ab8177598d1608df7d7e340ae639679bd66bc4cda9bc9a4eedeb170*1f300cd939dd5cf0920c787f12d16be22205e55a5bec5c9c6d563ab4fd0770d7*16*c015cff8dbf99345ac91c84a45667784*1*1*0*1*6*40*-4*2*1", "testpassword"},
	{"$pdf$Standard*7303809eaf677bdb5ca64b9d8cb0ccdd47d09a7b28ad5aa522c62685c6d9e499*bf38d7a59daaf38365a338e1fc07976102f1dfd6bdb52072032f57920109b43a*16*c56bbc4145d25b468a873618cd71c2d3*1*1*0*1*6*40*-4*2*1", "test"},

	/* R3 MD5 + RC4-40 */
	/* Code is tested with hash from a real document, but this one is fabricated */
	{"$pdf$1*3*40*-4*1*16*5e1f73575e1f73575e1f73575e1f7357*32*c0be424bef466277092f2a1ba0fbe506ebabe5c01db100dedc0ffeebabe5c01d*32*0ff1cedeadce110ff1cedeadce110ff1cedeadce110ff1cedeadce11babebabe", "hashcat"},

	/* R3 MD5 + RC4-128 */
	{"$pdf$2*3*128*-4*1*16*34b1b6e593787af681a9b63fa8bf563b*32*289ece9b5ce451a5d7064693dab3badf101112131415161718191a1b1c1d1e1f*32*badad1e86442699427116d3e5d5271bc80a27814fc5e80f815efeef839354c5f", "test"},
	/* Old format hashes */
	{"$pdf$Standard*badad1e86442699427116d3e5d5271bc80a27814fc5e80f815efeef839354c5f*289ece9b5ce451a5d7064693dab3badf101112131415161718191a1b1c1d1e1f*16*34b1b6e593787af681a9b63fa8bf563b*1*1*0*1*4*128*-4*3*2", "test"},
	{"$pdf$Standard*137ad7063db5114a66ce1900d47e5cab9c5d7053487d92ac978f54db86eca393*0231a4c9cae29b53892874e168cfae9600000000000000000000000000000000*16*c015cff8dbf99345ac91c84a45667784*1*1*0*1*6*128*-1028*3*2", "testpassword"},
	{"$pdf$Standard*d83a8ab680f144dfb2ff2334c206a6060779e007701ab881767f961aecda7984*a5ed4de7e078cb75dfdcd63e8da7a25800000000000000000000000000000000*16*06a7f710cf8dfafbd394540d40984ae2*1*1*0*1*4*128*-1028*3*2", "July2099"},
	{"$pdf$Standard*6a80a547b8b8b7636fcc5b322f1c63ce4b670c9b01f2aace09e48d85e1f19f83*e64eb62fc46be66e33571d50a29b464100000000000000000000000000000000*16*14a8c53ffa4a79b3ed9421ef15618420*1*1*0*1*4*128*-1028*3*2", "38r285a9"},
	{"$pdf$Standard*2446dd5ed2e18b3ce1ac9b56733226018e3f5c2639051eb1c9b2b215b30bc820*fa3af175d761963c8449ee7015b7770800000000000000000000000000000000*16*12a4da1abe6b7a1ceb84610bad87236d*1*1*0*1*4*128*-1028*3*2", "WHATwhatWHERE?"},
	{"$pdf$Standard*e600ecc20288ad8b0d64a929c6a83ee2517679aa0218beceea8b7986726a8cdb*38aca54678d67c003a8193381b0fa1cc101112131415161718191a1b1c1d1e1f*16*1521fbe61419fcad51878cc5d478d5ff*1*1*0*1*4*128*-3904*3*2", ""},

	/* R4 MD5 + RC4 */
	{"$pdf$4*4*128*-1028*1*16*e03460febe17a048b0adc7f7631bcc56*32*3456205208ad52066d5604018d498a6400000000000000000000000000000000*32*6d598152b22f8fa8085b19a866dce1317f645788a065a74831588a739a579ac4", "openwall"},
	{"$pdf$4*4*128*-1028*1*16*c015cff8dbf99345ac91c84a45667784*32*0231a4c9cae29b53892874e168cfae9600000000000000000000000000000000*32*137ad7063db5114a66ce1900d47e5cab9c5d7053487d92ac978f54db86eca393", "testpassword"},
	/* CMIYC 2013 "pro" hashes */
	{"$pdf$4*4*128*-4*1*16*f7bc2744e1652cf61ca83cac8fccb535*32*f55cc5032f04b985c5aeacde5ec4270f0122456a91bae5134273a6db134c87c4*32*785d891cdcb5efa59893c78f37e7b75acef8924951039b4fa13f62d92bb3b660", "L4sV3g4z"},
	{"$pdf$4*4*128*-4*1*16*ec8ea2af2977db1faa4a955904dc956f*32*fc413edb049720b1f8eac87a358faa740122456a91bae5134273a6db134c87c4*32*1ba7aed2f19c77ac6b5061230b62e80b48fc42918f92aef689ceb07d26204991", "ZZt0pr0x"},
	{"$pdf$4*4*128*-4*1*16*56761d6da774d8d47387dccf1a84428c*32*640782cab5b7c8f6cf5eab82c38016540122456a91bae5134273a6db134c87c4*32*b5720d5f3d9675a280c6bb8050cbb169e039b578b2de4a42a40dc14765e064cf", "24Le`m0ns"},

	/* R5 SHA-256 */
	{"$pdf$5*5*256*-1028*1*16*762896ef582ca042a15f380c63ab9f2c*127*8713e2afdb65df1d3801f77a4c4da4905c49495e7103afc2deb06d9fba7949a565143288823871270d9d882075a75da600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*15d0b992974ff80529e4b616b8c4c79d787705b6c8a9e0f85446498ae2432e0027d8406b57f78b60b11341a0757d7c4a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*a7a0f3891b469ba7261ce04752dad9c6de0db9c4155c4180e721938a7d9666c7*32*2fa9a0c52badebae2c19dfa7b0005a9cfc909b92babbe7db66a794e96a9f91e3", "openwall"},

	/* R6 SHA-256/384/512 + AES-128-CBC */
	{"$pdf$5*6*256*-1028*1*16*05e5abeb21ad2e47adac1c2b2c7b7a31*127*51d3a6a09a675503383e5bc0b53da77ec5d5ea1d1998fb94e00a02a1c2e49313c177905272a4e8e68b382254ec8ed74800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*127*dc38f01ef129aae2fca847396465ed518f9c7cf4f2c8cb4399a849d0fe9110227739ab88ddc9a6cf388ae11941270af500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000*32*b8e137baf316e0789ffa73f888d26495c14d31f2cfff3799e339e2fa078649f5*32*835a9e07461992791914c3d62d37493e07d140937529ab43e26ac2a657152c3c", "testpassword"},
	{NULL}
};

int pdf_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *keeptr;
	char *p;
	int res;

	if (strncmp(ciphertext,  FORMAT_TAG, FORMAT_TAG_LEN))
		return 0;

	ctcopy = xstrdup(ciphertext);
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_LEN;
	if ((p = strtokm(ctcopy, "*")) == NULL)	/* V */
		goto err;
	if (!isdec(p)) goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* R */
		goto err;
	if (!isdec(p)) goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* key_length */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res < 40 || res > MAX_KEY_SIZE || (res % 4))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* P */
		goto err;
	/* Somehow this can be signed or unsigned int; -2147483648 .. 4294967295 */
	if (!isdec_negok(p) && !isdecu(p)) goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* encrypt_metadata */
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* id_len */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > 128)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* id */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	/* id length can be 0 */
	if (*p && !ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* u_len */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > MAX_U_LEN)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* u */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* o_len */
		goto err;
	if (!isdec(p)) goto err;
	res = atoi(p);
	if (res > MAX_O_LEN)
		goto err;
	if ((p = strtokm(NULL, "*")) == NULL)	/* o */
		goto err;
	if (strlen(p) != res * 2)
		goto err;
	if (!ishexlc(p))
		goto err;
	MEM_FREE(keeptr);
	return 1;

err:
	MEM_FREE(keeptr);
	return 0;
}

static int pdf_old_valid(char *ciphertext, struct fmt_main *self)
{
	char *ctcopy, *ptr, *keeptr;
	int res;

	if (strncmp(ciphertext, FORMAT_TAG_OLD, FORMAT_TAG_OLD_LEN))
		return 0;
	if (!(ctcopy = xstrdup(ciphertext)))
		return 0;
	keeptr = ctcopy;
	ctcopy += FORMAT_TAG_OLD_LEN;
	if (!(ptr = strtokm(ctcopy, "*"))) /* 1 o_string */
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 2 u_string */
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 3 fileIDLen */
		goto error;
	if (strncmp(ptr, "16", 2))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 4 fileID */
		goto error;
	if (!ishexlc(ptr))
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 5 encryptMetaData */
		goto error;
	res = atoi(ptr);
	if (res != 0 && res != 1)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 6 work_with_user */
		goto error;
	res = atoi(ptr);
	if (res != 0 && res != 1)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 7 have_userpassword */
		goto error;
	res = atoi(ptr);
	if (res != 0 && res != 1)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 8 version_major */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 9 version_minor */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 10 key_length */
		goto error;
	res = atoi(ptr);
	if (res < 0 || res > MAX_KEY_SIZE)
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 11 permissions P */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 12 revision R */
		goto error;
	if (!(ptr = strtokm(NULL, "*"))) /* 13 version V */
		goto error;
	MEM_FREE(keeptr);
	return 1;
error:
	MEM_FREE(keeptr);
	return 0;
}

static char* pdf_convert_old_to_new(char ciphertext[])
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	char *out = mem_alloc_tiny(strlen(ctcopy), MEM_ALIGN_NONE);
	const char *fields[14];
	char *p;
	int c = 0;

	p = strtokm(ctcopy, "*");
	for (c = 0; c < 14; c++) {
		fields[c] = p;
		p = strtokm(NULL, "*");
	}
	strcpy(out,FORMAT_TAG);
	strcat(out,fields[13]); // V
	strcat(out,"*");
	strcat(out,fields[12]); // R
	strcat(out,"*");
	strcat(out,fields[10]); // keylen
	strcat(out,"*");
	strcat(out,fields[11]); // P
	strcat(out,"*");
	strcat(out,fields[5]); // enc metadata
	strcat(out,"*");
	strcat(out,fields[3]); // id_len
	strcat(out,"*");
	strcat(out,fields[4]); // id
	strcat(out,"*32*");    // len u
	strcat(out,fields[2]); // u
	strcat(out,"*32*");    // len o
	strcat(out,fields[1]); // o
	MEM_FREE(keeptr);
	return out;
}

char *pdf_prepare(char *split_fields[10], struct fmt_main *self)
{
	// Convert old format to new one
	if (!strncmp(split_fields[1], FORMAT_TAG_OLD, FORMAT_TAG_OLD_LEN) &&
	    pdf_old_valid(split_fields[1], self))
		return pdf_convert_old_to_new(split_fields[1]);

	return split_fields[1];
}

void *pdf_get_salt(char *ciphertext)
{
	char *ctcopy = xstrdup(ciphertext);
	char *keeptr = ctcopy;
	int i;
	char *p;
	static pdf_salt_type cs;

	memset(&cs, 0, sizeof(cs));
	ctcopy += FORMAT_TAG_LEN;	/* skip over "$pdf$" marker */
	p = strtokm(ctcopy, "*");
	cs.V = atoi(p);
	p = strtokm(NULL, "*");
	cs.R = atoi(p);
	p = strtokm(NULL, "*");
	cs.key_length = atoi(p);
	p = strtokm(NULL, "*");
	cs.P = (int)strtoll(p, (char **)NULL, 10);
	p = strtokm(NULL, "*");
	cs.encrypt_metadata = atoi(p);
	p = strtokm(NULL, "*");
	cs.id_len = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.id_len; i++)
		cs.id[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.u_len = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.u_len; i++)
		cs.u[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	p = strtokm(NULL, "*");
	cs.o_len = atoi(p);
	p = strtokm(NULL, "*");
	for (i = 0; i < cs.o_len; i++)
		cs.o[i] =
		    atoi16[ARCH_INDEX(p[i * 2])] * 16 +
		    atoi16[ARCH_INDEX(p[i * 2 + 1])];
	MEM_FREE(keeptr);
	return (void *)&cs;
}

int pdf_cmp_all(void *binary, int count)
{
	return any_pdf_cracked;
}

int pdf_cmp_one(void *binary, int index)
{
	return pdf_cracked[index];
}

int pdf_cmp_exact(char *source, int index)
{
	return 1;
}

/*
 * Report revision as tunable cost, since between revisions 2 and 6,
 * only revisions 3 and 4 seem to have a similar c/s rate.
 */
unsigned int pdf_revision(void *salt)
{
	pdf_salt_type *pdf_salt = salt;

	return (unsigned int)pdf_salt->R;
}

/*
 * This is mostly for being able to pick what to benchmark for rev. 3
 *
 * Revisions 2..4 has salt->R as RC4 key length (40 or 128).
 * Revision 5 use only SHA256 and has salt->R as 256.
 * Revision 6 also has salt->R as 256 but actually uses AES-128.
 */
unsigned int pdf_keylen(void *salt)
{
	pdf_salt_type *pdf_salt = salt;

	return (unsigned int)pdf_salt->key_length;
}
