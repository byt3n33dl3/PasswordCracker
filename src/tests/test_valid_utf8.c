/*
 * Copyright (c) 2024 Aleksey Cherepanov
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

/* Test code for valid_utf8() from unicode.c vs single char UTF-8 sequences
 *
 * It tests only a sequence of bytes for single character. Plus a few
 * cases of additional byte after valid 2-bytes long sequence are
 * tested. Higher-level logic is not checked. Test is sparse: checks
 * of continuous blocks are applied skipping parts. Dense checks are
 * applied close to borders to catch off-by-one mistakes. Valid
 * sequences are limited to single character (1-4 bytes). Invalid
 * sequences go up to 5 bytes and use even bigger steps for skipping.
 * ASCII bytes at trailing positions are tested lightly.
 *
 * Description in PR#5531 contains a script to test valid_utf8()
 * against Python3.  https://github.com/openwall/john/pull/5531
 *
 * See also info in  unicode.h
 */

/* This file has up to 6 levels of nesting, so tab-width 4 might be
 * helpful. Deep nesting is the price for simple regular structure. */

#define is_trailing(c) (0x80 <= (c) && (c) < 0xC0)

#define valid_utf8(a) (inc_test(), valid_utf8((a)))
#define expect(cond) \
	do { \
		if (!(cond)) { \
			printf("Failed %s(): check '%s' fails for this byte sequence: %s\n", \
			       Results.test_name, #cond, hex(buf, strlen((void *)buf))); \
			inc_failed_test(); \
			return; /* early exit for the whole test */ \
		} \
	} while (0)

void _test_valid_utf8()
{
	UTF8 buf[6] = {};

	/* Empty string is valid. */
	expect(valid_utf8(buf) == 1);

	/* 1 byte: ASCII is valid, non-ascii alone is invalid. */
	for (int c = 0; c < 256; c++) {
		buf[0] = c;
		buf[1] = '\0';
		expect(valid_utf8(buf) == (c < 128));
	}

	/* Setup dense check around borders of 80..BF range for trailing bytes. */
	unsigned char trailing_sparse_check[256] = {};
	for (int c = 0x79; c < 256; c += 16)
		trailing_sparse_check[c] = 1;
	for (int c = 0x80 - 8; c < 0x80 + 8; c++)
		trailing_sparse_check[c] = 1;
	for (int c = 0xBF - 8; c < 0xBF + 8; c++)
		trailing_sparse_check[c] = 1;

	/* Multi-byte test: either start is valid or we grow sequence (up to 5 bytes). */
	for (int c1 = 128; c1 < 256; c1++) {
		buf[0] = c1;
		buf[1] = '\0';

		int step = 1;

		/* Invalid starting byte would be checked with all endings. So
		 * checks are sparse for invalid starting bytes. */
		if (buf[0] < 0xC2 || 0xF4 < buf[0])
			step = 15; /* sparse checks */
		else
			step = 1;

		for (int c2 = 0x70, r2; c2 < 256; c2 += step) {
			/* The second byte is checked sparsely only for invalid starts. */
			buf[1] = c2;
			buf[2] = '\0';
			r2 = valid_utf8(buf);

			if (0xC2 <= buf[0] && buf[0] < 0xE0 &&
			    is_trailing(buf[1])) {

				expect(r2 == 2);

				/* Additional test with 41 and F5 after valid 2-bytes sequence */
				buf[3] = '\0';
				buf[2] = 'A';
				expect(valid_utf8(buf) == 2);
				buf[2] = 0xF5;
				expect(valid_utf8(buf) == 0);

				continue;
			}

			expect(r2 == 0);
			for (int c3 = 0x79, r3; c3 < 256; c3++) {
				if (0 == trailing_sparse_check[c3])
					continue; /* run code below sparsely */
				buf[2] = c3;
				buf[3] = '\0';
				r3 = valid_utf8(buf);

				if ((buf[0] == 0xE0 &&
				     0xA0 <= buf[1] && buf[1] < 0xC0 &&
				     is_trailing(buf[2])) ||

				    (buf[0] == 0xED &&
				     0x80 <= buf[1] && buf[1] < 0xA0 &&
				     is_trailing(buf[2])) ||

				    (0xE1 <= buf[0] && buf[0] < 0xF0 && buf[0] != 0xED &&
				     is_trailing(buf[1]) &&
				     is_trailing(buf[2]))) {

					expect(r3 == 2);
					continue;
				}

				expect(r3 == 0);
				for (int c4 = 0x79, r4; c4 < 256; c4++) {
					if (0 == trailing_sparse_check[c4])
						continue; /* run code below sparsely */
					buf[3] = c4;
					buf[4] = '\0';
					r4 = valid_utf8(buf);

					if ((buf[0] == 0xF0 &&
					     0x90 <= buf[1] && buf[1] < 0xC0 &&
					     is_trailing(buf[2]) &&
					     is_trailing(buf[3])) ||

					    (buf[0] == 0xF4 &&
					     0x80 <= buf[1] && buf[1] < 0x90 &&
					     is_trailing(buf[2]) &&
					     is_trailing(buf[3])) ||

					    ((buf[0] == 0xF1 || buf[0] == 0xF2 || buf[0] == 0xF3) &&
					     is_trailing(buf[1]) &&
					     is_trailing(buf[2]) &&
					     is_trailing(buf[3]))) {

						expect(r4 == 2);
						continue;
					}

					expect(r4 == 0);
					for (int c5 = 0x79; c5 < 256; c5 += 32) {
						/* We test only a few values for the fifth byte. */
						buf[4] = c5;
						buf[5] = '\0';
						expect(valid_utf8(buf) == 0);
					}
				}
			}
		}
	}
}

void test_valid_utf8()
{
	start_test(__FUNCTION__);
	failed = 0;
	_test_valid_utf8();
	end_test();
}

#undef expect
#undef is_trailing
#undef valid_utf8
