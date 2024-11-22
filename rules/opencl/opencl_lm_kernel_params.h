#include "opencl_lm_hst_dev_shared.h"
#include "opencl_device_info.h"

typedef unsigned WORD vtype;

#if no_byte_addressable(DEVICE_INFO)
#define RV7xx
#endif
#if gpu_nvidia(DEVICE_INFO)
#define _NV
#endif

#define vxorf(a, b) 					\
	((a) ^ (b))
#define vnot(dst, a) 					\
	(dst) = ~(a)
#define vand(dst, a, b) 				\
	(dst) = (a) & (b)
#define vor(dst, a, b) 					\
	(dst) = (a) | (b)
#define vandn(dst, a, b) 				\
	(dst) = (a) & ~(b)
#define vxor(dst, a, b) 				\
	(dst) = vxorf((a), (b))
#define vshl(dst, src, shift) 				\
	(dst) = (src) << (shift)
#define vshr(dst, src, shift) 				\
	(dst) = (src) >> (shift)
#define vshl1(dst, src) 				\
	vshl((dst), (src), 1)

#if HAVE_LUT3
#define vsel(dst, a, b, c)	(dst) = lut3(a, b, c, 0xd8)
#elif defined(_NV) || __CPU__
#define vsel(dst, a, b, c) 				\
	(dst) = (((a) & ~(c)) ^ ((b) & (c)))
#else
#define vsel(dst, a, b, c) 				\
	(dst) = bitselect((a),(b),(c))
#endif

#if defined(_NV) || __CPU__
#define JOHN_DES_OPT_REG /* Optimize register pressure more than gate count */
#include "opencl_sboxes.h"
#else
#include "opencl_sboxes-s.h"
#endif

#define vst_private(dst, ofs, src) 			\
	*((vtype *)((lm_vector *)&(dst) + (ofs))) = (src)

#define lm_clear_block_8(j) 			\
	vst_private(B[j] , 0, zero); 			\
	vst_private(B[j] , 1, zero); 			\
	vst_private(B[j] , 2, zero); 			\
	vst_private(B[j] , 3, zero); 			\
	vst_private(B[j] , 4, zero); 			\
	vst_private(B[j] , 5, zero); 			\
	vst_private(B[j] , 6, zero); 			\
	vst_private(B[j] , 7, zero);

#define lm_clear_block 				\
	lm_clear_block_8(0); 			\
	lm_clear_block_8(8); 			\
	lm_clear_block_8(16); 			\
	lm_clear_block_8(24); 			\
	lm_clear_block_8(32); 			\
	lm_clear_block_8(40); 			\
	lm_clear_block_8(48); 			\
	lm_clear_block_8(56);

/* This handles an input of 0xffffffffU correctly */
#define BITMAP_SHIFT ((BITMAP_MASK >> 5) + 1)

#define GET_HASH_0(hash, x, k, bits)			\
	for (bit = bits; bit < k; bit++)		\
		hash |= ((((uint)B[bit]) >> x) & 1) << bit;

#define GET_HASH_1(hash, x, k, bits)   			\
	for (bit = bits; bit < k; bit++)		\
		hash |= ((((uint)B[32 + bit]) >> x) & 1) << bit;

inline void cmp_final(unsigned lm_vector *B,
		      unsigned int *binary,
		      __global unsigned int *offset_table,
		      __global unsigned int *hash_table,
		     volatile __global uint *output,
		      volatile __global uint *bitmap_dupe,
		      unsigned int depth,
		      unsigned int section,
		      unsigned int iter)
{
	unsigned long hash;
	unsigned int hash_table_index, t, bit;

#if SELECT_CMP_STEPS > 1
	GET_HASH_0(binary[0], depth, 32, REQ_BITMAP_BITS);
	GET_HASH_1(binary[1], depth, 32, REQ_BITMAP_BITS);
#else
	binary[0] = 0;
	GET_HASH_0(binary[0], depth, 32, 0);
	GET_HASH_1(binary[1], depth, 32, REQ_BITMAP_BITS);
#endif

	hash = ((unsigned long)binary[1] << 32) | (unsigned long)binary[0];
	hash += (unsigned long)offset_table[hash % OFFSET_TABLE_SIZE];
	hash_table_index = hash % HASH_TABLE_SIZE;

	if (hash_table[hash_table_index + HASH_TABLE_SIZE] == binary[1])
	if (hash_table[hash_table_index] == binary[0])
	if (!(atomic_or(&bitmap_dupe[hash_table_index/32], (1U << (hash_table_index % 32))) & (1U << (hash_table_index % 32)))) {
		t = atomic_inc(&output[0]);
		output[1 + 3 * t] = (section * 32) + depth;
		output[2 + 3 * t] = iter;
		output[3 + 3 * t] = hash_table_index;
	}
}

inline void cmp( unsigned lm_vector *B,
		 __global unsigned int *offset_table,
		 __global unsigned int *hash_table,
		  __global unsigned int *bitmaps,
		 volatile __global uint *output,
		 volatile __global uint *bitmap_dupe,
		 int section, unsigned int iter) {

	unsigned int value[2] , i, bit, bitmap_index;

	for (i = 0; i < 32; i++){
#if SELECT_CMP_STEPS > 1
	value[0] = 0;
	value[1] = 0;
	GET_HASH_0(value[0], i, REQ_BITMAP_BITS, 0);
	GET_HASH_1(value[1], i, REQ_BITMAP_BITS, 0);
	bitmap_index = value[1] & BITMAP_MASK;
	bit = (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
	bitmap_index = value[0] & BITMAP_MASK;
	bit &= (bitmaps[BITMAP_SHIFT + (bitmap_index >> 5)] >> (bitmap_index & 31)) & 1U;
#else
	value[1] = 0;
	GET_HASH_1(value[1], i, REQ_BITMAP_BITS, 0);
	bitmap_index = value[1] & BITMAP_MASK;
	bit = (bitmaps[bitmap_index >> 5] >> (bitmap_index & 31)) & 1U;
#endif
	if (bit)
		cmp_final(B, value, offset_table, hash_table, output, bitmap_dupe, i, section, iter);
	}
}
