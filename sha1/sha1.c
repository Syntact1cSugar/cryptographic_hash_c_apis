#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include "sha1_local.h"
#include "sha1.h"

/* START - Generic helper functions */
static inline uint32_t __circular_rotate_left(uint32_t n, uint32_t s) {
	s %= 32;
	return (n << s) | (n >> (32 - s));
}

static inline void __memcpy_big_endian(uint8_t *dst, uint8_t *src, uint64_t n) {
	uint64_t i;

	for (i = 1; i <= n; ++i) {
		memcpy(dst + (i - 1), src + (n - i), 1);
	}
	return;
}

static inline uint32_t __add_mod_2p32(uint32_t a, uint32_t b) {
	return ((uint64_t) a + (uint64_t) b) % 4294967296 /* = 2^32 */ ;
}
/* END   - Generic helper functions */

MSHA1_CTX *MSHA1_CTX_new(void) {
	MSHA1_CTX *msha1_ctx = (MSHA1_CTX *) malloc(sizeof(MSHA1_CTX));
	return msha1_ctx;
}

/* START - Functions used for calculating digest */
static inline uint32_t _MSHA1_f(uint8_t t, uint32_t B, uint32_t C, uint32_t D) {
	if (0 <= t && 19 >= t)
		return (B & C) | ((~B) & D);
	else if (20 <= t && 39 >= t)
		return B ^ C ^ D;
	else if (40 <= t && 59 >= t)
		return (B & C) | (B & D) | (C & D);
	else if (60 <= t && 79 >= t)
		return B ^ C ^ D;
	/* default value */
	return 0;
}

static inline uint32_t _MSHA1_K(uint8_t t) {
	if (0 <= t && 19 >= t)
		return 0x5A827999;
	else if (20 <= t && 39 >= t)
		return 0x6ED9EBA1;
	else if (40 <= t && 59 >= t)
		return 0x8F1BBCDC;
	else if (60 <= t && 79 >= t)
		return 0xCA62C1D6;
	/* default value */
	return 0;
}
/* END   - Functions used for calculating digest */

void MSHA1_CTX_free(MSHA1_CTX *msha1_ctx) {
	/*
	 * msha1_ctx->msha1_ctx_message buffer is allocated and deallocated within
	 * MSHA1_CTX_update(), so no need to free here
	*/
	free(msha1_ctx);
}

int MSHA1_CTX_init(MSHA1_CTX *msha1_ctx) {
	if (NULL == msha1_ctx)
		return 1;
	memset((uint8_t *) msha1_ctx, 0, sizeof(MSHA1_CTX));
	/* initialize registers A, B, C & D */
	msha1_ctx->msha1_ctx_A = 0x67452301;
	msha1_ctx->msha1_ctx_B = 0xEFCDAB89;
	msha1_ctx->msha1_ctx_C = 0x98BADCFE;
	msha1_ctx->msha1_ctx_D = 0x10325476;
	msha1_ctx->msha1_ctx_E = 0xC3D2E1F0;
	msha1_ctx->msha1_ctx_flags |= F_MSHA1_CTX_INIT_DONE;
	return 0;
}

static void _MSHA1_CTX_sha1_step(MSHA1_CTX *msha1_ctx, uint8_t t) {
	uint32_t AA, BB, CC, DD, EE, TEMP;

	/* copy register values A, B, C, D & E */
	AA = msha1_ctx->msha1_ctx_A;
	BB = msha1_ctx->msha1_ctx_B;
	CC = msha1_ctx->msha1_ctx_C;
	DD = msha1_ctx->msha1_ctx_D;
	EE = msha1_ctx->msha1_ctx_E;

	TEMP = __add_mod_2p32(__circular_rotate_left(AA, 5), _MSHA1_f(t, BB, CC, DD));
	TEMP = __add_mod_2p32(TEMP, EE);
	TEMP = __add_mod_2p32(TEMP, msha1_ctx->msha1_ctx_W[t]);
	TEMP = __add_mod_2p32(TEMP, _MSHA1_K(t));

	/* update registers A, B, C, D & E */
	msha1_ctx->msha1_ctx_A = TEMP;
	msha1_ctx->msha1_ctx_B = AA;
	msha1_ctx->msha1_ctx_C = __circular_rotate_left(BB, 30);
	msha1_ctx->msha1_ctx_D = CC;
	msha1_ctx->msha1_ctx_E = DD;
	return;
}

static int _MSHA1_CTX_compute_digest(MSHA1_CTX *msha1_ctx) {
	uint64_t num_blocks, block;
	uint32_t *X = NULL;
	uint32_t AA, BB, CC, DD, EE;
	uint8_t t, i;

	msha1_ctx->msha1_ctx_W = (uint32_t *) malloc(sizeof(uint32_t) * 80);
	if (NULL == msha1_ctx->msha1_ctx_W)
		return 1;
	num_blocks = (msha1_ctx->msha1_ctx_message_sz) / MSHA1_BLOCK_SIZE;
	for (block = 0; block < num_blocks; ++block) {
		/* keep copy of registers A, B, C, D & E */
		AA = msha1_ctx->msha1_ctx_A;
		BB = msha1_ctx->msha1_ctx_B;
		CC = msha1_ctx->msha1_ctx_C;
		DD = msha1_ctx->msha1_ctx_D;
		EE = msha1_ctx->msha1_ctx_E;
		/* 64 byte block is divided to array of 32 bits - X[0...15] */
		X = (uint32_t *) (msha1_ctx->msha1_ctx_message + (MSHA1_BLOCK_SIZE * block));
		/* populate W[0...79] */
		for (i = 0; i < 16; ++i) {
			/* W[i] = big endian (X[i]) */
			__memcpy_big_endian((uint8_t *) &msha1_ctx->msha1_ctx_W[i],
								(uint8_t *) &X[i], 4);
		}
		for (i = 16; i < 80; ++i) {
			msha1_ctx->msha1_ctx_W[i] = msha1_ctx->msha1_ctx_W[i - 3];
			msha1_ctx->msha1_ctx_W[i] ^= msha1_ctx->msha1_ctx_W[i - 8];
			msha1_ctx->msha1_ctx_W[i] ^= msha1_ctx->msha1_ctx_W[i - 14];
			msha1_ctx->msha1_ctx_W[i] ^= msha1_ctx->msha1_ctx_W[i - 16];
			msha1_ctx->msha1_ctx_W[i] = __circular_rotate_left(msha1_ctx->msha1_ctx_W[i], 1);
		}
		/* perform 80 operations, each operation updating the registers A, B, C, D & E */
		for (t = 0; t < 80; ++t) {
			_MSHA1_CTX_sha1_step(msha1_ctx, t);
		}
		msha1_ctx->msha1_ctx_A = __add_mod_2p32(msha1_ctx->msha1_ctx_A, AA);
		msha1_ctx->msha1_ctx_B = __add_mod_2p32(msha1_ctx->msha1_ctx_B, BB);
		msha1_ctx->msha1_ctx_C = __add_mod_2p32(msha1_ctx->msha1_ctx_C, CC);
		msha1_ctx->msha1_ctx_D = __add_mod_2p32(msha1_ctx->msha1_ctx_D, DD);
		msha1_ctx->msha1_ctx_E = __add_mod_2p32(msha1_ctx->msha1_ctx_E, EE);
	}
	return 0;
}

static int _MSHA1_CTX_init_message_buff(MSHA1_CTX *msha1_ctx, const uint8_t *input) {
	uint64_t in_sz_bits;
	uint8_t *byte_cur = NULL;

	msha1_ctx->msha1_ctx_message_sz = msha1_ctx->msha1_ctx_in_sz + msha1_ctx->msha1_ctx_pad_sz + 8;
	msha1_ctx->msha1_ctx_message = (uint8_t *) malloc(sizeof(uint8_t) * msha1_ctx->msha1_ctx_message_sz);
	if (NULL == msha1_ctx->msha1_ctx_message)
		return 1;
	byte_cur = msha1_ctx->msha1_ctx_message;
	/* append input to message buffer */
	memcpy(byte_cur, input, msha1_ctx->msha1_ctx_in_sz);
	byte_cur += msha1_ctx->msha1_ctx_in_sz;
	/* append padding bytes to message buffer */
	memcpy(byte_cur, MSHA1_PAD_BYTES, msha1_ctx->msha1_ctx_pad_sz);
	byte_cur += msha1_ctx->msha1_ctx_pad_sz;
	/* append length bytes to message buffer (big endian) */
	in_sz_bits = 8 * msha1_ctx->msha1_ctx_in_sz;
	__memcpy_big_endian(byte_cur, (uint8_t *) &in_sz_bits, 8);
	byte_cur += 8;
	return 0;
}

static void _MSHA1_CTX_compute_sizes(MSHA1_CTX *msha1_ctx, uint64_t input_sz) {
	msha1_ctx->msha1_ctx_in_sz = input_sz;
	msha1_ctx->msha1_ctx_pad_sz = MSHA1_BLOCK_SIZE - ((input_sz + 8) % MSHA1_BLOCK_SIZE);
	return;
}

int MSHA1_CTX_update(MSHA1_CTX *msha1_ctx, const void *input, uint64_t input_sz) {
	int rc = 0;

	if (NULL == msha1_ctx || NULL == input || 0 >= input_sz)
		return 1;
	if (!(msha1_ctx->msha1_ctx_flags & F_MSHA1_CTX_INIT_DONE))
		return 2;
	/* msha1_ctx is ready to be processed */
	input = (uint8_t *) input;
	_MSHA1_CTX_compute_sizes(msha1_ctx, input_sz);
	if (0 != (rc = _MSHA1_CTX_init_message_buff(msha1_ctx, input)))
		goto Done;
	if (0 != (rc = _MSHA1_CTX_compute_digest(msha1_ctx)))
		goto Done;
Done:
	free(msha1_ctx->msha1_ctx_message);
	msha1_ctx->msha1_ctx_message = NULL;
	free(msha1_ctx->msha1_ctx_W);
	msha1_ctx->msha1_ctx_W = NULL;
	return rc;
}

int MSHA1_CTX_final(MSHA1_CTX *msha1_ctx, uint8_t *buffer, uint64_t buffer_sz) {
	if (NULL == msha1_ctx || NULL == buffer || MSHA1_DIGEST_SIZE > buffer_sz)
		return 1;
	/* SHA1 digest = ABCDE (each register in big endian) */
	__memcpy_big_endian(buffer +  0, (uint8_t *) &msha1_ctx->msha1_ctx_A, 4);
	__memcpy_big_endian(buffer +  4, (uint8_t *) &msha1_ctx->msha1_ctx_B, 4);
	__memcpy_big_endian(buffer +  8, (uint8_t *) &msha1_ctx->msha1_ctx_C, 4);
	__memcpy_big_endian(buffer + 12, (uint8_t *) &msha1_ctx->msha1_ctx_D, 4);
	__memcpy_big_endian(buffer + 16, (uint8_t *) &msha1_ctx->msha1_ctx_E, 4);
	return 0;
}
