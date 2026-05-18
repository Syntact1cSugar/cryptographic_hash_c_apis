
#include <stdlib.h>
#include <string.h>

#include "md5_local.h"
#include "md5.h"

/* start - generic helper functions */
static inline uint32_t __circular_left_rotate(uint32_t n, uint32_t s) {
	s %= 32;
	return ((n << s)  | (n >> (32 - s)));
}

static inline uint32_t __add_mod_2p32(uint32_t a, uint32_t b) {
	return ((uint64_t) a + (uint64_t) b) % 4294967296 /* = 2^32 */;
}
/* end   - generic helper functions */

/* start - primitive functions */
static inline uint32_t F(uint32_t B, uint32_t C, uint32_t D) {
	return (B & C) | ((~B) & D);
}
static inline uint32_t G(uint32_t B, uint32_t C, uint32_t D) {
	return (B & D) | (C & ~(D));
}
static inline uint32_t H(uint32_t B, uint32_t C, uint32_t D) {
	return B ^ C ^ D;
}
static inline uint32_t I(uint32_t B, uint32_t C, uint32_t D) {
	return C ^ (B | ~(D));
}
/* end   - primitive functions */

/* start - index permutation function*/
static inline uint32_t p(uint8_t round, uint8_t index) {
	switch (round) {
	case 1:
		return index;
	case 2:
		return (1 + 5 * index) % 16;
	case 3:
		return (5 + 3 * index) % 16;
	case 4:
		return (0 + 7 * index) % 16;
	}
	/* default */
	return 0;
}
/* end   - index permutation function */

MMD5_CTX *MMD5_CTX_new(void) {
	MMD5_CTX *mmd5_ctx = NULL;
	mmd5_ctx = (MMD5_CTX *) malloc(sizeof(MMD5_CTX));
	return mmd5_ctx;
}

void MMD5_CTX_free(MMD5_CTX *mmd5_ctx) {
	/*
	 * mmd5_ctx->mmd5_ctx_message is allocated in MMD5_CTX_update()
	 * and de-allocated within that function itself, so need to free that here
	 */
	free(mmd5_ctx);
	return;
}

int MMD5_CTX_init(MMD5_CTX *mmd5_ctx) {
	if (NULL == mmd5_ctx)
		return 1;
	memset((uint8_t *) mmd5_ctx, 0, sizeof(MMD5_CTX));
	/* Initialize registers A, B, C & D (little endian) */
	mmd5_ctx->mmd5_ctx_A = 0x67452301;
	mmd5_ctx->mmd5_ctx_B = 0xEFCDAB89;
	mmd5_ctx->mmd5_ctx_C = 0x98BADCFE;
	mmd5_ctx->mmd5_ctx_D = 0x10325476;
	mmd5_ctx->mmd5_ctx_init_done = 1;
	return 0;
}

static int _MD5_CTX_compute_md5_step(MMD5_CTX *mmd5_ctx) {
	uint32_t (*primitive_fun_cb) (uint32_t, uint32_t, uint32_t) = NULL;
	uint32_t AA = mmd5_ctx->mmd5_ctx_A;
	uint32_t BB = mmd5_ctx->mmd5_ctx_B;
	uint32_t CC = mmd5_ctx->mmd5_ctx_C;
	uint32_t DD = mmd5_ctx->mmd5_ctx_D;
	uint32_t ix1 = p(mmd5_ctx->mmd5_ctx_round, (mmd5_ctx->mmd5_ctx_step - 1));
	uint32_t ix2 = ((mmd5_ctx->mmd5_ctx_round - 1) * MMD5_STEPS_PER_ROUND) + mmd5_ctx->mmd5_ctx_step;

	switch (mmd5_ctx->mmd5_ctx_round) {
	case 1:
		primitive_fun_cb = F;
		break;
	case 2:
		primitive_fun_cb = G;
		break;
	case 3:
		primitive_fun_cb = H;
		break;
	case 4:
		primitive_fun_cb = I;
		break;
	default:
		return 1;
	}
	/*  Update register values A, B, C & D to new values using their old values */
	mmd5_ctx->mmd5_ctx_A = DD;

	mmd5_ctx->mmd5_ctx_B = __add_mod_2p32(AA, primitive_fun_cb(BB, CC, DD));
	mmd5_ctx->mmd5_ctx_B = __add_mod_2p32(mmd5_ctx->mmd5_ctx_B, mmd5_ctx->mmd5_ctx_X[ix1]);
	mmd5_ctx->mmd5_ctx_B = __add_mod_2p32(mmd5_ctx->mmd5_ctx_B, MMD5_T[ix2]);
	mmd5_ctx->mmd5_ctx_B = __circular_left_rotate(mmd5_ctx->mmd5_ctx_B, MMD5_s[ix2]);
	mmd5_ctx->mmd5_ctx_B = __add_mod_2p32(mmd5_ctx->mmd5_ctx_B, BB);

	mmd5_ctx->mmd5_ctx_C = BB;
	mmd5_ctx->mmd5_ctx_D = CC;
	return 0;
}

static int _MD5_CTX_compute_digest(MMD5_CTX *mmd5_ctx) {
	uint64_t num_blocks, block, AA, BB, CC, DD;
	int rc = 0;

	num_blocks = (mmd5_ctx->mmd5_ctx_message_sz) / MMD5_BLOCK_SIZE;
	for (block = 1; block <= num_blocks; ++block) {
		AA = mmd5_ctx->mmd5_ctx_A;
		BB = mmd5_ctx->mmd5_ctx_B;
		CC = mmd5_ctx->mmd5_ctx_C;
		DD = mmd5_ctx->mmd5_ctx_D;
		mmd5_ctx->mmd5_ctx_X = (uint32_t *) ((mmd5_ctx->mmd5_ctx_message) + (MMD5_BLOCK_SIZE * (block - 1)));
		for (mmd5_ctx->mmd5_ctx_round = 1;
			 mmd5_ctx->mmd5_ctx_round <= MMD5_ROUNDS;
			 mmd5_ctx->mmd5_ctx_round += 1) {
			for (mmd5_ctx->mmd5_ctx_step = 1;
				 mmd5_ctx->mmd5_ctx_step <= MMD5_STEPS_PER_ROUND;
				 mmd5_ctx->mmd5_ctx_step += 1) {
				if (0 != (rc = _MD5_CTX_compute_md5_step(mmd5_ctx)))
					goto Done;
			}
		}
		mmd5_ctx->mmd5_ctx_A = __add_mod_2p32(mmd5_ctx->mmd5_ctx_A, AA);
		mmd5_ctx->mmd5_ctx_B = __add_mod_2p32(mmd5_ctx->mmd5_ctx_B, BB);
		mmd5_ctx->mmd5_ctx_C = __add_mod_2p32(mmd5_ctx->mmd5_ctx_C, CC);
		mmd5_ctx->mmd5_ctx_D = __add_mod_2p32(mmd5_ctx->mmd5_ctx_D, DD);
	}
Done:
	return rc;
}

static int _MMD5_CTX_init_message_buff(MMD5_CTX *mmd5_ctx, const uint8_t *input) {
	uint64_t in_sz_bits = 0;
	uint8_t *byte_cur = NULL;

	mmd5_ctx->mmd5_ctx_message_sz = (mmd5_ctx->mmd5_ctx_in_sz + mmd5_ctx->mmd5_ctx_pad_sz + 8);
	mmd5_ctx->mmd5_ctx_message = (uint8_t *) malloc(sizeof(uint8_t) * mmd5_ctx->mmd5_ctx_message_sz);
	if (NULL == mmd5_ctx->mmd5_ctx_message)
		return 1;
	byte_cur = (uint8_t *) mmd5_ctx->mmd5_ctx_message;
	/* append input to message buffer */
	memcpy((uint8_t *) byte_cur, (uint8_t *) input, mmd5_ctx->mmd5_ctx_in_sz);
	byte_cur += mmd5_ctx->mmd5_ctx_in_sz;
	/* append padding to message buffer */
	memcpy((uint8_t *) byte_cur, (uint8_t *) MMD5_pad_bytes, mmd5_ctx->mmd5_ctx_pad_sz);
	byte_cur += mmd5_ctx->mmd5_ctx_pad_sz;
	/* append 8 byte length field in little endian format*/
	in_sz_bits = 8 * mmd5_ctx->mmd5_ctx_in_sz;
	memcpy(byte_cur, (uint8_t *) &in_sz_bits, 8);
	byte_cur += 8;
	return 0;
}

void _MMD5_CTX_compute_sizes(MMD5_CTX *mmd5_ctx, const uint64_t input_sz) {
	mmd5_ctx->mmd5_ctx_in_sz = input_sz;
	mmd5_ctx->mmd5_ctx_pad_sz = MMD5_BLOCK_SIZE - ((input_sz + 8) % MMD5_BLOCK_SIZE);
	return;
}

int MMD5_CTX_update(MMD5_CTX *mmd5_ctx, const void *input, const uint64_t input_sz) {
	int rc = 0;

	if (NULL == mmd5_ctx || NULL == input || 0 >= input_sz)
		return 1;
	if(!mmd5_ctx->mmd5_ctx_init_done)
		return 2;
	/* mmd5_ctx is valid and ready to processed */
	input = (uint8_t *) input;
	_MMD5_CTX_compute_sizes(mmd5_ctx, input_sz);
	if(0 != (rc = _MMD5_CTX_init_message_buff(mmd5_ctx, input)))
		goto Done;
	if(0 != (rc = _MD5_CTX_compute_digest(mmd5_ctx)))
		goto Done;
Done:
	free(mmd5_ctx->mmd5_ctx_message);
	return rc;
}

int MMD5_CTX_final(MMD5_CTX *mmd5_ctx, uint8_t *buffer, uint64_t buffer_sz) {
	if (NULL == mmd5_ctx || NULL == buffer || MMD5_DIGEST_SIZE > buffer_sz)
		return 1;
	/* md5 digest = ABCD (each register in little endian) */
	memcpy(buffer +  0, (uint8_t *) &mmd5_ctx->mmd5_ctx_A, 4);
	memcpy(buffer +  4, (uint8_t *) &mmd5_ctx->mmd5_ctx_B, 4);
	memcpy(buffer +  8, (uint8_t *) &mmd5_ctx->mmd5_ctx_C, 4);
	memcpy(buffer + 12, (uint8_t *) &mmd5_ctx->mmd5_ctx_D, 4);
	return 0;
}
