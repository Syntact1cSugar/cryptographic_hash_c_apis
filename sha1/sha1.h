#ifndef __mysha1_h__
#define __mysha1_h__

#include <stdint.h>

#define MSHA1_DIGEST_SIZE 20 /* bytes */

typedef struct MSHA1_CTX_t MSHA1_CTX;

extern MSHA1_CTX *MSHA1_CTX_new(void);
extern void MSHA1_CTX_free(MSHA1_CTX *msha1_ctx);
extern int MSHA1_CTX_init(MSHA1_CTX *msha1_ctx);
extern int MSHA1_CTX_update(MSHA1_CTX *msha1_ctx, const void *input, uint64_t input_sz);
extern int MSHA1_CTX_final(MSHA1_CTX *msha1_ctx, uint8_t *buffer, uint64_t buffer_sz);

#endif /* __msha1_h__ */
