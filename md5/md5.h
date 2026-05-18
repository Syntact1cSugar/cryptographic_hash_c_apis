#ifndef __mymd5_h__
#define __mymd5_h__

#define MMD5_DIGEST_SIZE 16 /* bytes */

typedef struct MMD5_CTX_st MMD5_CTX;

extern MMD5_CTX *MMD5_CTX_new(void);
extern void MMD5_CTX_free(MMD5_CTX *mmd5_ctx);
extern int MMD5_CTX_init(MMD5_CTX *mmd5_ctx);
extern int MMD5_CTX_update(MMD5_CTX *mmd5_ctx, const void *input, const uint64_t input_sz);
extern int MMD5_CTX_final(MMD5_CTX *mmd5_ctx, uint8_t *buffer, uint64_t buffer_sz);

#endif /* __mymd5_h__ */
