#include <stdint.h>
#include "msvc_compat.h"
#ifndef _SHA512_SMALL_H_
#define _SHA512_SMALL_H_

typedef struct _sha512_ctx {
	uint64_t hash[8];
	uint64_t length;
	uint32_t curlen;
	unsigned char buf[128];

} sha512_ctx;

#define SHA512_DIGEST_SIZE 64
#define SHA512_BLOCK_SIZE  128

void sha512_init(sha512_ctx *ctx);
void sha512_hash(sha512_ctx *ctx, const unsigned char *in, uint32_t inlen);
void sha512_done(sha512_ctx *ctx, unsigned char *out);

#endif