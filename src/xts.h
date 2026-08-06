#ifndef _XTS_H_
#define _XTS_H_
#include <stddef.h>
#include <stdint.h>

typedef struct {
	size_t ctx_size;
	void (*set_key)(const unsigned char *key, void *ctx);
	void (*encrypt)(const unsigned char *in, unsigned char *out, void *ctx);
	void (*decrypt)(const unsigned char *in, unsigned char *out, void *ctx);
} cipher_ops;

extern const cipher_ops CIPHER_AES;
extern const cipher_ops CIPHER_TWOFISH;
extern const cipher_ops CIPHER_SERPENT;

/* out must be a caller-allocated buffer of the same length as data */
void xts_pass(const cipher_ops *ops, const unsigned char *crypt_key,
	const unsigned char *tweak_key, const unsigned char *data, size_t len,
	uint64_t sector, int decrypt, unsigned char *out);

#endif
