#include <stdlib.h>
#include "xts.h"
#include "aes_small.h"
#include "twofish_small.h"
#include "serpent_small.h"

static int aes_tab_ready = 0;
static void aes_set_key_v(const unsigned char *key, void *ctx) {
	if (!aes_tab_ready) { aes256_gentab(); aes_tab_ready = 1; }
	aes256_set_key(key, (aes256_key *)ctx);
}
static void aes_encrypt_v(const unsigned char *in, unsigned char *out, void *ctx) { aes256_encrypt(in, out, (aes256_key *)ctx); }
static void aes_decrypt_v(const unsigned char *in, unsigned char *out, void *ctx) { aes256_decrypt(in, out, (aes256_key *)ctx); }

static void tf_set_key_v(const unsigned char *key, void *ctx) { twofish256_set_key(key, (twofish256_key *)ctx); }
static void tf_encrypt_v(const unsigned char *in, unsigned char *out, void *ctx) { twofish256_encrypt(in, out, (twofish256_key *)ctx); }
static void tf_decrypt_v(const unsigned char *in, unsigned char *out, void *ctx) { twofish256_decrypt(in, out, (twofish256_key *)ctx); }

static void sp_set_key_v(const unsigned char *key, void *ctx) { serpent256_set_key(key, (serpent256_key *)ctx); }
static void sp_encrypt_v(const unsigned char *in, unsigned char *out, void *ctx) { serpent256_encrypt(in, out, (serpent256_key *)ctx); }
static void sp_decrypt_v(const unsigned char *in, unsigned char *out, void *ctx) { serpent256_decrypt(in, out, (serpent256_key *)ctx); }

const cipher_ops CIPHER_AES = { sizeof(aes256_key), aes_set_key_v, aes_encrypt_v, aes_decrypt_v };
const cipher_ops CIPHER_TWOFISH = { sizeof(twofish256_key), tf_set_key_v, tf_encrypt_v, tf_decrypt_v };
const cipher_ops CIPHER_SERPENT = { sizeof(serpent256_key), sp_set_key_v, sp_encrypt_v, sp_decrypt_v };

static void gf_mul2(unsigned char t[16])
{
	int i;
	unsigned char carry = t[15] >> 7;
	for (i = 15; i > 0; i--) {
		t[i] = (t[i] << 1) | (t[i - 1] >> 7);
	}
	t[0] <<= 1;
	if (carry) {
		t[0] ^= 0x87;
	}
}

void xts_pass(const cipher_ops *ops, const unsigned char *crypt_key,
	const unsigned char *tweak_key, const unsigned char *data, size_t len,
	uint64_t sector, int decrypt, unsigned char *out)
{
	void *c1 = malloc(ops->ctx_size);
	void *c2 = malloc(ops->ctx_size);
	size_t off, bo, i;
	unsigned char idx[16], tweak[16], pp[16], p[16];

	ops->set_key(crypt_key, c1);
	ops->set_key(tweak_key, c2);

	for (off = 0; off < len; off += 512) {
		sector += 1;
		for (i = 0; i < 16; i++) {
			idx[i] = 0;
		}
		for (i = 0; i < 8; i++) {
			idx[i] = (unsigned char)((sector >> (8 * i)) & 0xff);
		}
		ops->encrypt(idx, tweak, c2);

		for (bo = 0; bo < 512 && off + bo < len; bo += 16) {
			const unsigned char *block = data + off + bo;
			for (i = 0; i < 16; i++) {
				pp[i] = block[i] ^ tweak[i];
			}
			if (decrypt) {
				ops->decrypt(pp, p, c1);
			} else {
				ops->encrypt(pp, p, c1);
			}
			for (i = 0; i < 16; i++) {
				out[off + bo + i] = p[i] ^ tweak[i];
			}
			gf_mul2(tweak);
		}
	}

	free(c1);
	free(c2);
}
