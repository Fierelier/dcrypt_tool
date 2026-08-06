#include <stdint.h>
#include "msvc_compat.h"
#ifndef _SHA512_PKCS5_2_SMALL_H_
#define _SHA512_PKCS5_2_SMALL_H_

void sha512_hmac(const void *k, uint32_t k_len, const void *d, uint32_t d_len, unsigned char *out);
void sha512_pkcs5_2(int i_count, const void *pwd, uint32_t pwd_len, const void *salt, uint32_t salt_len, unsigned char *dk, uint32_t dklen);

#endif