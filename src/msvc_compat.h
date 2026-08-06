#ifndef _MSVC_COMPAT_H_
#define _MSVC_COMPAT_H_

#include <stdint.h>
#include <string.h>

#define __declspec(x)

static inline uint32_t _rotl(uint32_t v, int s) { return (v << s) | (v >> (32 - s)); }
static inline uint32_t _rotr(uint32_t v, int s) { return (v >> s) | (v << (32 - s)); }
static inline uint64_t _rotr64(uint64_t v, int s) { return (v >> s) | (v << (64 - s)); }
static inline uint64_t _rotl64(uint64_t v, int s) { return (v << s) | (v >> (64 - s)); }
static inline uint32_t _byteswap_ulong(uint32_t v) {
	return ((v & 0xff) << 24) | ((v & 0xff00) << 8) | ((v >> 8) & 0xff00) | ((v >> 24) & 0xff);
}
static inline uint64_t _byteswap_uint64(uint64_t v) {
	return ((uint64_t)_byteswap_ulong((uint32_t)(v & 0xffffffffu)) << 32) |
		_byteswap_ulong((uint32_t)(v >> 32));
}
static inline void __movsb(unsigned char *d, const unsigned char *s, uint32_t n) { memcpy(d, s, n); }
static inline void __stosb(unsigned char *d, unsigned char v, uint32_t n) { memset(d, v, n); }

#endif
