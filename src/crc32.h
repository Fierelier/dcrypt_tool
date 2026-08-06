#ifndef _CRC32_H_
#define _CRC32_H_
#include <stddef.h>
#include <stdint.h>
uint32_t crc32_calc(const unsigned char *data, size_t len);
#endif
