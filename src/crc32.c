#include "crc32.h"

uint32_t crc32_calc(const unsigned char *data, size_t len)
{
	uint32_t crc = 0xffffffffu;
	size_t i;
	int j;

	for (i = 0; i < len; i++) {
		crc ^= data[i];
		for (j = 0; j < 8; j++) {
			uint32_t mask = -(crc & 1);
			crc = (crc >> 1) ^ (0xedb88320u & mask);
		}
	}
	return crc ^ 0xffffffffu;
}
