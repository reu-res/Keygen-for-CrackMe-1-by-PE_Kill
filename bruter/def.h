#include <stddef.h>
#include <stdint.h>
#include "rc4.h"

uint32_t Crc32(const unsigned char * buf, size_t len);
void fix_crc_end(unsigned char *buffer, int length, unsigned int tcrcreg);