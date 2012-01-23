#include "def.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

int main()
{
	uint32_t key[2] = {0, 0};
	uint8_t *pkey = (uint8_t *)&key;

	rc4_key skey;
	uint32_t rc4_data[2];

	do {
		fix_crc_end(pkey, 8, 0xFFB97FE0);

		prepare_key(pkey, 8, &skey);
		rc4_data[0] = 0xE6C5D5E1;
		rc4_data[1] = 0x41C98EAB;
		rc4((uint8_t *)rc4_data, 8, &skey);
		if (rc4_data[0] == 0xFACE0001 && rc4_data[1] == 0xFACE0002) {
			printf("Key: ");
			for (int i = 0; i < 8; i++) {
				printf("%02X", *pkey++);
			}
			printf("\n");
			break;
		}
	} while (key[0]++ <= 0xFFFFFFFF);

	printf("\n\n\t\tFin!\n");

	return 0;
}