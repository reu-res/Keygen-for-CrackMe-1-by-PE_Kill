#pragma warning(disable : 4996) // _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include "defs.h"

#include <string>
#include <iostream>

extern "C" {
	#include "RC4/rc4.h"
	#include "MD4Collisions/md4coll.h"
	#include "BigDigits/bigd.h"
}

unsigned int CheckSum(unsigned char *lpInput, int nSize)
{
	unsigned int result = 0;

	for (int i = 0; i < nSize; i++) {
		result = (result * 0x811C9DC5) ^ lpInput[i];
	}

	return result;
}

unsigned int round0(unsigned char *szName, int nLen)
{
	unsigned int result = 0, delta = 0xF8C9;

	for (int i = 0; i < nLen; i++) {
		result = result * delta + szName[i];
		delta *= 0x5C6B7;
	}

	return result;
}

unsigned int round1(unsigned char *szName, int nLen)
{
	unsigned int result = 0x4E67C6A7;

	for (int i = 0; i < nLen; i++) {
		result = result ^ ((result << 5) + (result >> 2) + szName[i]);
	}

	return result;
}

unsigned int round2(unsigned char *szName, int nLen)
{
	unsigned int result = 0, n;

	for (int i = 0; i < nLen; i++) {
		result = (result << 4) + szName[i];
		if ((n = result & 0xF0000000) != 0) {
			result = ((n >> 0x18) ^ result) & 0x0FFFFFFF;
		}
	}
	return result;
}

unsigned int round3(unsigned char *szName, int nLen)
{
	unsigned int result = 0, n;

	for (int i = 0; i < nLen; i++) {
		result = (result << 4) + szName[i];
		if ((n = result & 0xF0000000) != 0) {
			result = ((n >> 0x18) ^ result) & ~n;
		}
	}
	return result;
}

unsigned int round4(unsigned char *szName, int nLen)
{
	unsigned int result = 0;

	for (int i = 0; i < nLen; i++) {
		result = result * 0x83 + szName[i];
	}

	return result;
}

unsigned int round5(unsigned char *szName, int nLen)
{
	unsigned int result = 0;

	for (int i = 0; i < nLen; i++) {
		result = result * 0x1003F + szName[i];
	}

	return result;
}

unsigned int round6(unsigned char *szName, int nLen)
{
	unsigned int result = 0x1505;

	for (int i = 0; i < nLen; i++) {
		result = result * 0x21 + szName[i];
	}

	return result;
}

unsigned int round7(unsigned char *szName, int nLen)
{
	unsigned int result = nLen;

	for (int i = 0; i < nLen; i++) {
		result = _rotl(result, 5) ^ szName[i];
	}

	return result;
}

unsigned int round8(unsigned char *szName, int nLen)
{
	unsigned int result = nLen;

	for (int i = 0; i < nLen; i++) {
		result = (result << 7) ^ szName[i];
	}

	return result;
}

unsigned int XorKey(unsigned char *lpKey)
{
	unsigned int result = 0xAAAAAAAA, n;

	for (int i = 0; i < 0x28; i++) {
		if (i & 1) {
			n = ~(((result >> 5) ^ lpKey[i]) + (result << 0x0B));
		}
		else {
			n = (lpKey[i] * (result >> 3)) ^ (result << 7);
		}
		result ^= n;
	}

	unsigned int *lpdKey = (unsigned int *)lpKey;
	for (int i = 0; i < 10; i++) {
		result = _rotl(result, 7);
		lpdKey[i] ^= result;
	}

	return result;
}

int RSACrypt(unsigned char *lpInput, unsigned char *lpOutput)
{
	int res = 0;
	BIGD n, d, c, m;

	n = bdNew();
	d = bdNew();
	c = bdNew();
	m = bdNew();

	bdConvFromDecimal(n, big_N);
	bdConvFromDecimal(d, big_D);

	for (int i = 0; i < 4; i++)	{
		bdConvFromOctets(c, lpInput + i * 32, 32);
		if ((res = bdCompare(n, c)) < 0) { break; }
		bdModExp(m, c, d, n);
		bdConvToOctets(m, lpOutput + i * 32, 32);
	}

	bdFree(&m);
	bdFree(&c);
	bdFree(&d);
	bdFree(&n);

	return res;
}

int GetLicense(unsigned char *szName, int nNameLen, char *szLicense)
{
	LICENSE License = {0};
	unsigned char needbyte = 0xFF;

	unsigned int rc4key[10];
	rc4_key skey;
	
	unsigned char *lpInput, *lpOutput;

	rc4key[0] = round0(szName, nNameLen);
	rc4key[1] = round1(szName, nNameLen);
	rc4key[2] = round2(szName, nNameLen);
	rc4key[3] = round3(szName, nNameLen);
	rc4key[4] = round4(szName, nNameLen);
	rc4key[5] = round5(szName, nNameLen);
	rc4key[6] = round6(szName, nNameLen);
	rc4key[7] = round7(szName, nNameLen);
	rc4key[8] = round8(szName, nNameLen);
	rc4key[9] = CheckSum(szName, nNameLen);

	for (int i = 0; i < 10; i++) {
		printf("%08X\n", rc4key[i]);
	}

	License.AfterXorKey = XorKey((unsigned char *)&rc4key);

	for (int i = 0; i < 0x28; i++) {
		needbyte = table[needbyte ^ *((unsigned char *)&rc4key + i)];
	}

	initRandom();

	lpInput = (unsigned char *)malloc(0x80);
	lpOutput = (unsigned char *)malloc(0x80);
	
	printf("Please wait, it may take some time...\n");
	do {
		md4gen(needbyte, (License.AfterXorKey % 3) << 3);
		memcpy(lpInput, X0, 0x40);
		memcpy(lpInput + 0x40, X1, 0x40);
	} while (RSACrypt(lpInput, lpOutput) < 0);
	
	memcpy(&License, lpOutput, 0x80);
	
	free(lpInput);
	free(lpOutput);
	
	License.FaceKey1 = 0x19141918;
	License.FaceKey2 = 0x19411945;

	
	prepare_key((unsigned char *)rc4key, 0x28, &skey);
	rc4((unsigned char *)&License, 0x8C, &skey);

	License.LicenseCheckSum = CheckSum((unsigned char *)&License, 0x8C);

	for (int i = 0; i < 0x90; i++) {
		sprintf((char *)&szLicense[i * 2], "%02X", *((unsigned char *)&License + i));
	}

	return 1;
}

int main()
{
	char szName[50];
	int n;

	std::string szName1;

	printf("Name:\t");
	scanf("%s", szName);
	n = strlen(szName);

	if (n > 49) {
		printf("Name too long\n");
		return -1;
	} else {
		if (n < 5) {
			printf("Name too short\n");
			return -1;
		}
	}

	char szLicense[288 + 1];
	
	GetLicense((unsigned char *)szName, n, szLicense);
	printf("License:\n%s\n", szLicense);

	if (!OpenClipboard(NULL)) {
		printf("\nCan't copy license to clipboard\n\n");
		return -1;
	}
	EmptyClipboard();
	HGLOBAL hLic = GlobalAlloc(GMEM_ZEROINIT, 288 + 1);
	void *lplic = GlobalLock(hLic);
	strcpy((char *)lplic, szLicense);
	GlobalUnlock(hLic);
	SetClipboardData(CF_TEXT, hLic);
	GlobalFree(hLic);
	CloseClipboard();
	
	printf("\nLicense copy to clipboard\n\n");

	system("pause");

	return 0;
}