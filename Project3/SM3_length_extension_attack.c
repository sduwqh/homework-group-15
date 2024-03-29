#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#define uint32 unsigned int 
#define uint64 unsigned long long int
#define uint8 unsigned char
uint32 IV[8] = { 0x7380166f,0x4914b2b9,0x172442d7,0xda8a0600,0xa96f30bc,0x163138aa,0xe38dee4d,0xb0fb0e4e };
const uint32 T[64] = { 0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
					  0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
					  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
					  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
					  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
					  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
					  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
					  0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a };

uint32 FF(X, Y, Z, j);
uint32 GG(X, Y, Z, j);
uint32 loopleft(uint32 a, short length);
uint32 P0(uint32 X);
uint32 P1(uint32 X);
uint32* padding(uint8* target, uint64 targetlen, uint64 mlen);
void mextend(uint32 W[132], uint32 B[16]);
void CF(uint32 b[16]);
void IC(uint32* m, uint64 mlen);
void SM3hash(uint8 s[], uint32 size);
void InitialVector(uint32 V[8]) {
	V[0] = 0x7380166f;
	V[1] = 0x4914b2b9;
	V[2] = 0x172442d7;
	V[3] = 0xda8a0600;
	V[4] = 0xa96f30bc;
	V[5] = 0x163138aa;
	V[6] = 0xe38dee4d;
	V[7] = 0xb0fb0e4e;
}
uint32 FF(X, Y, Z, j) {
	if (j >= 0 && j <= 15) {
		return X ^ Y ^ Z;
	}
	else if (j >= 16 && j <= 63) {
		return (X & Y) | (X & Z) | (Y & Z);
	}
	else {
		printf("ERROR!");
		exit(1);
	}
}
uint32 GG(X, Y, Z, j) {
	if (j >= 0 && j <= 15) {
		return X ^ Y ^ Z;
	}
	else if (j >= 16 && j <= 63) {
		return (X & Y) | (~X & Z);
	}
	else {
		printf("ERROR!");
		exit(1);
	}
}
uint32 loopleft(uint32 a, short length) {
	if (length % 32 == 0) {
		return a;
	}
	length = length % 32;
	return (a << length) + (a >> (32 - length));
}
uint32 P0(uint32 X) {
	return X ^ loopleft(X, 9) ^ loopleft(X, 17);
}
uint32 P1(uint32 X) {
	return X ^ loopleft(X, 15) ^ loopleft(X, 23);
}
uint32* padding(uint8* target, uint64 targetlen, uint64 mlen) {

	uint32* M = (uint32*)calloc(mlen, sizeof(uint32));
	for (uint64 i = 0; i < targetlen; i += 4) {
		uint64 temp = i / 4;
		if ((targetlen - 1) / 4 == temp) {
			/*switch (targetlen - i) {
			case 1:
				M[temp] = ((uint32)target[i] << 24) | (0x80 << 16);
				break;
			case 2:
				M[temp] = ((uint32)target[i] << 24)| ((uint32)target[i+1] << 16) | (0x80 << 8);
				break;
			case 3:
				M[temp] = ((uint32)target[i] << 24) | ((uint32)target[i + 1] << 16) | ((uint32)target[i + 2] << 8) | 0x80;
				break;
			case 4:
				M[temp] = ((uint32)target[i] << 24) | ((uint32)target[i + 1] << 16) | ((uint32)target[i + 2] << 8) | ((uint32)target[i + 3]);
				M[temp + 1] = 0x80000000;
				break;
			}*/
			for (short j = 0; j < targetlen - i; j += 1) {
				M[temp] = M[temp] << 8 | (uint32)target[i + j];
			}
			if (targetlen - i == 4) {
				M[temp + 1] = 0x80000000;
			}
			else {
				M[temp] = M[temp] << 8 | 0x80;
				M[temp] = M[temp] << (8 * (3 - targetlen + i));
			}
		}
		else {
			M[temp] = ((uint32)target[i] << 24) | ((uint32)target[i + 1] << 16) | ((uint32)target[i + 2] << 8) | ((uint32)target[i + 3]);
		}
		M[mlen - 1] = (uint32)(targetlen * 8 & 0x00000000ffffffff);
		M[mlen - 2] = (uint32)(targetlen * 8 >> 32 & 0x00000000ffffffff);
	}
	return M;
}
void mextend(uint32 W[132], uint32 B[16]) {
	for (short i = 0; i < 16; i += 1) {
		W[i] = B[i];
	}
	for (short i = 16; i < 68; i += 1) {
		W[i] = P1(W[i - 16] ^ W[i - 9] ^ loopleft(W[i - 3], 15)) ^ loopleft(W[i - 13], 7) ^ W[i - 6];
	}
	for (short i = 68; i < 132; i += 1) {
		W[i] = W[i - 68] ^ W[i - 64];
	}
}
void CF(uint32 b[16]) {
	uint32 W[132] = { 0 };
	mextend(W, b);
	uint32 SS1, SS2, TT1, TT2;
	uint32 A = IV[0];
	uint32 B = IV[1];
	uint32 C = IV[2];
	uint32 D = IV[3];
	uint32 E = IV[4];
	uint32 F = IV[5];
	uint32 G = IV[6];
	uint32 H = IV[7];
	for (short j = 0; j < 64; j++) {
		SS1 = loopleft(loopleft(A, 12) + E + loopleft(T[j], j), 7);
		SS2 = SS1 ^ loopleft(A, 12);
		TT1 = FF(A, B, C, j) + D + SS2 + W[j + 68];
		TT2 = GG(E, F, G, j) + H + SS1 + W[j];
		D = C;
		C = loopleft(B, 9);
		B = A;
		A = TT1;
		H = G;
		G = loopleft(F, 19);
		F = E;
		E = P0(TT2);
	}
	IV[0] = A ^ IV[0];
	IV[1] = B ^ IV[1];
	IV[2] = C ^ IV[2];
	IV[3] = D ^ IV[3];
	IV[4] = E ^ IV[4];
	IV[5] = F ^ IV[5];
	IV[6] = G ^ IV[6];
	IV[7] = H ^ IV[7];
}
void IC(uint32* m, uint64 mlen) {

	uint32 B[16] = { 0 };
	for (uint64 i = 0; i < mlen; i += 16) {
		for (short j = 0; j < 16; j += 1) {
			B[j] = m[i + j];
		}
		CF(B);
	}
}
void SM3hash(uint8 s[], uint32 size) {
	InitialVector(IV);
	uint64 a = size / 64 + 1;
	short b = size % 64;
	if (b >= 56)
		a = a + 1;
	uint64 mlen = 16 * a;
	uint32* m = padding(s, size, mlen);
	printf("\nmessege after padding is\n");
	for (int i = 0; i < mlen; i += 1) { 
		printf("%08x ", m[i]);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	//printf("-----------------------------------------\n");
	IC(m, mlen);
}
void SM3hashAttack(uint8 s[], uint32 size,uint32 size0) {
	uint64 a = size / 64 + 1;
	short b = size % 64;
	if (b >= 56)
		a = a + 1;
	uint64 mlen = 16 * a;
	uint32* m = padding(s, size, mlen);
	printf("\nmessege after padding is\n");
	for (int i = 0; i < mlen; i += 1) {
		printf("%08x ", m[i]);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	printf("-----------------------------------------\n");
	uint64 a0 = size0 / 64 + 1;
	short b0 = size0 % 64;
	if (b0 >= 56)
		a0 = a0 + 1;
	//printf("a0=%08x ", size0);
	m[mlen - 1] += a0 * 512;
	printf("\nmessege after padding is\n");
	for (int i = 0; i < mlen; i += 1) {
		printf("%08x ", m[i]);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	printf("-----------------------------------------\n");
	/*for (int i = 0; i < 8; i += 1) {
		printf("%08x ", IV[i]);
	}*/
	IC(m, mlen);
}
int main() {
	uint8 str1[6] = { "shuiyc" };
	uint32 size1 = sizeof(str1);
	SM3hash(str1, size1);
	printf("\n------------------------------\nSM3 hash value is:\n");
	for (int i = 0; i < 8; i += 1) {
		printf("%08x ", IV[i]);
	}
	printf("\nstarting length entension attack...\n");
	uint8 str2[16] = { "is attacking SM3" };
	uint32 size0 = sizeof(str2);
	SM3hashAttack(str2, size0, size1);
	printf("\n------------------------------\nSM3 hash value is:\n");
	for (int i = 0; i < 8; i += 1) {
		printf("%08x ", IV[i]);
	}
	printf("\n");
	uint8 str3[80] = { "shuiyc\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00""0is attacking SM3" };
	uint32 size3 = sizeof(str3);
	SM3hash(str3, size3);
	printf("\n------------------------------\nSM3 hash value is:\n");
	for (int i = 0; i < 8; i += 1) {
		printf("%08x ", IV[i]);
	}
	
}