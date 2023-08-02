# Project3: implement length extension attack for SM3, SHA256, etc
## 一、攻击原理
由于sha256和SM3的实现大致是将消息填充后进行压缩迭代，并且将上一轮迭代的结果作为下一轮的初始向量输入进压缩迭代的部件，这就产生了一个漏洞：
如果已知str1的长度以及其hash值，那么对任意str2，我们都可以求出hash(pad(str1)||str2)的值
这是因为str1的hash值已知，因此可以修改hash函数的初始向量，并将str2进行特殊填充，这里的特殊填充主要是在末尾除了要有str2本身的长度信息，还应该在此基础上加上str1填充后的长度，这样就能伪造pad(str1)||str2的消息填充
实际上不止SM3和sha256，长度拓展攻击对许多hash函数都有效
## 二、针对sha256的长度拓展攻击
针对sha256的长度拓展攻击利用python实现，这是因为标准库中的hashlib方便验证sha256攻击的正确性。代码实现如下

```python
import hashlib

def pad(s):
    binaries = s.encode()
    M = binaries + b'\x80' + b'\x00'*(64-len(binaries)-1-8) + (len(binaries)*8).to_bytes(8, byteorder='big')
    return M

def pad_attack(s,Mlen):
    binaries = s.encode()
    M = binaries + b'\x80' + b'\x00'*(64-len(binaries)-1-8) + (len(binaries)*8+Mlen*8).to_bytes(8, byteorder='big')
    return M

K = [
0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

def ROTR(x, n):
    x = (x >> n) | (x << 32 - n)
    return x

def Initialize(M):
    W = [0] * 64
    for t in range(0, 16):
        W[t] = M[t * 4:t * 4 + 4]
        W[t] = int(W[t].hex(), 16)
    for t in range(16, 64):
        S1 = ROTR(W[t - 2], 17) ^ ROTR(W[t - 2], 19) ^ (W[t - 2]>>10)
        S0 = ROTR(W[t - 15], 7) ^ ROTR(W[t - 15], 18) ^ (W[t - 15] >> 3)
        W[t] = (S1+W[t-7]+S0+W[t-16]) & 0xFFFFFFFF
    return W
    
def Iteration(W,H):
    a = H[0]
    b = H[1]
    c = H[2]
    d = H[3]
    e = H[4]
    f = H[5]
    g = H[6]
    h = H[7]

    for t in range(0, 64):
        S1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25)
        Ch = (e & f) ^ ((~e) & g)
        S0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22)
        Maj = (a & b) ^ (a & c) ^ (b & c)
        T1 = h + S1 + Ch + K[t] + W[t]
        T2 = S0 + Maj
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF

    H[0] = a + H[0] & 0xFFFFFFFF
    H[1] = b + H[1] & 0xFFFFFFFF
    H[2] = c + H[2] & 0xFFFFFFFF
    H[3] = d + H[3] & 0xFFFFFFFF
    H[4] = e + H[4] & 0xFFFFFFFF
    H[5] = f + H[5] & 0xFFFFFFFF
    H[6] = g + H[6] & 0xFFFFFFFF
    H[7] = h + H[7] & 0xFFFFFFFF
    return H

def sha256hash(s):
    H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
    M=pad(s)
    W=Initialize(M)
    H=Iteration(W,H)
    sha256 = ''
    for sha in H:
        sha256 = sha256 + sha.to_bytes(4, byteorder='big').hex()
    print(sha256)
    return sha256

def sha256hash_attack(h,s,mlen):
    H=[int(h[8*i:8*i+8],base=16) for i in range(len(h)//8)]
    #print(H)
    M=pad_attack(s,mlen)
    W=Initialize(M)
    H=Iteration(W,H)
    sha256 = ''
    #print(H)
    for sha in H:
        sha256 = sha256 + sha.to_bytes(4, byteorder='big').hex()    
    return sha256


str1="shuiyc"
print("origin string:",str1)
h=hashlib.sha256(str1.encode()).hexdigest()
print("hash value:",h)

print("starting length entension attack...")
str2="is attacking sha256"
print("extended string:",str2)
    

h2=sha256hash_attack(h,str2,len(pad(str1)))

s=pad(str1)+str2.encode()
h3=hashlib.sha256(s).hexdigest()

print("h2=",h2)
print("h3=",h3)
if h2==h3:
    print("Length entension attack succeed!")
```

运行代码，得到以下结果
![](https://s3.bmp.ovh/imgs/2023/08/02/9bc7dbf55ff5cbc0.png)
可以看到在我们将原字符串的hash值作为初始向量修改后，再将拓展的字符串进行特殊填充后攻击得到的hash值与pad(str1)||str2的hash值相同，因此长度拓展攻击成功

## 三、针对sha256的长度拓展攻击
针对SM3的长度拓展攻击利用c实现，这是因为Project4中本人已经实现了SM3的c语言版本，攻击代码如下
```c
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
	printf("\n");
	for (int i = 0; i < mlen; i += 1) { 
		printf("%08x ", m[i]);
		if (i % 8 == 7) {
			printf("\n");
		}
	}
	printf("-----------------------------------------\n");
	IC(m, mlen);
}
void SM3hashAttack(uint8 s[], uint32 size,uint32 size0) {
	uint64 a = size / 64 + 1;
	short b = size % 64;
	if (b >= 56)
		a = a + 1;
	uint64 mlen = 16 * a;
	uint32* m = padding(s, size, mlen);
	
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
	m[mlen - 1] += a0 * 512;//?
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
```

运行代码，得到以下结果
![](https://s3.bmp.ovh/imgs/2023/08/02/1a43aac259de93e8.png)
在原字符串str1被hash之后，hash值作为初始向量，因此SM3hashAttack函数中无需像正常SM3hash一样初始化IV。接着在SM3hashAttack函数中将待拓展的字符串str2先普通填充，再加上pad(str1)的长度，压缩迭代，得到结果与hash(str3)结果一致，其中str3=pad(str1)||str2，因此长度拓展攻击成功