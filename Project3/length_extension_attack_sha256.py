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



