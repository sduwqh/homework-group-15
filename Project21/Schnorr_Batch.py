import hashlib
import binascii
import random
import time

p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)

def EC_add(p1, p2):
    if (p1 is None):
        return p2
    if (p2 is None):
        return p1
    if (p1[0] == p2[0] and p1[1] != p2[1]):
        return None
    if (p1 == p2):
        lam = (3 * p1[0] * p1[0] * pow(2 * p1[1], p - 2, p)) % p
    else:
        lam = ((p2[1] - p1[1]) * pow(p2[0] - p1[0], p - 2, p)) % p
    x3 = (lam * lam - p1[0] - p2[0]) % p
    return (x3, (lam * (p1[0] - x3) - p1[1]) % p)




def EC_mul(p, n):
    r = None
    for i in range(256):
        if ((n >> i) & 1):
            r = EC_add(r, p)
        p = EC_add(p, p)
    return r

def bytes_point(p):
    return (b'\x03' if p[1] & 1 else b'\x02') + p[0].to_bytes(32, byteorder="big")

def sha256(b):
    return int.from_bytes(hashlib.sha256(b).digest(), byteorder="big")

def on_curve(point):
    return (pow(point[1], 2, p) - pow(point[0], 3, p)) % p == 7

def jacobi(x):
    return pow(x, (p - 1) // 2, p)


sk1=0x0000000000000000000000000000000000000000000000000000000000000001
pk1=EC_mul(G,sk1)
message1=bytearray.fromhex('0000000000000000000000000000000000000000000000000000000000000001')

sk2=0x0000000000000000000000000000000000000000000000000000000000000001
pk2=EC_mul(G,sk2)
message2=bytearray.fromhex('0000000000000000000000000000000000000000000000000000000000000001')

sk3=0x0000000000000000000000000000000000000000000000000000000000000001
pk3=EC_mul(G,sk3)
message3=bytearray.fromhex('0000000000000000000000000000000000000000000000000000000000000001')



def sign(msg,sk):
    r=random.randint(0,n-1)
    R=EC_mul(G,r)
    e = sha256(R[0].to_bytes(32, byteorder="big") + bytes_point(EC_mul(G, sk)) + msg)
    s=r+e*sk
    return R,s

#sG=R+e*pk
def verify(msg,pk,R,sig):
    e = sha256(R[0].to_bytes(32, byteorder="big") + bytes_point(pk) + msg)
    s1=EC_add(R,EC_mul(pk,e))
    s2=EC_mul(G,sig)
    if s1==s2:
        return True
    else:
        return False




sk_list=[sk1,sk2,sk3]
pk_list=[]
msg_list=[message1,message2,message3]
for sk in sk_list:
    pk_list.append(EC_mul(G,sk))

result=[]
for i in range(0,len(msg_list)):
    result.append(sign(msg_list[i],sk_list[i]))

R_list=[]
for i in range(0,len(result)):
    R_list.append(result[i][0])

sig_list=[]
for i in range(0,len(result)):
    sig_list.append(result[i][1])

t1=time.time()
for i in range(len(msg_list)):
    print(verify(msg_list[i],pk_list[i],R_list[i],sig_list[i]))
print("Time:",time.time()-t1)


def schnorr_batch(msg_list,pk_list,R_list,sig_list):
    sig=0
    e=[]
    for i in sig_list:
        sig+=i

    s1 = EC_mul(G, sig)
    tmp1=None
    for i in range(0,len(msg_list)):
        e.append(sha256(R_list[i][0].to_bytes(32, byteorder="big") + bytes_point(pk_list[i]) + msg_list[i]))
    for i in range(0,len(msg_list)):
        tmp1=EC_add(tmp1,EC_mul(pk_list[i],e[i]))
    tmp2=None
    for i in range(0, len(msg_list)):
        tmp2=EC_add(tmp2,R_list[i])
    s2=EC_add(tmp1,tmp2)
    if s1==s2:
        return True
    else:
        return False



t2=time.time()
print(schnorr_batch(msg_list,pk_list,R_list,sig_list))
print("Time:",time.time()-t2)

