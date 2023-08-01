import hashlib
import random

def gcd(a, b):
    r = a % b
    while (r != 0):
        a = b
        b = r
        r = a % b
    return b


# 求模逆
def xgcd(a, m):
    if gcd(a, m) != 1:
        return None
    u1, u2, u3 = 1, 0, a
    v1, v2, v3 = 0, 1, m
    while v3 != 0:
        q = u3 // v3
        v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
    return u1 % m


def EC_add(P, Q):
    if (P == 0):
        return Q
    if (Q == 0):
        return P
    if P == Q:
        t1 = (3 * (P[0] ** 2) + a)
        t2 = xgcd(2 * P[1], p)
        k = (t1 * t2) % p
    else:
        t1 = (P[1] - Q[1])
        t2 = (P[0] - Q[0])
        k = (t1 * xgcd(t2, p)) % p
    X = (k * k - P[0] - Q[0]) % p
    Y = (k * (P[0] - X) - P[1]) % p
    Z = [X, Y]
    return Z


# 椭圆曲线上的乘法
def EC_mul(k, g):
    if k == 0:
        return 0
    if k == 1:
        return g
    r = g
    while (k >= 2):
        r = EC_add(r, g)
        k = k - 1
    return r

# 简单椭圆曲线用于测试
# a = 2
# b = 2
# p = 17
# g = [5, 1]
# n = 19


#secp256k1曲线
p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
a = 0
b = 7
n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
G = [Gx, Gy]



def tonelli(n, p):  # tonelli-shanks算法
    # 勒让德符号
    def legendre(a, p):
        return pow(a, (p - 1) // 2, p)

    if (legendre(n, p) != 1):
        return -1
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r


def ECMH(m):
    while (1):
        e=hashlib.sha256(m.encode()).hexdigest()
        e = int(e, 16)
        x = (e ** 3 + a * e + b) % p  # 将hash值映射到椭圆曲线上
        y = tonelli(x, p)
        if (y == -1):
            continue
        return [x, y]


def ECMH_set(m_set):
    H=[]
    i=0
    for m in m_set:
        e = hashlib.sha256(m.encode()).hexdigest()
        e = int(e, 16)
        x = (e ** 3 + a * e + b) % p  # 将hash值映射到椭圆曲线上
        y = tonelli(x, p)
        if (y == -1):
            continue
        H.append([x,y])
        if i==0:
            hash=H[0]
        else:
            hash=EC_add(hash,H[i])
        i=i+1
    return hash




m='1234'
print("single message hash：",ECMH(m))
m_set=['1234','5678','0000']
print("multiple message hashe:",ECMH_set(m_set))