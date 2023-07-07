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


# 椭圆曲线参数
a = 2
b = 2
p = 17
g = [5, 1]
n = 19



def sign(d,m):
    k = random.randint(1, p - 1)
    K=EC_mul(k,g)
    r=K[0]%n
    e=hash(m)
    s=((e+r*d)*xgcd(k,n))%n
    return r,s

def verify(r,s,m,P):
    e=hash(m)
    point=EC_add(EC_mul((e*xgcd(s,n))%n,g),EC_mul((r*xgcd(s,n))%n,P))*xgcd(s,n)
    if point[0]%n==r:
        return True
    else:
        return False


d = 5  #私钥
m = 'Satoshi'
e = hash(m)
P = EC_mul(d, g)

r,s=sign(d,m)
print("Verify signature:")
print(verify(r,s,m,P))

#-K点伪造签名
print("-K点伪造签名:")
print(verify(r,EC_mul(-1,s),m,P))

#e重组
def e_Reorganization_attack():
    a1 = random.randint(1, p - 1)
    b1 = random.randint(1, p - 1)
    K1=EC_add(EC_mul(a1,g),EC_mul(b1,P))
    r1=K1[0]%n
    s1=(r1*xgcd(b1,n))%n
    e1=(a1*r1*xgcd(b1,n))%n
    return e1,r1,s1

def verify_attack(e,r,s,m,p):
    point = EC_add(EC_mul((e * xgcd(s, n)) % n, g), EC_mul((r * xgcd(s, n)) % n, P)) * xgcd(s, n)
    if point[0] % n == r:
        return True
    else:
        return False

print("e重组伪造签名：")
e1,r1,s1=e_Reorganization_attack()
print(verify_attack(e1,r1,s1,m,p))
