## Implement the above ECMH scheme
ECMH哈希算法：

![](https://img1.imgtp.com/2023/07/22/qGTLdtHs.png)

##### 实现方式：


我们编写和运行了一段实现椭圆曲线哈希(ECMH, Elliptic Curve-based Message Hashing)的代码。这是一种特殊的哈希方法，将输入的消息映射到椭圆曲线上的一个点。本实验通过Python代码展示了椭圆曲线哈希(ECMH)的基本原理和实现方法。这种方法有一些优秀的性质，例如抵抗冲突攻击的能力，这使得它在密码学和区块链技术中有广泛的应用。同时，该方法的实现需要高效的数学运算和算法，如模逆、椭圆曲线点的加法和乘法、Tonelli-Shanks算法等，这些都对我们的编程能力和算法理解能力提出了挑战。

###### 代码概述

代码首先定义了一些基础的数学函数，如`gcd`（求两数的最大公因数）和`xgcd`（求模逆）。这些函数用于后续的椭圆曲线点的加法和乘法运算。

```python
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
```

接下来的部分是椭圆曲线点的加法`EC_add`和乘法`EC_mul`。这两个函数都是在椭圆曲线加法和倍点运算的基础上定义的。

```python
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
```

然后代码定义了一种椭圆曲线，使用的参数是`secp256k1`。这是比特币中所使用的椭圆曲线。

代码还定义了一个`tonelli`函数，实现了Tonelli-Shanks算法，用于求解模平方根，这在后续的哈希函数中会用到。

```python
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

```

最后，代码实现了两个ECMH函数，一个用于对单个消息进行哈希(`ECMH`)，另一个用于对消息集进行哈希(`ECMH_set`)。

```python
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
```

在ECMH函数中，我们首先使用SHA256对输入的消息进行哈希，然后将哈希值作为椭圆曲线的x坐标，求解出对应的y坐标，得到的(x, y)就是该消息的哈希值。如果没有对应的y坐标，则跳过这个x坐标，继续求解下一个。

在ECMH_set函数中，我们对消息集中的每个消息执行ECMH操作，得到一系列的点，然后将这些点相加，得到的结果就是整个消息集的哈希值。

##### 实现效果：代码可直接运行
在代码的最后部分，我们对单个消息和消息集进行了哈希，并测量了所花费的时间。

对于单个消息'1234'，哈希函数输出了一个点，并显示了执行哈希的时间。

对于消息集['1234','5678','0000']，哈希函数输出了一个点，并显示了执行哈希的时间。在这个过程中，我们将每个消息映射到椭圆曲线上的一个点，并将所有的点相加得到最终的哈希值。

![代码运行结果](https://img1.imgtp.com/2023/08/02/a4aYoysh.png)
