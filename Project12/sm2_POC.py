from gmssl import sm2

data1 = b'Hello, world!'
data2 = b'i love China!'
k0 = '123456789'
k = int(k0, 16)

private_key = '5BAAD23ECD879BA8101D6FD5711E60BC587578C1DA0701F19A939B94C7B00BC3'
public_key = 'E063BBCD83C503AFBC876211A5EE5889131EABCEDAF70F21FA36BAC38F183CB2B1B3C24F923EEDEEA103FA327033ED39A363B4358B940A964005004BC2D8B5CB'
# 创建CryptSM2对象
crypt_sm2 = sm2.CryptSM2(private_key, public_key)
n = int(crypt_sm2.ecc_table['n'], 16)
print("user1 signed message1 with d1")

signature1 = crypt_sm2.sign(data1, k0)
# 打印签名结果
print("signature1:", signature1)

# 验证签名
is_valid = crypt_sm2.verify(signature1, data1)
if is_valid:
    print("signature1 is valid.")
else:
    print("signature1 is invalid.")

print("user1 signed message2 with d1")

signature2 = crypt_sm2.sign(data2, k0)
# 打印签名结果
print("signature2:", signature2)

print("user2 signed message2 with d2")
private_key = '8077EADA412C4E7FE6DB8821C8A2526C1CCAF56F8D67D3675E2F25A3E62EB189'
public_key = '771DB722DDB414671B3BD6123BA761A65EA07C47E28FAF40B4F9BE1897A8BA654921C69CDA1BC47E909D927157BCFACFB6781A3A2B1CD63C96E13D66268A40AE'
# 创建新的CryptSM2对象代表另一个user
crypt_sm2_1 = sm2.CryptSM2(private_key, public_key)
signature3 = crypt_sm2_1.sign(data2, k0)
print("signature3:", signature3)

# 1.leaking k
print("when leaking k...")
R_str1 = signature1[:64]  # 提取前64个字符作为 R 的字符串表示
S_str1 = signature1[64:]  # 提取后64个字符作为 S 的字符串表示
R1 = int(R_str1, 16)  # 将 R 的字符串表示转换为整数值
S1 = int(S_str1, 16)  # 将 S 的字符串表示转换为整数值
inv = pow(R1 + S1, int(crypt_sm2.ecc_table['n'], base=16) - 2, int(crypt_sm2.ecc_table['n'], base=16))
# one can compute d with k and signature
d = ((k - S1) * inv) % n
if d == int(crypt_sm2.private_key, 16):
    print("compute d successfully")
    print("d=", '%064x' % d)
else:
    print("fail to compute d")

# 2.reusing k
print("when reusing k...")

R_str2 = signature2[:64]
S_str2 = signature2[64:]
R2 = int(R_str2, 16)
S2 = int(S_str2, 16)
inv1 = pow(S1 - S2 + R1 - R2, int(crypt_sm2.ecc_table['n'], base=16) - 2, int(crypt_sm2.ecc_table['n'], base=16))

# Recovering user1 secret key with 2 signatures
d1 = ((S2 - S1) * inv1) % n
if d1 == int(crypt_sm2.private_key, 16):
    print("compute d successfully")
    print("d=", '%064x' % d1)
else:
    print("fail to compute d")

# reusing k by different users
print("when reusing k by different users...")
R_str3 = signature3[:64]
S_str3 = signature3[64:]
R3 = int(R_str3, 16)
S3 = int(S_str3, 16)
inv2 = pow(S3 + R3, int(crypt_sm2.ecc_table['n'], base=16) - 2, int(crypt_sm2.ecc_table['n'], base=16))
inv3 = pow(S1 + R1, int(crypt_sm2.ecc_table['n'], base=16) - 2, int(crypt_sm2.ecc_table['n'], base=16))
# user1 can deduce user3 secret key
d2 = ((k - S3) * inv2) % n
if d2 == int(crypt_sm2_1.private_key, 16):
    print("user1 computed user3's d successfully")
    print("d=", '%064x' % d2)
else:
    print("fail to compute d")
# user3 can deduce user1 secret key
d3 = ((k - S1) * inv3) % n
if d3 == int(crypt_sm2.private_key, 16):
    print("user3 computed user1's d successfully")
    print("d=", '%064x' % d3)
else:
    print("fail to compute d")

# one can forge signature if the verification does not check m
print("when the verification does not check m... ")


def calculate_r(a, b):
    # 计算 k = a * curve.generator + b * P
    P1 = crypt_sm2._kg(a, crypt_sm2.ecc_table['g'])
    P2 = crypt_sm2._kg(b, crypt_sm2.public_key)
    if P1 == P2:
        P1 = '%s%s' % (P1, 1)
        P1 = crypt_sm2._double_point(P1)
    else:
        P1 = '%s%s' % (P1, 1)
        P1 = crypt_sm2._add_point(P1, P2)
        P1 = crypt_sm2._convert_jacb_to_nor(P1)
    x = int(P1[0:crypt_sm2.para_len], 16)
    # 返回r=X(K)
    return x


a = 123456789
b = 987654321
r = b - a
s = a
e = b - a - calculate_r(a, b)
R_str5 = format(r, f'0{64}X')
S_str5 = format(s, f'0{64}X')
signature5 = R_str5 + S_str5


# 不检查m，而直接检查e的验签函数
def verify(self, Sign, e):
    # 验签函数，sign签名r||s，E消息hash，public_key公钥

    r = int(Sign[0:self.para_len], 16)
    s = int(Sign[self.para_len:2 * self.para_len], 16)
    t = (r + s) % int(self.ecc_table['n'], base=16)
    if t == 0:
        return 0

    P1 = self._kg(s, self.ecc_table['g'])
    P2 = self._kg(t, self.public_key)
    if P1 == P2:
        P1 = '%s%s' % (P1, 1)
        P1 = self._double_point(P1)
    else:
        P1 = '%s%s' % (P1, 1)
        P1 = self._add_point(P1, P2)
        P1 = self._convert_jacb_to_nor(P1)

    x = int(P1[0:self.para_len], 16)
    return r == ((e + x) % int(self.ecc_table['n'], base=16))


is_valid = verify(crypt_sm2, signature5, e)
if is_valid:
    print("forge signature successfully")
else:
    print("fail to forge signature")

# Same d and k with ECDSA, leads to leaking of d
print("when using same d and k with ECDSA...")
# 私钥（十六进制或整数形式）
private_key = int(crypt_sm2.private_key, 16)
# 因为ECDSA签名算法的库函数不包括SM2所使用的椭圆曲线参数集。所有这里我们自定义一个与SM2推荐相同的椭圆曲线参数集。
# 用于ECDSA签名算法。并结合已有的库函数给出ECDSA算法的完整py实现。
import collections
import hashlib

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')

curve = EllipticCurve(
    'secp256k1',
    # Field characteristic.
    p=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    # Curve coefficients.
    a=0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    b=0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
    # Base point.
    g=(0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
       0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0),
    # Subgroup order.
    n=0xfffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123,
    # Subgroup cofactor.
    h=1,
)


def inverse_mod(k, p):
    """Returns the inverse of k modulo p.

    This function returns the only integer x such that (x * k) % p == 1.

    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points #########################################

def is_on_curve(point):
    """Returns True if the given point lies on the elliptic curve."""
    if point is None:
        # None represents the point at infinity.
        return True

    x, y = point

    return (y * y - x * x * x - curve.a * x - curve.b) % curve.p == 0


def point_neg(point):
    """Returns -point."""
    assert is_on_curve(point)

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    assert is_on_curve(result)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""
    assert is_on_curve(point1)
    assert is_on_curve(point2)

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p,
              -y3 % curve.p)

    assert is_on_curve(result)

    return result


def scalar_mult(k, point):
    """Returns k * point computed using the double and point_add algorithm."""
    assert is_on_curve(point)

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

        # Double.
        addend = point_add(addend, addend)

        k >>= 1

    assert is_on_curve(result)

    return result


# Keypair generation and ECDSA

def make_keypair(private_key):
    """Generates a random private-public key pair."""
    public_key = scalar_mult(private_key, curve.g)

    return public_key


def hash_message(message):
    """Returns the truncated SHA521 hash of the message."""
    message_hash = hashlib.sha512(message).digest()
    e = int.from_bytes(message_hash, 'big')

    # FIPS 180 says that when a hash needs to be truncated, the rightmost bits
    # should be discarded.
    z = e >> (e.bit_length() - curve.n.bit_length())

    assert z.bit_length() <= curve.n.bit_length()

    return z


def sign_message(private_key, message):
    z = hash_message(message)

    r = 0
    s = 0

    while not r or not s:
        k = int('123456789', 16)
        x, y = scalar_mult(k, curve.g)

        r = x % curve.n
        s = ((z + r * private_key) * inverse_mod(k, curve.n)) % curve.n

    return r, s


def verify_signature(public_key, message, signature):
    z = hash_message(message)

    r, s = signature

    w = inverse_mod(s, curve.n)
    u1 = (z * w) % curve.n
    u2 = (r * w) % curve.n

    x, y = point_add(scalar_mult(u1, curve.g),
                     scalar_mult(u2, public_key))

    if (r % curve.n) == (x % curve.n):
        return 'signature matches'
    else:
        return 'invalid signature'


public = make_keypair(private_key)
signature = sign_message(private_key, data1)
# With the two sigs, private key d can be recovered:
e = hash_message(data1)
R = signature[0]
S = signature[1]
inv4 = pow(R - S * S1 - S * R1, -1, n)
d4 = ((S * S1 - e) * inv4) % n
if d4 == int(private_key):
    print("compute d successfully")
    print("d=", '%064x' % d4)
else:
    print("fail to compute d")
