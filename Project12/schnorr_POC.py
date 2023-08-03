import hashlib
import random
import ecdsa
import ecpy.curves
from ecdsa.curves import SECP256k1
from ecdsa.numbertheory import inverse_mod
from ecpy.curves import Curve, Point


def generate_key_pair():
    # 选择椭圆曲线参数
    curve = SECP256k1

    # 创建一个随机的私钥
    private_key = random.randint(1, curve.order - 1)

    # 从私钥生成对应的公钥
    public_key = private_key * curve.generator

    return private_key, public_key


def sign(private_key, message, k1=None):
    # 选择椭圆曲线参数
    curve = SECP256k1

    # 随机选择一个临时私钥
    if k1 is not None:
        k = k1
    else:
        k = random.randint(1, curve.order - 1)
    # 从临时私钥生成对应的临时公钥
    R = k * curve.generator
    # 计算 e = H(R || message)
    e = int.from_bytes(
        hashlib.sha256(ecdsa.ellipticcurve.AbstractPoint.to_bytes(R) + message).digest(), 'big')

    # 计算签名的s值
    s = (k + e * private_key) % curve.order

    return R, s


def verify(public_key, message, signature):
    # 选择椭圆曲线参数
    curve = SECP256k1
    # 提取签名中的R和s
    R, s = signature
    # 计算 e = H(R || message)
    e = int.from_bytes(
        hashlib.sha256(ecdsa.ellipticcurve.AbstractPoint.to_bytes(R) + message).digest(), 'big')
    # 计算 sG = s * curve.generator, eP = e * public_key
    # T = R + eP
    sG = ecdsa.ellipticcurve.PointJacobi.__mul__(curve.generator, s)
    T = ecdsa.ellipticcurve.PointJacobi.mul_add(R, 1, public_key, e)
    # 如果计算得到的 R + eP 等于 sG，则验证成功
    return sG == T


curve = ecdsa.curves.SECP256k1
n = curve.order
k = 123456789
# user1 signed message1 with d1
# 生成密钥对
private_key, public_key = generate_key_pair()
print("private key(d)=", private_key)
# 待签名的消息
message1 = b"Hello, Schnorr!"
# 签名
signature1 = sign(private_key, message1, k)
# 验证签名
is_valid = verify(public_key, message1, signature1)
print("Signature is valid:", is_valid)
# Leaking k leads to leaking of d
print("when leaking k...")
R, s = signature1
e = int.from_bytes(hashlib.sha256(int(R.x()).to_bytes(32, 'big') + int(R.y()).to_bytes(32, 'big') + message1).digest(),
                   'big')
inv1 = pow(e, -1, n)
d1 = ((s - k) * inv1) % n
if d1 == private_key:
    print("compute d successfully")
    print("d=", d1)
else:
    print("fail to compute d")

# Reusing k leads to leaking of d
print("when reusing k...")
# user2 signed message2 with d
message2 = b'i love China!'
signature2 = sign(private_key, message2, k)
R1, s1 = signature2
e1 = int.from_bytes(
    hashlib.sha256(int(R1.x()).to_bytes(32, 'big') + int(R1.y()).to_bytes(32, 'big') + message2).digest(), 'big')
inv2 = pow(e - e1, -1, n)
d2 = ((s - s1) * inv2) % n
if d2 == private_key:
    print("compute d successfully")
    print("d=", d2)
else:
    print("fail to compute d")

# reusing k by different users
print("when reusing k by different users...")
# user3 signed message2 with d1 but used same k
private_key1, public_key1 = generate_key_pair()
print("private key1(d1)=", private_key1)
# 签名
signature3 = sign(private_key1, message2, k)
R2, s2 = signature3
e2 = int.from_bytes(
    hashlib.sha256(int(R2.x()).to_bytes(32, 'big') + int(R2.y()).to_bytes(32, 'big') + message2).digest(), 'big')
# user3 compute user1's d with two signatures , his own d and messages
d3 = ((s - s2 + e2 * private_key1) * inv1) % n
if d3 == private_key:
    print("user3 compute user1's d successfully")
    print("d=", d3)
else:
    print("fail to compute d")

# user1 compute user3's d with two signatures , his own d and messages
inv3 = pow(e2, -1, n)
d4 = ((s2 - s + e * private_key) * inv3) % n
if d4 == private_key1:
    print("user1 compute user3's d successfully")
    print("d1=", d4)
else:
    print("fail to compute d")

# Malleability, e.g. r, s and r, -s, are both valid signatures, lead to blockchain network split
print("when（r,s) and (r, −s) are both valid signatures...")
signature4 = (R, (-s))
print(signature4)
# is_valid = verify(public_key, message1, signature4)
# if is_valid:
#     print("signature:(r,-s) is valid.")
# else:
#     print("signature:(r,-s) is invalid.")

# One can forge signature if the verification does not check m
print("when the verification does not check m... ")
R3 = ecdsa.ellipticcurve.PointJacobi.__add__(R, R1)
e3 = (e + e1) % n
s3 = (s + s1) % n
signature5 = (R3, s3)


# 直接检查e而忽略m的验签函数
def verify1(public_key, e, signature):
    # 选择椭圆曲线参数
    curve = SECP256k1
    # 提取签名中的R和s
    R, s = signature
    # 计算 sG = R + eP
    sG = s * curve.generator
    eP = e * public_key

    # 如果计算得到的 sG + eP 等于 R，则验证成功
    return sG == R + eP


is_valid = verify1(public_key, e3, signature5)
if is_valid:
    print("forge signature successfully")

# Same d and k with ECDSA, leads to leaking of d
print("when using same d and k with ECDSA...")
# user4 used ecdsa to sign message1 with same d and k.
import ecdsa
import hashlib

# 椭圆曲线参数
curve = ecdsa.SECP256k1

# 创建私钥对象
signing_key = ecdsa.SigningKey.from_secret_exponent(private_key, curve)

# 获取公钥
public_key = signing_key.get_verifying_key().to_string()

private_key_b = private_key.to_bytes(32, 'big')


def ecdsa_sign(private_key, message):
    # 创建签名对象
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    # 签名
    signature = signing_key.sign(message, k=123456789)
    # 解码字节串格式的签名为 (r, s) 元组
    r, s = ecdsa.util.sigdecode_string(signature, signing_key.curve.order)
    # 返回签名结果
    return r, s


def ecdsa_verify(public_key, signature, message):
    # 创建验证对象
    verifying_key = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    # 编码 (r, s) 元组为字节串格式的签名
    signature = ecdsa.util.sigencode_string(signature[0], signature[1], verifying_key.curve.order)
    # 验证签名
    is_valid = verifying_key.verify(signature, message, sigdecode=ecdsa.util.sigdecode_string)
    # 返回验证结果
    return is_valid


# 签名
signature = ecdsa_sign(private_key_b, message1)
R3, s3 = signature

hm = hashlib.sha1(message1).digest()
e3 = int(hm.hex(), 16)
# With the two sigs, private key d can be recovered:
inv4 = pow(R3 + e * s3, -1, n)
d5 = ((s * s3 - e3) * inv4) % n
if d5 == private_key:
    print("compute  d successfully")
    print("d=", d5)
else:
    print("fail to compute d")

# Ambiguity of DER encode could lead to blockchain network split
print("when user encoded with Ambiguity...")
# 因为我自己实现的schnorr签名算法直接基于算法描述编写，没有一般库函数的层层套接，因此不存在先把消息或签名编码再交给上层函数。故这里暂不给出演示。
# 但显然若编码不规范，就会因为结果的偏差导致签名验证出现分歧。
