import binascii
import hashlib
import ecdsa
from ecdsa.util import sigencode_strings


def generate_ecdsa_keypair():
    # 选择曲线参数集（例如，secp256k1）
    curve = ecdsa.SECP256k1

    # 生成私钥
    private_key = ecdsa.SigningKey.generate(curve=curve)
    # 获取对应的公钥
    public_key = private_key.get_verifying_key()
    # 返回公钥和私钥
    return private_key.to_string(), public_key.to_string()


def ecdsa_sign(private_key, message):
    # 创建签名对象
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)

    # 对消息进行签名
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


#
# private_key, public_key = generate_ecdsa_keypair()
#
# print("Private key:", private_key.hex())
# print("Public key:", public_key.hex())
private_key = b'l\xb6\x04\x89-\x01\xb4\xd3\xab\x0f}\xa0\xc0\xee@\n\x9c\xc9\x7f\x0b\x7f\xff&\x0bv\x82\xe9\x91\xbd\x13\xe0\xfe'
public_key = b'\xf6\x8b\xb7\xcc\x9aRSf\x9d\xba\x17[q\xdf\xb6<3\xa3q\xb0\xa6\xd5\x86\xc7\xbc\xbd\xb32\x1b9\xd7\x8a\x80\xebEGF#\xfa\xd0\x8e\x8b?Ib8\x80\x9cv\xa6\x8b\xf2\xa2\xa4\x98:\xad\x01\xf0X\x83+\x8e\xf7'
print("Private key:", private_key.hex())
# 要签名的消息
message = b"Hello, World!"

# 签名
signature = ecdsa_sign(private_key, message)
print("Signature (r, s):", signature)

# 验证签名
is_valid = ecdsa_verify(public_key, signature, message)
print("Is valid:", is_valid)

# 获取 secp256k1 参数集
curve = ecdsa.curves.SECP256k1
curve_name = curve.name

p = curve.curve.p()
n = curve.order
a = curve.curve.a()
b = curve.curve.b()
gx, gy = curve.generator.x(), curve.generator.y()
print("n=", n)
r = signature[0]
s = signature[1]
# signature=(4051293998585674784991639592782214972820158391371785981004352359465450369227, 89594240186149241594009538665606955547794554066464651092432507913778975713381)
# is_valid = ecdsa_verify(public_key, signature, message)
# print("Is valid:", is_valid)

# Leaking k leads to leaking of d
print("when leaking k...")
k = 123456789

hm = hashlib.sha1(message).digest()
e = int(hm.hex(), 16)
inv = pow(r, -1, n)
d = (((s * k) - e) * inv) % n
if d == int(private_key.hex(), 16):
    print("compute d successfully")
    print("d=", '%064x' % d)
else:
    print("fail to compute d")

# Reusing k leads to leaking of d
print("when reusing k...")
message1 = b"i love china!"

hm = hashlib.sha1(message1).digest()
e1 = int(hm.hex(), 16)
signature1 = ecdsa_sign(private_key, message1)
print("Signature1 (r, s):", signature1)
# Recovering d with 2 signatures and message
r1 = signature1[0]
s1 = signature1[1]
inv1 = pow(s1 * r - s * r1, -1, n)
d1 = ((s * e1 - s1 * e) * inv1) % n
if d1 == int(private_key.hex(), 16):
    print("compute d successfully")
    print("d=", '%064x' % d)
else:
    print("fail to compute d")

# reusing k by different users
print("when reusing k by different users...")
# other user(user1)
private_key1, public_key1 = generate_ecdsa_keypair()

print("Private key:", private_key1.hex())
# 签名
signature2 = ecdsa_sign(private_key1, message1)
print("Signature2 (r, s):", signature2)

# 验证签名
is_valid = ecdsa_verify(public_key1, signature2, message1)
print("Is valid:", is_valid)
r2 = signature2[0]
s2 = signature2[1]
# user1 compute user's d with two signatures , his own d and messages
inv2 = pow(s * r2, -1, n)
d2 = ((s2 * e + s2 * d * r - s * e1) * inv2) % n
if d2 == int(private_key1.hex(), 16):
    print("compute d successfully")
    print("d=", '%064x' % d2)
else:
    print("fail to compute d")
# user compute user1's d with two signatures , his own d and messages
inv3 = pow(s2 * r, -1, n)
d3 = ((s * e1 + s * d2 * r2 - s2 * e) * inv3) % n
if d3 == int(private_key.hex(), 16):
    print("compute d successfully")
    print("d=", '%064x' % d3)
else:
    print("fail to compute d")

# Malleability, e.g. r, s and r, -s, are both valid signatures, lead to blockchain network split
print("when r, s and r, -s, are both valid signatures...")
signature3 = (signature[0], -signature[1] % n)
is_valid = ecdsa_verify(public_key, signature3, message)
if is_valid:
    print("signature:(r,-s) is valid.")

# One can forge signature if the verification does not check m
print("when the verification does not check m... ")
from ecdsa import VerifyingKey, SECP256k1


def calculate_r(a, b, public_key):
    # 假设有一个名为public_key的ECDSA公钥
    vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
    # 计算 a * curve.generator
    aG_point = a * SECP256k1.generator
    # 计算 b * P
    bP_point = b * vk.pubkey.point
    # 计算 k = a * curve.generator + b * P
    k_point = aG_point + bP_point
    # 返回r=X(K)
    return k_point.x() % n


a = 12345  # 随机数a
b = 67890  # 随机数b


def ecdsa_verify2(public_key, signature, e):
    # 创建验证对象
    verifying_key = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    # 编码 (r, s) 元组为字节串格式的签名
    signature = ecdsa.util.sigencode_string(signature[0], signature[1], verifying_key.curve.order)
    print(signature)
    # 验证签名,跳过了verify函数，直接调用下一层的verify_digest函数，即不检查message,只检查哈希值e
    is_valid = verifying_key.verify_digest(signature, e, sigdecode=ecdsa.util.sigdecode_string)
    # 返回验证结果
    return is_valid


r = calculate_r(a, b, public_key) % n
s = r * pow(b, -1, n) % n
e = int(a * r * pow(b, -1, n) % n)
e1 = e.to_bytes((e.bit_length() + 7) // 8, 'big')
signature = (r, s)
is_valid = ecdsa_verify2(public_key, signature, e1)
print("is valid =", is_valid)
if is_valid:
    print("forge signature successfully")

# Ambiguity of DER encode could lead to blockchain network split
print("when user encoded with Ambiguity...")
from pyasn1.type import univ
from pyasn1.codec.der import encoder


def encode_der(num):
    # 创建Integer类型对象
    integer_value = univ.Integer(num)

    # 进行DER编码并返回编码后的bytes类型数据
    encoded_der = encoder.encode(integer_value)
    return encoded_der


def ecdsa_verify1(public_key, signature, message):
    # 创建验证对象
    verifying_key = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    # 编码 (r, s) 元组为字节串格式的签名
    signature = encode_der(signature[0]) + encode_der(signature[1])
    print("after DER:", signature)
    # 验证签名
    is_valid = verifying_key.verify(signature, message)
    # 返回验证结果
    return is_valid


is_valid = ecdsa_verify(public_key, signature, message)
print("Is valid1:", is_valid)
