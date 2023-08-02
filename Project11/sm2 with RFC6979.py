import hashlib
import hmac
from gmssl import sm2
import time

def octets2bit(octet_string):
    bit_string = ""
    for octet in octet_string:
        binary = bin(octet)[2:].zfill(8)  # 将八位字节转换为二进制字符串，并填充到8位
        bit_string += binary

    return bit_string


def bits2int(bit_string, qlen):
    blen = len(bit_string)
    if qlen < blen:
        bit_string = bit_string[:qlen]  # 截断位序列
    else:
        bit_string = '0' * (qlen - blen) + bit_string  # 扩展位序列

    result = 0
    for bit in bit_string:
        result = result * 2 + int(bit)  # 大端法转换为整数

    return result


def int2octets(integer_value, qlen):
    rlen = 8 * ((qlen + 7) // 8)  # 计算位序列的长度，向上取整到最接近的8的倍数
    bit_string = bin(integer_value)[2:].zfill(rlen)  # 将整数转换为二进制字符串，并填充到指定长度

    octet_string = bytes([int(bit_string[i:i + 8], 2) for i in range(0, rlen, 8)])  # 将位序列按8位一组转换为八位字节序列

    return octet_string


def generate_k(private_key, message, qlen, q, hash_func=hashlib.sha256):
    h1 = hash_func(message).digest()
    qlen = qlen * 4
    V = b'\x01' * 32
    K = b'\x00' * 32
    private_key = int(private_key, base=16)
    K = hmac.new(K, V + b'\x00' + int2octets(private_key, qlen) + h1, hash_func).digest()
    V = hmac.new(K, V, hash_func).digest()
    K = hmac.new(K, V + b'\x01' + int2octets(private_key, qlen) + h1, hash_func).digest()
    V = hmac.new(K, V, hash_func).digest()
    while True:
        T = ''
        while len(T) < qlen:  # 以位为单位计算长度
            V = hmac.new(K, V, hash_func).digest()
            T += octets2bit(V)  # 将字节序列转换为位序列
        k = bits2int(T, qlen)  # 将位序列转换为整数

        if 1 <= k < q - 1:
            return k

        K = hmac.new(K, V + b'\x00', hash_func).digest()
        V = hmac.new(K, V, hash_func).digest()


# 16进制的公钥和私钥
private_key = '00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key=private_key)
data = b"hello sm2!"  # bytes类型
n = int(sm2_crypt.ecc_table['n'], 16)

start = time.perf_counter()
#RFC6979生成随机数k
k = hex(generate_k(private_key, data, sm2_crypt.para_len, n))
end = time.perf_counter()
# 计算程序运行时间
elapsed = end - start
print(f"RFC6979生成随机数k的程序的运行时间为{elapsed}毫秒")

start = time.perf_counter()
#签名
sign = sm2_crypt.sign(data, k)
end = time.perf_counter()
# 计算程序运行时间
elapsed = end - start
print(f"sm2签名算法运行时间为{elapsed}毫秒")

assert sm2_crypt.verify(sign, data)
print("signature is valid.")
print("signature:", sign)
