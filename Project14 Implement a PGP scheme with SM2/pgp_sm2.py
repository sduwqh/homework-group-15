from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from gmssl import sm2, func
from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT

#sm2公钥
public_key = 'B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207'
#初始化sm4
crypt_sm4 = CryptSM4()

def generate_key_and_salt(password, salt_length=16, iterations=100000):
    # 生成随机盐
    salt = os.urandom(salt_length)
    # 创建PBKDF2HMAC实例并派生密钥
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 输出密钥长度为32字节（256位）
        salt=salt,
        iterations=iterations
    )
    key = kdf.derive(password)

    return key, salt

def encrypt_data(data, key, iv):
    # 创建加密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))

    # 初始化加密器
    encryptor = cipher.encryptor()

    # 添加填充
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    # 加密数据
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data

def decrypt_data(encrypted_data, key, iv):
    # 创建解密器
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    # 初始化解密器
    decryptor = cipher.decryptor()
    # 解密数据
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    # 去除填充
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data_without_padding = unpadder.update(decrypted_data) + unpadder.finalize()

    return data_without_padding

def PGP_ENC(m,k):
    private_key = b'00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5'
    print("sm2私钥：",private_key)
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 
    password = b"mysecretpassword"
    key, salt = generate_key_and_salt(password)
    print("盐：",salt)
    enc_private_key = encrypt_data(private_key, key, iv)
    sm2_crypt = sm2.CryptSM2(
    public_key=public_key, private_key=private_key)
    enc_k = sm2_crypt.encrypt(k)
    crypt_sm4.set_key(k, SM4_ENCRYPT)
    enc_m = crypt_sm4.crypt_cbc(iv , m)
    return enc_m,enc_k, enc_private_key,key
def PGP_DEC(c,enc_k,KEY,K):
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 
    key=K
    private_key = decrypt_data(KEY, key, iv)
    print("解密得sm2私钥：", private_key)
    sm2_crypt = sm2.CryptSM2(
    public_key=public_key, private_key=private_key)
    k=sm2_crypt.decrypt(enc_k)
    crypt_sm4.set_key(k, SM4_DECRYPT)
    m = crypt_sm4.crypt_ecb(c)
    return m,k
message=b'123456789'
print("待传送信息：",message)
key = b'3l5butlj26hvv313'
print("sm4对称加密密钥：",key)
encrypt_value,enc_k,Key,K=PGP_ENC(message,key)
print("私钥口令：",K)
print("私钥钥匙串：",Key)
print("通过sm2加密后sm4对称加密密钥：",enc_k)
dec_message,k=PGP_DEC(encrypt_value,enc_k,Key,K)
print("解密得sm4对称加密密钥：",k)
print("解密：",dec_message)

