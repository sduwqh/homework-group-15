# Implement a PGP scheme with SM2

## PGP简介
PGP是一套用于讯息加密、验证的应用程序，主要用于确保电子通信的安全性和隐私性。PGP是由Phil Zimmermann在1991年开发的，旨在为用户提供易于使用的加密工具，以保护他们的通信免受未经授权的访问和窥视。
PGP加密由一系列散列、数据压缩、对称密钥加密，以及公钥加密的算法组合而成。每个步骤支持几种算法，主要内容包括加密和解密、数字签名、密钥管理、信任模型、兼容性。
PGP广泛应用于保护电子邮件、文件传输和数据存储等场景。许多组织和个人使用PGP来保护敏感信息、保护隐私和确保数字通信的安全性。
## 具体实现流程
### 加密

1.用伪随机数生成器生成会话密钥

2.用公钥密码加密会话密钥

3.压缩消息

4.用对称密码加密压缩后信息

5.将加密的会话密钥与加密的消息拼合起来

6.文本转换

![](https://img1.imgtp.com/2023/07/23/MyUED4Zr.png)
### 解密

1.接收者输入解密的口令

2.根据口令生成用于解密私钥的密钥

3.将钥匙串中经过加密的私钥进行解密，得到接收者的私钥

4.将报文数据转换成二进制数据

5.将二进制数据分解成两部分：加密的会话密钥、经过压缩和加密的消息

6.用私钥解密会话密钥

7.将收到的消息用会话密码进行解密

8.对解密得到的消息进行解压缩。

9.得到原始消息。

![](https://img1.imgtp.com/2023/07/23/D2xwimCZ.png)
### 私钥解密（PBE）
PGP 的私钥是保存在用户的钥匙串中的。为了防止钥匙串被盗，私钥都是以加密状态保存的，并在保存时使用了基于口令的密码（PBE）。
PBE算法的核心思想是使用用户提供的密码作为主要密钥来加密数据。密码通常比随机生成的密钥要短和更容易记忆，因此需要通过一些方法将密码转换为可用于加密数据的密钥。这个转换过程通常使用密码哈希函数和盐（salt）来增强安全性。

这次项目中采用了PBKDF2算法，PBKDF2算法通过多次迭代和盐的使用增加了攻击者猜测密码的难度，并提高了系统的安全性。盐是一个随机的值，它使得相同的密码在不同的加密过程中产生不同的密文，避免了常见密码的简单字典攻击。

## 代码实现
### PBE算法实现
~~~python
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
~~~
### PGP加密
~~~python
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
    #m = zlib.compress(m)
    enc_m = crypt_sm4.crypt_cbc(iv , m)
    return enc_m,enc_k, enc_private_key,key
~~~
### PGP解密
~~~python
def PGP_DEC(c,enc_k,KEY,K):
    iv = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' 
    key=K
    private_key = decrypt_data(KEY, key, iv)
    print("解密得sm2私钥：", private_key)
    sm2_crypt = sm2.CryptSM2(
    public_key=public_key, private_key=private_key)
    k=sm2_crypt.decrypt(enc_k)
    crypt_sm4.set_key(k, SM4_DECRYPT)
    print("c:",c)
    m = crypt_sm4.crypt_ecb(c)
    #m = zlib.decompress(m)
    return m,k
~~~

## 运行结果
![](https://img1.imgtp.com/2023/07/23/M8djC4zG.png)