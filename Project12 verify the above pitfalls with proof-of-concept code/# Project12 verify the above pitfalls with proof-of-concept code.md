# Project12: verify the above pitfalls with proof-of-concept code
## POC code
POC是“Proof of Concept”的缩写，中文意为“概念验证”或“验证性证明”。在计算机领域，POC通常是指一种方法或代码，用于验证某个漏洞、安全问题或技术的存在与可行性。
POC code（概念验证代码）是指由安全研究人员或黑客编写的一小段代码，用于演示或证明某个漏洞或安全问题的存在。这些代码通常能够利用系统或应用程序的弱点，以某种方式显示攻击者能够利用该漏洞进行未授权的操作，或者可能导致系统遭受攻击。POC代码并不是攻击代码，而是用于证明潜在漏洞的存在，从而促使开发人员或厂商采取措施修复问题，以提高系统的安全性。
## pitfalls
![1690205439277.png](https://img1.imgtp.com/2023/07/24/nngfLncX.png)
### ECDSA
#### 算法介绍
用于数字签名，ECC与DSA的结合，签名过程与DSA类似。选择椭圆曲线Ep(a,b)和基点G，选择私钥d（d<n，n为G的阶），计算公钥P=dG。
签名生成：
选择一个随机数（称为k），该数值在每次签名时都不同。
使用私钥对消息的哈希值进行签名计算：
r = (k * G).x mod n
s = (k^(-1) * (hash + r * private_key)) mod n
其中，G是椭圆曲线上的基点，n是椭圆曲线的阶数，^(-1)表示k的模n逆元，hash是消息的哈希值，private_key是私钥。
signature is (r,s)

签名验证：
接收到消息、签名、以及公钥。
使用公钥计算椭圆曲线上的点R：
R = (s^(-1) * hash * G + s^(-1) * r * public_key).x
验证签名的有效性：
如果R的x坐标等于签名中的r值，则验证通过，否则，验证失败。

我们调用python中的ecdsa库函数,创建签名与验签函数。
```python
import ecdsa
def ecdsa_sign(private_key, message):
    # 创建签名对象
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    # 对消息进行签名
    signature = signing_key.sign(message, k=123456789)
    # 解码字节串格式的签名为 (r, s) 元组
    r, s = ecdsa.util.sigdecode_string(signature, signing_key.curve.order)
    # 返回签名结果
    return r, s

```
如上，在sign函数中指定k=123456789，方便后续攻击演示。
#### Leaking k leads to leaking of d
k泄露会导致私钥d的泄露。
由s = (k^(-1) * (hash + r * private_key)) mod n，
得d=(s*k-hash)*r^(-1) mod n

```python
inv = pow(r, -1, n)
d = (((s * k) - e) * inv) % n
```

经验证，d=private_key
#### Reusing k leads to leaking of d
用户重复使用k会导致私钥泄露
设r1,s1是用户对另一条信息的签名，
由s = (k^(-1) * (hash + r * private_key)) mod n，
s1 = (k^(-1) * (hash + r1 * private_key)) mod n，
推导出下列等式
```python
inv1 = pow(s1 * r - s * r1, -1, n)
d1 = ((s * e1 - s1 * e) * inv1) % n
```
即攻击者可利用两个签名计算出私钥

#### reusing k by different users
两个用户使用相同的随机数k会泄露私钥.
具体来说，用户1可根据自己的私钥，双方的消息和签名计算出用户2的私钥，用户2同样也可如此计算出用户1的私钥。
由s = (k^(-1) * (hash + r * private_key)) mod n，
s2= (k^(-1) * (hash + r2* private_key2) mod n，
对用户1，推导出：
```python
inv2 = pow(s * r2, -1, n)
d2 = ((s2 * e + s2 * d * r - s * e1) * inv2) % n
```
对用户2，推导出：
```python
inv3=pow(s2*r,-1,n)
d3=((s*e1+s*d2*r2-s2*e)*inv3)%n
```

#### Malleability, e.g. r, s and r, -s, are both valid signatures, lead to blockchain network split
在ECDSA中，存在一种签名的“可塑性”（Malleability）问题，这意味着对于同一条消息，可能存在多个不同的有效签名，而这些签名对应的是不同的(r, s)值对。
这种可塑性可能导致区块链网络分裂的问题，具体情况如下：
假设有两个交易A和B，它们的输入是同一笔资金，但使用不同的有效签名进行了签名。由于交易在区块中被打包并广播到网络上，节点将尝试将这两个交易包含在下一个区块中。然而，由于两个交易的签名不同，导致两个不同的区块被挖出，部分网络节点接受区块A，而其他节点接受区块B，从而导致了区块链的分裂。
这种分裂可能导致“双花”问题，即同一笔资金在不同的分支上被多次使用，破坏了区块链的一致性和可信性
我们已知一个有效签名signature=(r,s),则可以伪造一个新的签名（r,-s)。
如下。经运行后，Is valid= True。故ecdsa具有可塑性。

```python
signature3=(signature[0],-signature[1] %n)
is_valid = ecdsa_verify(public_key, signature3, message)
```

#### Ambiguity of DER encode could lead to blockchain network split

在ECDSA中，另一个可能导致区块链网络分裂的问题涉及到DER（Distinguished Encoding Rules）编码的歧义性。

DER是一种用于将数据结构编码为字节序列的规范化方法，通常用于编码ECDSA签名。在DER编码中，由于签名的r和s值的长度可能不固定，存在不同的编码方式，这就导致了歧义性。

在区块链网络中，当交易被打包并广播到网络时，节点会验证交易的签名。如果节点对DER编码的解析方式不一致，可能会导致对同一笔交易的签名验证结果不同，从而造成区块链网络分裂

在原始的ecdsa库中，使用了number_to_string方法编码

```python
def sigencode_strings(r, s, order):
    r_str = number_to_string(r, order)
    s_str = number_to_string(s, order)
    return (r_str, s_str)
def number_to_string(num, order):
    l = orderlen(order)
    fmt_str = "%0" + str(2 * l) + "x"
    string = binascii.unhexlify((fmt_str % num).encode())
    assert len(string) == l, (len(string), l)
    return string
```
在某些情况下，用户可能会未按规定编码自己的签名。
这里假设用户使用pyasn1库的DER编码对自己的签名编码。
下面给出其python实现与基于该编码方式的验签函数。

```python
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
    signature = encode_der(signature[0])+encode_der(signature[1])
    print("after DER:",signature)
    # 验证签名
    is_valid = verifying_key.verify(signature, message, sigdecode=ecdsa.util.sigdecode_string)
    # 返回验证结果
    return is_valid

is_valid = ecdsa_verify1(public_key, signature, message)
```
显然因为编码方式的不同，验证签名的结果也发生改变。一个消息的合法签名经过上述不同编码方式后，未能通过验证签名环节。即验证失败，引起歧义。

#### One can forge signature if the verification does not check m
1.选随机数a、b，计算K=aG+bP
2.计算r=X(K)，s=rb^-1^   , e=a*r*b^-1^
3.验证：s^-1^∗(eG+rP)=r^−1^b∗(arb^−1^G+rP)=aG+bP=K，验证通过

python实现：

```python
def calculate_r(a, b, public_key):
    # 假设有一个名为public_key的ECDSA公钥
    vk = VerifyingKey.from_string(public_key, curve=SECP256k1)
    # 计算 aG
    aG_point = a * SECP256k1.generator
    # 计算 bP
    bP_point = b * vk.pubkey.point
    # 计算 K=aG+bP
    k_point = aG_point + bP_point
    # 返回r=X(K)
    return k_point.x() % n
```
计算出r后按算式计算s,e即可得出伪造签名。
由于验签不检查m,我们直接调用库函数里的verify_digest函数来完成验签。下面是新的验签函数的实现。

```python
def ecdsa_verify2(public_key, signature, e):
    # 创建验证对象
    verifying_key = ecdsa.VerifyingKey.from_string(public_key, curve=ecdsa.SECP256k1)
    # 编码 (r, s) 元组为字节串格式的签名
    signature = ecdsa.util.sigencode_string(signature[0], signature[1], verifying_key.curve.order)
    print(signature)
    # 验证签名,跳过了verify函数，直接调用下一层的verify_digest函数，即不检查message,只检查消息哈希值e
    is_valid = verifying_key.verify_digest(signature, e, sigdecode=ecdsa.util.sigdecode_string)
    # 返回验证结果
    return is_valid
```
将公钥与计算好的伪造签名(r,s)，伪造消息e作为参数输入验签函数。经运行，函数返回值为True。故伪造签名成功。
### SM2
#### 算法介绍
![36626b32eae324fdda2a8b336fa83397.png](https://i2.mjj.rip/2023/07/08/36626b32eae324fdda2a8b336fa83397.png)
我们调用python中的gmssl库,并创建类CryptSM2对象用于表示一个用户，然后调用库里的函数进行签名验签操作。并从在线网站上（https://const.net.cn/tool/sm2/genkey/）生成一对适用于sm2算法的密钥。
```python
from gmssl import sm2
private_key = '8077EADA412C4E7FE6DB8821C8A2526C1CCAF56F8D67D3675E2F25A3E62EB189'
public_key = '771DB722DDB414671B3BD6123BA761A65EA07C47E28FAF40B4F9BE1897A8BA654921C69CDA1BC47E909D927157BCFACFB6781A3A2B1CD63C96E13D66268A40AE'
crypt_sm2 = sm2.CryptSM2(private_key, public_key)

```
#### Leaking k leads to leaking of d
k泄露会导致私钥d的泄露。
![1690897236940.png](https://img1.imgtp.com/2023/08/01/txocytgA.png)
如图，其py实现如下：
```
R_str1 = signature1[:64]  # 提取签名前64个字符作为 R 的字符串表示
S_str1 = signature1[64:]  # 提取签名后64个字符作为 S 的字符串表示
R1 = int(R_str1, 16)  # 将 R 的字符串表示转换为整数值
S1 = int(S_str1, 16)  # 将 S 的字符串表示转换为整数值
inv = pow(R1 + S1, int(crypt_sm2.ecc_table['n'], base=16) - 2, int(crypt_sm2.ecc_table['n'], base=16))
# one can compute d with k and signature
d = ((k - S1) * inv) % n
```
d即为所求，经运行得d=private_key，故计算成功。

#### reusing k
用户重复使用k会导致私钥泄露
![1690897408033.png](https://img1.imgtp.com/2023/08/01/hOWoxXD9.png)
如图，其py实现如下：
```
R_str2 = signature2[:64]
S_str2 = signature2[64:]
R2 = int(R_str2, 16)
S2 = int(S_str2, 16)
inv1 = pow(S1 - S2 + R1 - R2, int(crypt_sm2.ecc_table['n'], base=16) - 2, int(crypt_sm2.ecc_table['n'], base=16))

# Recovering user1 secret key with 2 signatures
d1 = ((S2 - S1) * inv1) % n
```
d1即为所求。经运行得d1=private_key，破解成功。

#### reusing k by different users
两个用户使用相同的随机数k加密不同消息会向彼此泄露自己的私钥.
![1690897539157.png](https://img1.imgtp.com/2023/08/01/l3xga3R5.png)
如图，其py实现如下：
```
R_str3 = signature3[:64]
S_str3 = signature3[64:]
R3 = int(R_str3, 16)
S3 = int(S_str3, 16)
inv2 = pow(S3 + R3, int(crypt_sm2.ecc_table['n'], base=16) - 2, int(crypt_sm2.ecc_table['n'], base=16))
inv3 = pow(S1 + R1, int(crypt_sm2.ecc_table['n'], base=16) - 2, int(crypt_sm2.ecc_table['n'], base=16))

# user1 can deduce user3 secret key
d2 = ((k - S3) * inv2) % n
# user3 can deduce user1 secret key
d3 = ((k - S1) * inv3) % n
```
d2,d3即为用户通过各自的签名计算出对方的私钥。经运行，与私钥相同，故破解成功。

#### one can forge signature if the verification does not check m
如果验签函数不检查消息值而直接检查消息的哈希值，会出现伪造签名攻击。
由验签流程，我们可通过构造e伪造合法签名。
1.选随机数a、b，计算K=aG+bP
2.计算r = b - a， s = a， e = b - a - X(k)
3.验证r=e+X(k) mod n ，通过即验签成功。
py实现如下：
```python
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
    # 返回x=X(K)
    return x
#选取随机数a,b
a = 123456789
b = 987654321
r = b - a
s = a
e = b - a - calculate_r(a, b)
#将r,s还原成字符串形式的签名
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
#验证签名
is_valid = verify(crypt_sm2, signature5, e)
```
经运行得签名有效，故伪造成功。

####  Same d and k with ECDSA, leads to leaking of d
![1690898367293.png](https://img1.imgtp.com/2023/08/01/qvblEjXD.png)
如图，若sm2使用相同的随机数与私钥加密消息，会导致私钥泄露。
其部分py实现如下：

```
# With the two sigs, private key d can be recovered:
e = hash_message(data1)
R = signature[0]
S = signature[1]
inv4 = pow(R - S * S1 - S * R1, -1, n)
d4 = ((S * S1 - e) * inv4) % n
```
这里的R,S是ecdsa的签名，而R1,S1是sm2对相同消息使用相同d和k 的签名。d4即为所求私钥。
这里为确保两种算法的阶数n一致，为ecdsa算法使用了sm2的椭圆曲线参数集 sm2p256v1。ecdsa签名的具体流程可参考完整python文件。

### Schnorr
#### 算法介绍
密钥生成：
选择椭圆曲线Ep(a,b)和基点G，选择私钥d（d<n，n为G的阶），计算公钥P=dG。
签名消息：
签名者已知的是：G-椭圆曲线, H()-哈希函数，m-待签名消息, d-私钥。
选择一个随机数k, 令 R = kG，e=hash(R || M)
令 s = k + ed modn
那么，公钥P对消息m的签名就是：(R, s)，这一对值即为Schnorr签名。
验证签名：
验证者已知的是：G-椭圆曲线, H()-哈希函数，m-待签名消息, P-公钥，(R, s)-Schnorr签名。验证如下等式：
sG = R +eP
若等式成立，则可证明 签名合法

我们调用ecdsa库，按照上述算法流程构建schnorr算法的签名函数与验签函数。这里我们调用了ecdsa的SECP256k1作为椭圆曲线参数集。

#### user1 signed message1 with d1
k泄露会导致私钥d的泄露。
由 s = k + ed modn，
d=(s-k)*e^-1^
其python实现如下：

```python
signature1 = sign(private_key, message1, k)
R, s = signature1
e = int.from_bytes(hashlib.sha256(int(R.x()).to_bytes(32, 'big') + int(R.y()).to_bytes(32, 'big') + message1).digest(),
                   'big')
inv1 = pow(e, -1, n)
d1 = ((s - k) * inv1) % n
```
d1即为所求，经运行d1=private_key，故计算成功。

####  Reusing k leads to leaking of d
用户重复使用k会导致私钥泄露。
由 s = k + ed modn
s1=k+e~1~d modn
可得d=(s-s1)*(e-e~1~)^-1^
其python实现如下：

```python
signature2 = sign(private_key, message2, k)
R1, s1 = signature2
e1 = int.from_bytes(
    hashlib.sha256(int(R1.x()).to_bytes(32, 'big') + int(R1.y()).to_bytes(32, 'big') + message2).digest(), 'big')
inv2 = pow(e - e1, -1, n)
d2 = ((s - s1) * inv2) % n
```
d2即为所求，经运行其与私钥值相同，故计算成功。

#### reusing k by different users
由 s = k + edmodn
s1=k+e~1~d~1~ modn
可推得另一名用户私钥：d=(s-s~1~+e~1~d~1~)e^-1^
同理，另一名用户同样可以通过已知签名和自己的私钥计算出该用户的私钥d~1~
d~1~=(s~1~-s+ed)e~1~^-1^

python实现如下：
```python
signature3 = sign(private_key1, message2, k)
R2, s2 = signature3
e2 = int.from_bytes(
    hashlib.sha256(int(R2.x()).to_bytes(32, 'big') + int(R2.y()).to_bytes(32, 'big') + message2).digest(), 'big')
# user3 compute user1's d with two signatures , his own d and messages
d3 = ((s - s2 + e2 * private_key1) * inv1) % n
# user1 compute user3's d with two signatures , his own d and messages
inv3 = pow(e2, -1, n)
d4 = ((s2 - s + e * private_key) * inv3) % n
```
d3,d4即为所求私钥。

#### Malleability, e.g. r, s and r, -s, are both valid signatures, lead to blockchain network split
在椭圆曲线数字签名算法（比如ECDSA和Schnorr）中，签名的可脆性指的是对于给定的消息和私钥，可以通过对签名进行某些修改而得到一个不同但仍然有效的签名。例如，对于一个有效的签名(r, s)，我们可以构造一个有效的签名(r, -s)。它导致了签名的二义性，可能导致网络分裂和安全问题

#### Ambiguity of DER encode could lead to blockchain network split
在 Schnorr 签名中，如果不对 DER 编码进行规范化处理，可能会导致 DER 编码的二义性问题，从而引发区块链网络分裂。
二义性问题是指对同一个签名结果进行不同的编码，可能导致验证过程的结果不一致。这种情况下，验证签名的一方可能得到不同的签名值，从而导致验证结果的不一致。

####  One can forge signature if the verification does not check m
Schnorr 签名是线性的。线性是签名函数的属性（签名函数以密钥和一条消息作为输入，输出签名）.由验签函数：sG=R+eP,若验签函数不检查消息，则可通过选择消息攻击伪造签名。
攻击者可收集签名者的正确签名集 M，(rllls)和 M~1~ ，(r~1~lls~1~)，设需要签名的消息为M‘ ，然后进行如下计算 ：
(1)计算 R=r+r~1~ modn
(2)计算 S=s+s~1~ modn
(3)计算 e=H(rllls) modn
(4)计算 e~1~=H(r~1~lls~1~) modn
(5)计算 E=e+e~1~ modn
则有SG=R+EP，显然成立。
则 M’，(R||S)就是攻击者假冒签名者进行的正确签名。
因为哈希函数的单向性，我们只可知道伪造消息的哈希值E，当验签函数不检查消息值时，该伪造签名可通过验签流程。
其python实现如下

```python
#调用ecdsa的椭圆曲线库以完成两个椭圆曲线域上的点集运算。
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
```
#### Same d and k with ECDSA, leads to leaking of d
由 s = k + edmodn （Schnorr)
s~1~ = (k^(-1) * (e~1~ + r * private_key)) mod n	(ECDSA)
可推出私钥d=(ss~1~-e~1~)(r~1~+es~1~)^-1^ mod n
python实现如下：

```python
signature = ecdsa_sign(private_key_b, message1)
R3, s3 = signature
hm = hashlib.sha1(message1).digest()
e3 = int(hm.hex(), 16)
# With the two sigs, private key d can be recovered:
inv4=pow(R3+e*s3,-1,n)
d5=((s*s3-e3)*inv4)%n
```

d5即两次签名的共同私钥d。