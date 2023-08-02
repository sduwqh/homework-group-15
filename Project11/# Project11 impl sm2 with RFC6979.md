# Project11: impl sm2 with RFC6979
## sm2签名算法
### 数字签名
数字签名是只有信息的发送者才能产生的别人无法伪造的一段数字串，这段数字串同时也是对信息的发送者发送信息真实性的一个有效证明。它是一种类似写在纸上的普通的物理签名，但是使用了公钥加密领域的技术来实现的，用于鉴别数字信息的方法。一套数字签名通常定义两种互补的运算，一个用于签名，另一个用于验证。数字签名是非对称密钥加密技术与数字摘要技术的应用。



![9ebf1d89b4b3d8447cc58a1dfbfbff42.png](https://i2.mjj.rip/2023/07/08/9ebf1d89b4b3d8447cc58a1dfbfbff42.png)



### sm2流程
![36626b32eae324fdda2a8b336fa83397.png](https://i2.mjj.rip/2023/07/08/36626b32eae324fdda2a8b336fa83397.png)

签名流程图示：
![500b9d3df9d5b382467d41f207449f65.png](https://i3.mjj.rip/2023/07/09/500b9d3df9d5b382467d41f207449f65.png)
 通过上述流程，可以发现暴漏k值（签名)相当于暴漏私钥。假设我们每次在进行签名时都使用相同的 k 值，或是选择一个没有那么随机产生出来的 k 值，黑客可通过反推方式求得 k 值， 一旦 k 值遭泄，签名者的私钥 也可轻易的被回推计算出来。具体可分为以下几种情况：

 #### 若k泄露
 ![0018544eca48edb586273af0ef57d0f3.png](https://i2.mjj.rip/2023/07/08/0018544eca48edb586273af0ef57d0f3.png)

#### 若k被同一用户重用
![4784ada083b2e19366e2dd6e7f7ae913.png](https://i2.mjj.rip/2023/07/08/4784ada083b2e19366e2dd6e7f7ae913.png)
#### 若k被不同用户重用
![7ed9d9735bd30c5928e04bf70d61c360.png](https://i2.mjj.rip/2023/07/08/7ed9d9735bd30c5928e04bf70d61c360.png)

因此： k值必须是保密且唯一的，这就是为什么RFC6979提出我们需要有较佳的 k 值选法。

## RFC6979

根据RFC6979的标准文档（https://datatracker.ietf.org/doc/html/rfc6979#autoid-12），
其Key Parameters如下：
E：一个定义在给定有限域上的椭圆曲线。
q：一个足够大的素数（至少为160位），是曲线阶数的约数。
G：E上的一个点，其阶数为q。
ECDSA计算所涉及的群由形如 jG（将点G乘以整数j）的曲线点组成，其中j的取值范围是从0到q-1。G满足qG = 0（在曲线E上的“无穷远点”）。该群的大小为q。
与“GM/T 0003-2012 《SM2椭圆曲线公钥密码算法》”的参数表述略有不同。
这里的q即等价于SM2参数集中的n

RFC6979使用三个长度参数：qlen、blen和rlen。
qlen是q的二进制表示的长度
rlen是qlen向上取整为8的倍数的结果（如果qlen已经是8的倍数，则rlen等于qlen；否则，rlen会稍微大一些，最多为qlen+7）
blen是输入位序列的长度（以位为单位）

RFC6979涉及三种数据类型转换
bits2int：将位序列表示的二进制数据转换为非负整数
int2octets：将整数值 x 转换为一个字节序列
bits2octets：将长度为 blen 的位序列转换为一个字节序列


产生k的流程如下：
首先定义：`HMAC_K(V) `，其指使用密钥(key)K对数据V进行HMAC算法。

给定输入消息m，应用以下过程：
1. 通过哈希函数H处理m，产生：`h1 = H（m）`
2. `V = 0x01 0x01 0x01 ... 0x01`

  > V的长度等于8 * ceil（hlen / 8）。例如，如果H是SHA-256，则V被设置为值为1的32个八位字节的序列。
3. `K = 0x00 0x00 0x00 ... 0x00`

  > K的长度等于8 * ceil（hlen / 8）。
4. `K = HMAC_K（V || 0x00 || int2octets（x）|| bits2octets（h1））`
  >'||'表示连接。x是私钥。
  >
  >' octets '是字节（bits are grouped into octets (sequences of   eight bits)）
5. `V = HMAC_K（V）`

6. `K = HMAC_K（V || 0x01 || int2octets（x）|| bits2octets（h1））`

7. `V = HMAC_K（V）`

8. 执行以下流程，直到找到合适的值k:
   1. 将T设置为空序列。 T的长度（以比特为单位）表示为tlen。(now, tlen = 0)。

   2. 当tlen <qlen时，请执行以下操作：
   `V = HMAC_K（V）`
   `T = T || V`
   >qlen是模数的二进制长度（qlen is the smallest integer such that q is less than 2^qlen.）
   3. 计算`k = bits2int（T）`。
       如果k的值在[1，q-1]范围内，则成功生成k。否则，计算：
       `K = HMAC_K（V || 0x00）`
       `V = HMAC_K（V）`
       并循环，尝试生成一个新的T来计算出合适的k。
   
     根据以上步骤，其python实现如下
```python
def generate_k(private_key, message, qlen, q, hash_func=hashlib.sha256):
    h1 = hash_func(message).digest()
    qlen=qlen*4
    V = b'\x01' * 32
    K = b'\x00' * 32
    private_key=int(private_key,base=16)
    K = hmac.new(K, V + b'\x00' + int2octets(private_key,qlen) + h1, hash_func).digest()
    V = hmac.new(K, V, hash_func).digest()
    K = hmac.new(K, V + b'\x01' + int2octets(private_key,qlen) + h1, hash_func).digest()
    V = hmac.new(K, V, hash_func).digest()
    while True:
        T = ''
        while len(T) < qlen:  
            V = hmac.new(K, V, hash_func).digest()
            T += octets2bit(V)  
        k = bits2int(T,qlen)  

        if 1 <= k < q - 1:
            return k
        
        K = hmac.new(K, V + b'\x00', hash_func).digest()
        V = hmac.new(K, V, hash_func).digest()

```

之后我们调用gmssl库里有关sm2签名算法的源代码加以测试。
（源代码来源：https://github.com/duanhongyi/gmssl/blob/master/gmssl）
并从在线网站上（https://const.net.cn/tool/sm2/genkey/）生成一对适用于sm2算法的密钥。
测试函数的py实现：

```python
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
```

测试结果：
RFC6979生成随机数k的程序的运行时间为0.00011940003605559468毫秒
sm2签名算法运行时间为0.005904999969061464毫秒
signature is valid.
signature: a0e00d843c17e00d4ffb095e53edf35fec00c220a2ba8f9f768a6fd6e26219fd46f2d5af988582d2f9fee56d0f8efd4d32c1aa70425c6a0902a396cd73e1994c


签名正确，我们给出的RFC6979实现可以成功生成满足要求的随机数k。并且从实现性能上来看，生成随机数k所需时间仅为签名算法用时的1/50左右，不会制约sm2算法的签名速度。
