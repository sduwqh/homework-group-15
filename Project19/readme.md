### *Project20: forge a signature to pretend that you are Satoshi

#### 1、ECDSA签名：
ECDSA是ECC与DSA的结合，整个签名过程与DSA类似，所不一样的是签名中采取的算法为ECC，最后签名出来的值也是分为r,s。

**共享信息：**

- 椭圆曲线
- 椭圆曲线基点 $G$
- 哈希算法 $H(\bullet)$
- 映射算法 $X(\bullet)$ 从椭圆曲线上的点到 $F_p$ 的映射关系，取椭圆曲线点的 $x$ 坐标，即 $X(H)=H . x$ 
- 公钥 $P=d G$ ( $d$ 为私钥 $)$
- 待签名消息 $m$

**签名过程如下：**

1.  生成随机数k,计算$$ K=k*G $$

2. 计算$$ e=H(m) $$

3. 生成签名(r,s):$$ r=X(K) ; s=(e+r d) * k^{-1} $$

```python
def sign(d,m):
    k = random.randint(1, p - 1)
    K=EC_mul(k,g)
    r=K[0]%n
    e=hash(m)
    s=((e+r*d)*xgcd(k,n))%n
    return r,s
```

**验证：**

1. 计算 $$ e=H(m) $$
2. 验证 $$ X((eG+rP)*s^{-1})=r $$

```python
def verify(r,s,m,P):
    e=hash(m)
    point=EC_add(EC_mul((e*xgcd(s,n))%n,g),EC_mul((r*xgcd(s,n))%n,P))*xgcd(s,n)
    if point[0]%n==r:
        return True
    else:
        return False
```



#### 2、伪造攻击：

##### $-K$ 点 伪造：
- 已知合法签名 $(e,(r, s))$
- 因 $r=X(K)=X(-K) ，-K$ 对于该签名依然有效。
- 以 $-K$ 点生成签名: $(e,(r,-s))$

```python
verify(r,EC_mul(-1,s),m,P) #true
```

##### e重组伪造：
攻击者模型
- 已知公钥 $P$
- 不考虑哈希函数相关的签名 $(m,(r, s))$ ，仅考虑 $(e,(r, s))$
- 通过 构造 $e$ 重组合法签名
- 选取随机数 $a 、 b$ ，计算 $K=a G+b P$
- ECDSA: 计算 $r=X(K) 、 s=r b^{-1} 、 e=a r b^{-1}$
- SM2: 计算 $r=b-a 、 s=a 、 e=X(K)-b+a$
- $(e,(r, s))$ 即合法签名

```python
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

```

代码运行结果：

> Verify signature:
> True
> -K点伪造签名:
> True
> e重组伪造签名：
> True
