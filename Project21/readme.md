## Schnorr Batch

项目完成人： 王庆华

### 1、Schnorr数字签名算法简单流程

Setup:   

  ![](https://img1.imgtp.com/2023/08/02/rYPFd8pT.png)

Sign:


![](https://img1.imgtp.com/2023/08/02/w1OMVpqK.png)

Verify:

  ![](https://img1.imgtp.com/2023/08/02/B4dIkb8u.png)

```python
def sign(msg,sk):
    r=random.randint(0,n-1)
    R=EC_mul(G,r)
    e = sha256(R[0].to_bytes(32, byteorder="big") + bytes_point(EC_mul(G, sk)) + msg)
    s=r+e*sk
    return R,s

#sG=R+e*pk
def verify(msg,pk,R,sig):
    e = sha256(R[0].to_bytes(32, byteorder="big") + bytes_point(pk) + msg)
    s1=EC_add(R,EC_mul(pk,e))
    s2=EC_mul(G,sig)
    if s1==s2:
        return True
    else:
        return False
```



### 2、schnorr batch verify

![](https://img1.imgtp.com/2023/07/11/xHFxjOpY.png)

```python
def schnorr_batch(msg_list,pk_list,R_list,sig_list):
    sig=0
    e=[]
    for i in sig_list:
        sig+=i

    s1 = EC_mul(G, sig)
    tmp1=None
    for i in range(0,len(msg_list)):
        e.append(sha256(R_list[i][0].to_bytes(32, byteorder="big") + bytes_point(pk_list[i]) + msg_list[i]))
    for i in range(0,len(msg_list)):
        tmp1=EC_add(tmp1,EC_mul(pk_list[i],e[i]))
    tmp2=None
    for i in range(0, len(msg_list)):
        tmp2=EC_add(tmp2,R_list[i])
    s2=EC_add(tmp1,tmp2)
    if s1==s2:
        return True
    else:
        return False
```

只有三个签名同时验证成功batch才能验证成功，且签名存在随机性

代码运行结果：

![](https://img1.imgtp.com/2023/07/11/pav6LwRA.png)

可见通过batch同时验证签名所用时间减少了50%左右
