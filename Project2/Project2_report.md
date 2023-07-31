# Project2 implement the Rho method of reduced SM3
## 代码实现
```python
from time import time
from pysmx.SM3 import SM3
from string import digits,ascii_lowercase
import random

lib=digits+ascii_lowercase[:6]
print(lib)
res=dict()
bitlen=8
strlen=bitlen//4
print("bitlen=",bitlen)
def randomstring(length):
    return ''.join([random.choice(lib) for _ in range(length)])

def FindCollision():
    sm3 = SM3()
    s=randomstring(64)
    while True:
        sm3.update(s)
        h=sm3.hexdigest()
        
        hstart=h[:strlen]
        
        if hstart in res:
            t2=time()
            print('Collision Found')
            print([s,res[hstart][0]],'hashvalue start with',hstart)
            print(t2-t1)
            break
        res[hstart]=[s,h]
        s=h

t1=time()
FindCollision()
```
## 运行时间测试
这里我分别选取了SM3的前8,16,24,32,40,48比特来进行碰撞，数据如下
![](https://s3.bmp.ovh/imgs/2023/07/31/15e265c964ae4e85.png)
![](https://s3.bmp.ovh/imgs/2023/07/31/468af2101cc941d7.png)
![](https://s3.bmp.ovh/imgs/2023/07/31/70af44f92271bc96.png)
![](https://s3.bmp.ovh/imgs/2023/08/01/b5e6ce86673f6ec7.png)
![](https://s3.bmp.ovh/imgs/2023/08/01/8bd39325cf575467.png)
![](https://s3.bmp.ovh/imgs/2023/08/01/75f4228897f20135.png)

汇总成表格如下

| bit   | time      |
| ----- | --------- |
| 8bit  | 0.005s    |
| 16bit | 0.087s    |
| 24bit | 2.509s    |
| 32bit | 18.898s   |
| 40bit | 99.974s   |
| 48bit | 4987.498s |
