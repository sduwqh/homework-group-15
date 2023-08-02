# Project1 implement the naïve birthday attack of reduced SM3
## 代码实现
为了提高代码运行效率，这里选择了python的多线程库来实现，在实际测试过程中发现双线程的速度是最快的，线程数过高会导致读写字典冲突从而导致线程运行阻塞，降低代码速度，具体代码如下
```python
from concurrent.futures import ThreadPoolExecutor
from time import time
from pysmx.SM3 import SM3
from string import printable
import random
#---------------------------------------------------------------------------------------------------------
lib=printable[:-6]
print(lib)


res=dict()
bitlen=44#44 500s
strlen=bitlen//4
print("bitlen=",bitlen)
def FindCollision():
    sm3 = SM3()
    while True:
        s=''.join(random.sample(lib,20))
        sm3.update(s)
        h=sm3.hexdigest()
        h=h[:strlen]
        if h in res:
            t2=time()
            print('Collision Found')
            print([res[h],s],'hashvalue start with',h)
            print(t2-t1)
        res[h]=s


t1=time()
#FindCollision0()
with ThreadPoolExecutor(max_workers=2) as t:
    task1 = t.submit(FindCollision)
    task2 = t.submit(FindCollision)
    #task3 = t.submit(FindCollision,'2')
    #task4 = t.submit(FindCollision,'3')
    #task5 = t.submit(FindCollision,'4')
    #task6 = t.submit(FindCollision,'5')
#---------------------------------------------------------------------------------------------------------

```
## 运行时间测试
这里我分别选取了SM3的前8,16,24,32,40,48比特来进行碰撞，数据如下
![](https://s3.bmp.ovh/imgs/2023/07/31/28bf0ab36daadd1a.png)
![](https://s3.bmp.ovh/imgs/2023/07/31/c25bf6454b710c81.png)
![](https://s3.bmp.ovh/imgs/2023/07/31/1e1c9d5f09b7895e.png)
![](https://s3.bmp.ovh/imgs/2023/07/31/ad6b674dabf1ba43.png)
![](https://s3.bmp.ovh/imgs/2023/07/31/c3aa521fc57294b4.png)
![](https://s3.bmp.ovh/imgs/2023/07/31/f7c415e7d5a5a87a.png)

下表记录了找到第一对碰撞的时间
|bit|time|
|-----|-----|
|8bit|0.003s|
|16bit|0.023s|
|24bit|0.951s|
|32bit|18.204s|
|40bit|207.783s|
|48bit|4529.371s|

最高找到48bit的碰撞
