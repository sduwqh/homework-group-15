from concurrent.futures import ThreadPoolExecutor
from time import time
from pysmx.SM3 import SM3
from itertools import product
from string import printable
import random
#---------------------------------------------------------------------------------------------------------
lib=printable[:-6]
print(lib)


res=dict()
bitlen=48#44 500s
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



