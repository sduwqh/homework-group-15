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