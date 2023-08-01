import hashlib
import socket
from tkinter import Y
from gmpy2 import invert
from random import randint
#椭圆曲线Fp_256

p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3    
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
x_G = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
y_G = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

#椭圆曲线上的加法(x,y)=(x1,y1)+(x2,y2)
def epoint_add(x1,y1,x2,y2):
    if x1 == x2 and y1 == p-y2:
        return False
    if x1!=x2:
        r=((y2 - y1) * invert(x2 - x1, p))%p#invert函数用于求模逆
    else:
        r=(((3 * x1 * x1 + a)%p) * invert(2 * y1, p))%p
        
    x = (r * - x1 - x2)%p
    y = (r * (x1 - x) - y1)%p
    return x,y

#椭圆曲线上的点乘k*(x,y)
def mul(x,y,k):
    k = k%p
    k = bin(k)[2:]
    rx,ry = x,y
    for i in range(1,len(k)):
        rx,ry = epoint_add(rx, ry, rx, ry)
        if k[i] == '1':
            rx,ry = epoint_add(rx, ry, x, y)
    return rx%p,ry%p
def receive_T1(client):
    x, addr = client.recvfrom(1024)
    y, addr = client.recvfrom(1024)
    x = int(x.decode(), 16)
    y = int(y.decode(), 16)
    return (x,y),addr
def create_T2(T1,client,addr):
    T2 = mul(T1[0], T1[1], invert(d2, p))
    x, y = hex(T2[0]), hex(T2[1])
    client.sendto(x.encode('utf-8'), addr)
    client.sendto(y.encode('utf-8'), addr)
if __name__=="__main__":
   HOST=""
   PORT=8090
   client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   client.bind(("", 8090))
   d2 = 0x5E35D7D3F3C54DBAC72E61819E730B019A84208CA3A35E4C2E353DFCCB2A3B53
   T1,addr=receive_T1(client)
   create_T2(T1,client,addr)

