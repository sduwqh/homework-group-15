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

def receive_p(client):
    x,addr=client.recvfrom(1024)
    y,addr=client.recvfrom(1024)
    x = int(x.decode(),16)
    y = int(y.decode(),16)
    return x,y,addr

def create_d2_p(x,y):
    d2=randint(1,n-1)
    x,y=mul(x,y,invert(d2,p))
    x,y=epoint_add(x,y,x_G,-y_G)
    return d2,x,y

def receive_q1_e(client):
    x,addr=client.recvfrom(1024)
    y,addr=client.recvfrom(1024)
    e,addr = client.recvfrom(1024)
    x=int(x.decode(),16)
    y=int(y.decode(),16)
    e=int(e.decode(),16)
    return x,y,e
def creat_r_s2_s3(client,q1_x,q1_y,e,addr):
    k2 = randint(1,n-1)
    k3 = randint(1,n-1)
    Q2=mul(x_G,x_G,k2)
    x1,y1=mul(q1_x,q1_y,k3)
    x1,y1=epoint_add(x1,y1,Q2[0],Q2[1])
    r =(x1 + e)%n
    s2 = (d2 * k3)%n
    s3 = (d2 * (r+k2))%n
    client.sendto(hex(r).encode(),addr)
    client.sendto(hex(s2).encode(),addr)
    client.sendto(hex(s3).encode(),addr)



HOST=""
PORT=8090
#addr=(HOST,PORT)
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client.bind(("", 8090))
p1_x,p1_y,addr=receive_p(client)
d2,x_p,y_p=create_d2_p(p1_x,p1_y)
q1_x,q1_y,e=receive_q1_e(client)
creat_r_s2_s3(client,q1_x,q1_y,e,addr)
   
