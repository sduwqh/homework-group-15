from ftplib import parse150
import hashlib
import socket
from gmpy2 import invert
from random import randint
import sys
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

#生成d1和p1
def create_d_p():
    d1=randint(1,n-1)
    p1=mul(x_G,y_G,d1)
    return d1,hex(p1[0]),hex(p1[1])
def send_Q1_e(client,addr):
    m="123456"
    server_ID = "ID0"
    client_ID = "ID1"
    z = server_ID + client_ID
    m=z+m
    e=hashlib.sha256(m.encode()).hexdigest()
    k1=randint(1,n-1)
    Q1=mul(x_G,y_G,k1)
    x,y=hex(Q1[0]),hex(Q1[1])
    client.sendto(x.encode('utf-8'),addr)
    client.sendto(y.encode('utf-8'), addr)
    client.sendto(e.encode('utf-8'), addr)
    return k1
def receive(client):
    r,addr=client.recvfrom(1024)
    s2,addr=client.recvfrom(1024)
    s3,addr=client.recvfrom(1024)
    r = int(r.decode(),16)
    s2 = int(s2.decode(),16)
    s3 = int(s3.decode(),16)
    return r,s2,s3

def sign(d1,k1,r,s2,s3):
    s=((d1 * k1) * s2 + d1 * s3 - r)%n
    print("Sign:")
    print((hex(r),hex(s)))

if __name__=="__main__":
    HOST = '127.0.0.1'
    PORT=8090
    addr=(HOST,PORT)
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
          client.connect((HOST, PORT))
          print("connection!")
    except Exception:
           print("connection failed")
           sys.exit()
    else:
            d1,x,y=create_d_p()
            client.sendto(x.encode('utf-8'),addr)
            client.sendto(y.encode('utf-8'),addr)
            k1=send_Q1_e(client,addr)
            r,s2,s3=receive(client)
            sign(d1,k1,r,s2,s3)
            client.close()