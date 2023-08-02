from smtplib import SMTPDataError
from socket import *
import hashlib
client = socket(AF_INET, SOCK_STREAM)
client.connect(('127.0.0.1', 8081))
class Alice:
    def __init__(self,s,sigc,d):
        self.s=s
        self.sigc=sigc
        self.d=d
    def proof(self):
        p=hashlib.sha256(self.s.encode()).hexdigest()
        for i in range((self.d)-1):
              p=hashlib.sha256(p.encode()).hexdigest()
        return p
class Bob:
     def __init__(self,p,sigc,d):
        self.p=p
        self.sigc=sigc
        self.d=d
     def proof(self):
         c=hashlib.sha256(self.p.encode()).hexdigest()
         for i in range(self.d-1):
             c=hashlib.sha256(c.encode()).hexdigest()
         return c
while True:
   sdata = input('请输入出生年份：')
   client.send(sdata.encode('utf-8'))
   s=client.recv(1024).decode()
   print(s)
   sigc=client.recv(1024).decode()
   print(sigc)
   d=int(input("Which year do want to prove that you are borned in："))
   d1=d-int(sdata)
   alice=Alice(s,sigc,d1)
   d2=2100-d
   p=alice.proof()
   bob=Bob(p,sigc,d2)
   c=bob.proof()
   sig=hashlib.sha256(c.encode()).hexdigest()
   if sig==sigc:
       print("Bob检验结果：",True)
   else:
       print("Bob检验结果：",False)
client.close()
