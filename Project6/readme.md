# impl this protocol with actual network communication
![](https://img1.imgtp.com/2023/07/31/tkSHy2rk.png)

## 运行说明
先运行Trusted_Issuer.py，再运行Alice-Bob.py

## 代码说明

Trusted_Issuer为可信任第三方，Alice通过Trusted_Issuer向Bob提供证明，而Bob通过验证Trusted_Issuer给出的证据判断Alice所说是否属实
### Tip
在消息的传输过程中，由于采用的方式为不断对信息进行哈希操作，所以Bob除可对Alice所说判断真假外，无法得到Alice的任何其他信息
### Trusted_Issuer
~~~python
class MyTCPhanler(socketserver.BaseRequestHandler):
   def handle(self):
     while True:
       try:
          data = self.request.recv(1024)
          if len(data) == 0: break
          print('-->收到客户端的消息: ', data)
          lst=[]
          data=int(data)
          seed=random.randint(2^127,2^128)
          s=hashlib.sha256(str(seed).encode()).hexdigest()
          print(s)
          lst.append(s)
          k=up-data
          c=hashlib.sha256(s.encode()).hexdigest()
          for i in range(k-1):
              c=hashlib.sha256(c.encode()).hexdigest()
          sigc=hashlib.sha256(c.encode()).hexdigest()
          lst.append(sigc)
          self.request.send(s.encode('utf-8'))
          self.request.send(sigc.encode('utf-8'))
          print(sigc)
          print(len(sigc))
       except ConnectionResetError:
          break
     self.request.close()
~~~
### Alice和Bob
~~~python
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
~~~

## 运行结果
![](https://img1.imgtp.com/2023/07/31/ZDDiVK4H.png)

