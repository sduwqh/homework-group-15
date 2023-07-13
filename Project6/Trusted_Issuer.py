import socketserver
import random
import hashlib
up=2100
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
if __name__ == '__main__':
    server=socketserver.ThreadingTCPServer(('127.0.0.1',8081),MyTCPhanler)
    server.serve_forever() 