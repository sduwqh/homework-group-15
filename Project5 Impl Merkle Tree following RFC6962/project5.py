import math
import hashlib
import random
from tkinter import N
def Create_Merkle_Tree(data):
    Depth=math.ceil(math.log(len(data), 2))+1 #计算深度
    Merkle_Tree=[[] for _ in range(Depth)] #定义一个Merkel_Tree
    #将数据块的hash值存入叶子节点
    #将每两个子节点相加后哈希值写入父节点
    for n in range(1,Depth):
        i=Depth-1-n
        L = math.floor(len(Merkle_Tree[i+1])/2)
        for j in range(0, L):
            Merkle_Tree[i].append((hashlib.sha256(Merkle_Tree[i+1][2*j].encode() + Merkle_Tree[i+1][2*j+1].encode())).hexdigest())
            Merkle_Tree[i].append((hashlib.sha256("0x01".encode()+Merkle_Tree[i+1][2*j].encode() + Merkle_Tree[i+1][2*j+1].encode())).hexdigest())
        if len(Merkle_Tree[i+1])%2 == 1:
               Merkle_Tree[i].append(Merkle_Tree[i+1][-1])
    return Merkle_Tree

def inclusion_proof(m,Merkle_Tree): #寻找存在性证据
    Depth=len(Merkle_Tree)
    m=(hashlib.sha256("0x00".encode()+m.encode())).hexdigest()
    try:
        n=Merkle_Tree[Depth-1].index(m) #在叶子节点中寻找该节点
    except:
        print("该节点不存在在Merkle_Tree中")
        return
    evidence=[]
    for i in range(0,Depth):
    #遍历生成证据
        d=Depth-1-i
        if n%2==0:
            if n == len(Merkle_Tree[d]) - 1:
                pass
            else:
                evidence.append([Merkle_Tree[d][n],Merkle_Tree[d][n+1]])
        else:
            evidence.append([Merkle_Tree[d][n-1],Merkle_Tree[d][n]])
        n = math.floor(n/2)
    evidence.append([Merkle_Tree[0][0]])
    return evidence


def exclusion_proof(m,evidence,root):#验证存在性
     Depth=len(evidence)
     m= (hashlib.sha256("0x00".encode()+m.encode())).hexdigest()
     if evidence[-1][0]!=root:#根节点不符
         return False
     if m !=evidence[0][0]and m !=evidence[0][1]:#子节点不符
         return False
     for i in range(0, Depth-1):
     #遍历所有节点与证据做对比
         node = (hashlib.sha256("0x01".encode()+evidence[i][0].encode() + evidence[i][1].encode())).hexdigest()
         if  node != evidence[i+1][0] and node != evidence[i+1][1]:
             return False
     if (hashlib.sha256("0x01".encode()+evidence[-2][0].encode() + evidence[-2][1].encode())).hexdigest() != evidence[-1][0]:
         return False
     return True


if __name__ == '__main__':
    data=[''.join(random.sample('abcdefghijklmnopqrstuvwxyz0123456789',5)) for i in range(0,100000)]#随机生成10w个节点的数据
    Merkle_Tree =Create_Merkle_Tree(data)
    m=random.randint(0,100000-1)
    evidence=inclusion_proof(data[m],Merkle_Tree)#生成证据
    print(evidence)
    root=Merkle_Tree[0][0]
    print("验证：",exclusion_proof(data[m],evidence,root))#验证证据