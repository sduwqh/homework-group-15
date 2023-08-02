# Project5 Impl Merkle Tree following RFC6962
## 要求
1.Impl Merkle Tree following RFC6962
2.Construct a Merkle tree with 10w leaf nodes
3.Build inclusion proof for specified element
4.Build exclusion proof for specified element
![](https://img1.imgtp.com/2023/07/06/cYVCIboa.png)

## Merkle tree

Merkle Tree也称为Hash Tree，由Ralph Merkle于1979年提出并命名，是基于Hash的数据结构，它是一种树结构，每个叶节点是数据块的Hash，每个非叶节点是其子节点的Hash。Merkle Tree可以高效和安全地实现较大的数据内容验证，是Hash List和Hash Chain的泛化,也是区块链中的一个基本的组成部分，其被用于分布式系统中，可用于验证计算机之间存储，处理和传输的任何类型数据，确保在P2P网络中收到的数据块没有被破坏或者篡改，甚至有没有发送假数据块。

正是因为有了Merkel tree，以太坊节点才可以建立运行在所有的计算机、笔记本、智能手机，甚至是那些由Slock.it生产的物联网设备之上。Merkle trees的主要作用是快速归纳和校验区块数据的存在性和完整性。一般意义上来讲，它是哈希大量聚集数据“块”的一种方式，它依赖于将这些数据“块”分裂成较小单位的数据块，每一个bucket块仅包含几个数据“块”，然后取每个bucket单位数据块再次进行哈希，重复同样的过程，直至剩余的哈希总数仅变为1。

### 结构
将数据分割成小的Block，并计算数据块的Hash，将相邻两个Hash合并后再计算出父Hash，Hash(Hash(DataBlock1) | Hash(DataBlock2))，再将新的相邻的两个父Hash值进行Hash，生成更上层的Hash，最后会汇聚到树的根节点，称为Merkle Root。
![](https://img1.imgtp.com/2023/07/06/CM47RZRl.png)

在p2p网络下载之前，先从可信的源获得文件的Merkle Tree树根。一旦获得了树根，就可以从其他从不可信的源获取Merkle tree。通过可信的树根来检查其他不可信的Merkle Tree节点。如果当前检测的Merkle Tree结构是损坏的或者虚假的，舍弃当前不可信的获取源，选择其他源获得另一个Merkle Tree，直到获得一个与可信树根匹配的Merkle Tree。

相比与一般的Hash Function以及Hash List，Merkle Tree最重要的好处是可以单独取出Hash树的一个分支对数据进行验证，而不用计算整个Merkle Tree。
### Second Preimage攻击
Merkle Tree的根并不表示树的深度，这将导致second-preimage攻击，攻击者可以创建出一个具有相同Merkle Root的的新Merkle Tree分支。
解决方法：计算叶节点Hash时，在数据前加0x00，在计算内部节点Hash时，在数据前加0x01，限制Hash树的大小是一些正式安全验证的先决条件。一些实现在Hash前使加树深前缀来限制树的深度，在获取Hash链时，每一步都要减少前缀并且到达叶节点时仍为正才被认为有效。
## 实现
### 创建Merkle_Tree

初始化一个二维列表用于存放Merkel tree，计算树的深度和叶子节点的个数，接着计算数据哈希值并写入叶子节点；每两个子节点计算相加后的哈希值并写入父节点列表。，如此重复，直至生成所需Merkel tree。

~~~python
def Create_Merkle_Tree(data):
    Depth=math.ceil(math.log(len(data), 2))+1 #计算深度
    Merkle_Tree=[[] for _ in range(Depth)] #定义一个Merkel_Tree
    Merkle_Tree[Depth-1] = [(hashlib.sha256("0x00".encode()+i.encode())).hexdigest() for i in data]
    #将数据块的hash值存入叶子节点
    #将每两个子节点相加后哈希值写入父节点
    for n in range(1,Depth):
        i=Depth-1-n
        L = math.floor(len(Merkle_Tree[i+1])/2)
        for j in range(0, L):
            Merkle_Tree[i].append((hashlib.sha256("0x01".encode()+Merkle_Tree[i+1][2*j].encode() + Merkle_Tree[i+1][2*j+1].encode())).hexdigest())
        if len(Merkle_Tree[i+1])%2 == 1:
               Merkle_Tree[i].append(Merkle_Tree[i+1][-1])
    return Merkle_Tree
~~~
### 节点存在性证据

首先检查该节点是否位于叶子节点，若不在，则无法生成存在性证据，若在，则根据其所在叶子节点的索引，从底到上遍历Merkle_Tree每层所对应父节点，生成存在性证据。

~~~python
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
~~~
### 验证

首先检查待检验树根节点以及叶节点是否与给定证据中根节点叶节点相同，然后，检查作为证据给出的树的每一层的子节点之和的哈希值是否是它的父节点（即检查是否满足Merkle Tree的结构！），最后，单独测试根节点的子节点是否能够生成根节点，如果能够通过所有测试，则表明检测节点确实在给定根节点的树中。 

~~~python
def exclusion_proof(m,evidence,root):#验证存在性证据
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
~~~

