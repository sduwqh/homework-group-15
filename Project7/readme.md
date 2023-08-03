# Project7: Try to Implement this scheme
## 哈希链 (Hash Chain)
哈希链通常用于认证的过程中，在哈希链之前主要是使用的是 身份-密码 验证的方式。 1981年，Lamport1 提出使用哈希函数的方式代替传统的验证方式。 这种哈希链的形式在后来的实际生活中也有着广泛的应用，而且对后来区块链的出现也有一定的启发意义。
原理：
计算每个数据的哈希值。
将两个数据的哈希值组合，计算哈希值，再与下一个数据的哈希值组合，计算哈希值。以此类推，最后得到链尾的哈希值

## Generalizing Hashchains 
![1690974286001.png](https://img1.imgtp.com/2023/08/02/ivWDJ7Vp.png)
如图所示，我们考虑在接受最多 99999 的整数的系统中，发出的值是数字 03999 的情况。
它将按如下方式工作：发行者将创建 5 条链，以 base10 为基数的每个数字一条。
然后，发行者将把每个哈希链的顶部节点放在一个累加器中。这些值提供给爱丽丝（证明者），显然，所有值都可以通过派生函数计算，因此只会向 Alice 提供一个种子值。
现在，为了让爱丽丝证明她有一个承诺 ，她将提供黄色（明亮）颜色的节点，如上图所示。简而言之，她从每个链的顶部节点开始计数，并根据她需要证明的数字，返回相应的节点。
现在，在 Carol 收到上述五个值后，她将应用与值 0 1 4 9 2 显示的迭代调用一样多次数的哈希函数。因此，第一个数字为零次，第二个数字为一次，第三个数字为四次，依此类推。最终，Carol 可以计算每个链的所有顶级节点，从而确信 Alice 被释放了一个值至少为 01492 的整数。
其python实现如下：
```python
import hashlib
import random
import string


def generate_salt(length):
    # 生成指定长度的随机数
    letters = string.ascii_letters + string.digits
    salt = ''.join(random.choice(letters) for i in range(length))
    return salt


def derive_seed_from_key_with_salt(key, salt):
    # 将随机数与密钥拼接在一起，然后使用SHA-256作为密钥派生函数，派生种子值
    data = key + salt.encode()
    seed = hashlib.sha256(data).digest()
    return seed


def hash_function(value, k=None):
    if k is not None:
        for i in range(k):
            hm = hashlib.sha256(str(value).encode()).hexdigest()
            value = hm
        return value
    return hashlib.sha256(str(value).encode()).hexdigest()


# 根据承诺值创建哈希链
def create_hash_chain(seed, n):
    chain = [hash_function(seed)]
    if n == 0:
        return chain
    for i in range(n):
        chain.append(hash_function(chain[i]))
    return chain


# Alice 根据要证明的数字返回相对应的节点
def prove_commitment(chains, value):
    proof = []
    i = 0
    for digit in value:
        node_index = i
        chain_index = len(chains[node_index]) - int(digit) - 1
        proof.append(chains[node_index][chain_index])
        i = i + 1
    return proof


# 接收方通过证明方提供的节点和相应迭代次数进行哈希。并与顶级结点比较，若相同则证明成功。
def verify_proof(chains, proof, value):
    top_nodes = [chain[len(chain) - 1] for chain in chains]
    proofhash = [hash_function(a, int(b)) for a, b in zip(proof, value)]
    for i in range(len(proof)):
        if proofhash[i] != top_nodes[i]:
            return False
    return True


if __name__ == "__main__":
    # 假设key是一个随机的32字节值
    SEED = []
    seed = b'\x01\x23\x45\x67\x89\xab\xcd\xef\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff'
    SEED.append(seed)
    for i in range(4):
        salt = generate_salt(length=8)
        key = seed
        # 派生种子
        seed = derive_seed_from_key_with_salt(key, salt)
        SEED.append(seed)
    # 创建哈希链
    com = '03999'
    chains = [create_hash_chain(seed, int(n)) for seed, n in zip(SEED, com)]
    # 根据证明值返回相应节点
    value_to_prove = '01492'
    proof = prove_commitment(chains, value_to_prove)
    # 验证节点
    is_verified = verify_proof(chains, proof, value_to_prove)
    if is_verified:
        print("Proof is valid. Alice has a commitment greater than or equal to", int(value_to_prove))
    else:
        print("Proof is invalid. Alice does not have a commitment greater than or equal to", int(value_to_prove))


```

###  局限性
让我们尝试另一个发布的值 03997，现在尝试证明大于或等于 1599。但我们没有最后一个数字的长度为十的链。我们可以证明 1597，但不能证明 1598 和 1599，一般来说，我们无法证明最后一个数字为 8 或 9 的任何数字。也就是单个哈希多链无法工作。如图所示
![1690974914180.png](https://img1.imgtp.com/2023/08/02/mKICx1Kn.png)

### Fix Previous Problem
为了解决上述问题，我们引入“最小支配分区”（MDP）的概念。产生满足上述属性的最小集合大小，即能够证明任何范围直到发布值。
例如，[312， 303， 233] 是 base4 中数字 312 的 MDP 列表，如下所示：
With Comm312, Comm303, Comm233, Alice can prove number <312
• Use Comm233 if prove number [0, 233]
• Use Comm303 if prove number [300, 303]
• Use Comm312 if prove number [310, 312]
Call [312, 303, 233] MDP-list for base4 number 312
如图：
![1690975221626.png](https://img1.imgtp.com/2023/08/02/YIDcg9cj.png)

### Reducing Commitment Number
一个优化技巧是共享 MDP 承诺之间的链。实际上，这很容易通过接线完成，如下面的 312 base4 示例中所示。简而言之，我们创建了 3 条完整链，每条数字一条。然后，每个 MDP 承诺都连接到其相应的索引，如下所示：
![1690975307748.png](https://img1.imgtp.com/2023/08/02/n5IipWPL.png)

###  Hiding Commitment Number
MDP 列表的大小可以达到每个应用程序支持的最大位数。例如，如果可接受的最大数字由 20 个十进制数字组成，则 MDP 列表的大小最多可以达到 20 个元素的 base10。
但是，MDP 列表的大小以及所选 MDP 承诺的索引可能会泄露有关已发布编号的信息。当发布了数字 02999（在最大可能的 99999 中），这个数字只需要MDP列表中的一个元素，即[2999]，因为它可以用来证明任何数字<=2999 。但是，如果 Alice 透露了此信息（仅存在一个 MDP 承诺），则验证者会了解到发出的数字不能是 2998 或任何其他需要多个 MDP 值的整数。
所以建议使用Merkle tree填充节点数量,如图：
![1690975606348.png](https://img1.imgtp.com/2023/08/02/nGQRDHUz.png)

### Putting All Things Together+
完整协议实现如图，即HashWires: Hyperefficient Credential-Based Range Proofs。
![1690975810852.png](https://img1.imgtp.com/2023/08/02/8ZHPXkHu.png)
如图所示，结合了前文所述的优化方式并将之体系化。我在py文件给出了hashwires图示中的实现。
