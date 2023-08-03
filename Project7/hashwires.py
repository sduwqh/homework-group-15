import random
import string
import hashlib
import hmac

#定义树结构
class TreeNode:
    def __init__(self, value=None):
        self.value = value
        self.left = None
        self.right = None


def pad_leaves(leaves, target_length):
    padded_leaves = leaves[:]
    while len(padded_leaves) < target_length:
        padded_leaves.append(hash_function(0))  # Pad with hashed zeros
    return padded_leaves


def create_padded_sparse_merkle_tree(height, leaves):
    if height == 0:
        return TreeNode(leaves[0])

    num_leaves = 2 ** height
    padded_leaves = pad_leaves(leaves, num_leaves)

    node = TreeNode()
    node.left = create_padded_sparse_merkle_tree(height - 1, padded_leaves[:num_leaves // 2])
    node.right = create_padded_sparse_merkle_tree(height - 1, padded_leaves[num_leaves // 2:])

    return node


def print_tree(node, level=0, prefix="Root: "):
    if node is not None:
        print("  " * level + prefix + str(node.value))
        print_tree(node.left, level + 1, "Left: ")
        print_tree(node.right, level + 1, "Right: ")


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


def shuffle(seed, A, B, C):
    # 将seed和三个哈希值A、B、C连接为一个字符串
    combined_string = str(seed) + str(A) + str(B) + str(C)

    # 计算连接字符串的哈希值
    hash_value = hashlib.sha256(combined_string.encode()).hexdigest()

    # 将哈希值解释为整数
    hash_int = int(hash_value, 16)

    # 对A、B、C进行重新排列（模拟洗牌操作）
    shuffled_list = [A, B, C]
    shuffled_list = [shuffled_list[i] for i in [(hash_int + j) % 3 for j in range(3)]]

    return tuple(shuffled_list)

    # kdf


def kdf(seed, num_random_numbers):
    random_numbers = []
    for i in range(num_random_numbers):
        # 使用HMAC-SHA256进行派生
        derived_key = hmac.new(seed, msg=bytes([i]), digestmod=hashlib.sha256).digest()
        random_numbers.append(int.from_bytes(derived_key, byteorder='big'))
    return random_numbers


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
    # for Alice to prove that she holds a commitment>=1492
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

    # The Final HashWires Protocol
    random_numbers = kdf(seed, 3)
    # 创建哈希链
    com = '333'
    chains = [create_hash_chain(seed, int(n)) for seed, n in zip(random_numbers, com)]
    # 返回对应节点
    com1 = '312'
    com2 = '303'
    com3 = '233'
    sum1 = prove_commitment(chains, com1)
    sum2 = prove_commitment(chains, com2)
    sum3 = prove_commitment(chains, com3)
    # 生成承诺值 pl_accum：a,b,c
    a = sum1[0]
    for i in sum1[1:]:
        a = a + i
    b = sum2[0]
    for i in sum2[1:]:
        b = b + i
    c = sum3[0]
    for i in sum3[1:]:
        c = c + i
    salta, saltb, saltc, shuffle_seed, seedD = kdf(seed, 5)
    A = hash_function(a + str(salta))
    B = hash_function(b + str(saltb))
    C = hash_function(c + str(saltc))
    # optional
    D = hash_function(seedD, 9)
    # 引入随机数的shuffle(a,b,c)洗牌算法
    shuffled_A, shuffled_B, shuffled_C = shuffle(shuffle_seed, A, B, C)
    # 创建叶子节点
    leaves = [shuffled_A, shuffled_B, shuffled_C]
    # 构建填充稀疏Merkle树
    height = 4
    root_node = create_padded_sparse_merkle_tree(height, leaves)
    # 稀疏Merkle树结构
    print_tree(root_node, level=0, prefix="Root: ")
