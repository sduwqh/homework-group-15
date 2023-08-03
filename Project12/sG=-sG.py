import random


def mod_inv(a, m):
    return pow(a, -1, m)


def EC_mul(a, p, a_param, p_mod):
    # 在椭圆曲线上进行点乘操作
    x1, y1 = None, None
    x2, y2 = p
    for bit in bin(a)[2:]:
        if bit == '1':
            x1, y1 = EC_add(x1, y1, x2, y2, a_param, p_mod)
            x2, y2 = EC_double(x2, y2, a_param, p_mod)
        else:
            x2, y2 = EC_add(x2, y2, x1, y1, a_param, p_mod)
            x1, y1 = EC_double(x1, y1, a_param, p_mod)
    return x1, y1


def EC_double(x, y, a_param, p_mod):
    # 在椭圆曲线上进行点加倍操作
    if x is None:
        return None, None
    s = (3 * x * x + a_param) * mod_inv(2 * y, p_mod) % p_mod
    x3 = (s * s - 2 * x) % p_mod
    y3 = (s * (x - x3) - y) % p_mod
    return x3, y3


def EC_add(x1, y1, x2, y2, a_param, p_mod):
    # 在椭圆曲线上进行点相加操作
    if x1 is None:
        return x2, y2
    if x2 is None:
        return x1, y1
    if x1 == x2 and y1 == y2:
        return EC_double(x1, y1, a_param, p_mod)
    s = (y2 - y1) * mod_inv(x2 - x1, p_mod) % p_mod
    x3 = (s * s - x1 - x2) % p_mod
    y3 = (s * (x1 - x3) - y1) % p_mod
    return x3, y3


# SECP256k1椭圆曲线参数
A = 0
B = 7
G_X = 55066263022277343669578718895168534326250603453777594175500187360389116729240
G_Y = 32670510020758816978083085130507043184471273380659243275938904335757337482424
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
G = (G_X, G_Y)

# 选择一个随机数，模拟签名s
s = random.randint(2 ** 20, 2 ** 25)

# 执行点乘操作
sG = EC_mul(s, G, A, P)
minus_sG = EC_mul(-s, G, A, P)
print("sG:", sG)
print("-sG:", minus_sG)
# 输出结果,若sG=-sG,则可与（R，s）一样通过验签函数。证明（R,-s)与（R，s）一样，都是有效的签名。
if sG == minus_sG:
    print("(R，s) and (R,-s) are both valid signatures.")
