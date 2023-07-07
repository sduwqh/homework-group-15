from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import padding

# 生成密钥对
private_key = ec.generate_private_key(ec.SECP256K1())
public_key = private_key.public_key()

# 要签名的消息
message = b"Hello, world!"
# 签名
signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))

# 验证签名
try:
    public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
    print("签名有效")
except InvalidSignature:
    print("签名无效")
