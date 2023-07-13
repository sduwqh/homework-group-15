### *Project18：比较Firefox和Chrome的记住密码插件的实现区别

####  Chrome记住密码实现

在windows系统中，Chrome中保存的密码先被二次加密，然后被保存在SQLite数据库文件中，位置如下：
> AppData\Local\Google\Chrome\User Data\ Local State

使用工具SQLiteStudio读取数据库文件：

![](https://img1.imgtp.com/2023/07/13/sKf7doz2.png)

可进一步查看加密后的密码16进制：

![](https://img1.imgtp.com/2023/07/13/QRDK7YD0.png)

编写脚本将此数据导出：

```python
from os import getenv
import sqlite3
import binascii
conn = sqlite3.connect(getenv("LOCALAPPDATA") + r"\Google\Chrome\User Data\Default\Login Data")
cursor = conn.cursor()
cursor.execute('SELECT action_url, username_value, password_value FROM logins')
for result in cursor.fetchall():
    print (binascii.b2a_hex(result[2]))
```



参考Chromium开源代码，找到Chrome做二次加密的方法： 通过Windows API CryptProtectData()实现。

参考https://msdn.microsoft.com/en-us/library/windows/desktop/aa380261(v=vs.85).aspx获得关键信息：

**对应解密函数为CryptUnprotectData**

参考地址：https://msdn.microsoft.com/en-us/library/windows/desktop/aa380882(v=vs.85).aspx获得信息

**只有与加密数据的用户具有相同登录凭据的用户才能解密数据**

也就是说，只能在当前用户的凭据下解密数据，即Chrome使用windows账户密钥去加密chrome口令并存储在本地，所以只要登录了windows账户即可通过解密获取Chrome保存的各种口令。

通过查阅资料可知chrome将用户密钥存储在：

> AppData\Local\Google\Chrome\User Data\ Local State

加密密钥是通过 Base64 编码进行存储的,通过访问Local State文件并进行解密即可获得密钥：

```python
local_state = os.environ['LOCALAPPDATA'] + r'\Google\Chrome\User Data\Local State'
def getkey():
    with open(local_state, 'r', encoding='utf-8') as f:
        base64_encrypted_key = json.load(f)['os_crypt']['encrypted_key']
    encrypted_key = base64.b64decode(base64_encrypted_key)
    key= win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]
    return key
```

对文本进行解密：

```python
def decrypt(key, text, salt=None):
    nonce, cipher_bytes = text[3:15], text[15:]
    aes_gcm = AESGCM(key)
    return aes_gcm.decrypt(nonce, cipher_bytes, salt).decode('utf-8')
```

获取账户和口令：

```python
def getpassword(key):
    conn = sqlite3.connect(getenv("LOCALAPPDATA") + r"\Google\Chrome\User Data\Default\Login Data")
    cursor = conn.cursor()
    cursor.execute('SELECT action_url, username_value, password_value FROM logins')
    for result in cursor.fetchall():
        # print (binascii.b2a_hex(result[2]))
        print("账号：",result[1])
        password = decrypt(key, result[2])
        print("密码：",password)
```

![](https://img1.imgtp.com/2023/07/13/q12B9pRc.png)

#### FireFox记住密码
