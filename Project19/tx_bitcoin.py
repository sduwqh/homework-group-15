#send a tx on Bitcoin testnet...
import requests
import re
#url: Bitcoin testnet链接
url='https://en.bitcoin.it/wiki/Testnet'
#向它发送的tx信息
tx={
    'tx':'111222333'
    }
post_html=requests.post(url,data=tx)

print(post_html.text)
