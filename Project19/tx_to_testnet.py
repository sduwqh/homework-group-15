# send a tx on Bitcoin testnet, and parse the tx data down to every bit, better write script yourself
import requests
from bs4 import BeautifulSoup

def get_page_details(hash_value):
    base_url = "https://blockchair.com"
    url = f"{base_url}/zh/bitcoin/testnet/transaction/{hash_value}"

    response = requests.get(url)
    if response.status_code == 200:
        html_content = response.text
        # 使用BeautifulSoup解析HTML内容
        soup = BeautifulSoup(html_content, "html.parser")

        # 获取<a>标签的文本和链接
        block_link = soup.find("a", class_="transaction-status__blockid")
        block_number = block_link.text
        block_href = block_link["href"]

        # 输出结果
        print("区块号:", block_number)
        print("区块链接:", base_url + block_href)
        response = requests.get(base_url + block_href)
        if response.status_code == 200:
            html_content = response.text
            # 使用BeautifulSoup解析HTML内容
            soup = BeautifulSoup(html_content, "html.parser")
            hash_span = soup.find("span", class_="page-block__hash__hash")
            hash_value = hash_span.text.strip()  # 去除空白字符
            # 输出哈希信息
            print("哈希值:", hash_value)
            merkle_span = soup.find("span", class_="hash-sm__hash")
            #输出默克尔根值
            merkle_parts = merkle_span.find_all("span")
            merkle_root = "".join(part.text for part in merkle_parts)
            print("默克尔根值:", merkle_root)
        else:
            print("network error")
    else:
        print("network error")

tx = "9d49a74c1b174a0ffca7b62106295bdd34f5c193c715e479ac31d57cb44ba524"
get_page_details(tx)

