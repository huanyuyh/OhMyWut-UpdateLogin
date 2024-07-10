import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import base64
from lxml import etree
from urllib.parse import urlencode
# 加密函数
def rsa_encrypt(data, public_key):
    cipher = PKCS1_v1_5.new(public_key)
    encrypted_data = cipher.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')


session = requests.session()
res = session.get("https://zhlgd.whut.edu.cn/tpass/login?service=https%3A%2F%2Fzhlgd.whut.edu.cn%2Ftp_up%2F")
print("Session Cookies after login:")
for cookie in session.cookies:
    print (f"{cookie.name}: {cookie.value}")

#  # 打印登录响应内容和响应头
# print("Login Response:")
# print(res.text)
# print("\nLogin Response Headers:")
# for key, value in res.headers.items():
#     print(f"{key}: {value}")
 # 打印登录响应内容和响应头
print("Login Response:")
# print(response.text)
print("\nLogin Response Headers:")
for key, value in res.headers.items():
    print(f"{key}: {value}")

lts = etree.HTML(res.text).xpath("//input[@id='lt']/@value")
print(lts)
lt = etree.HTML(res.text).xpath("//input[@id='lt']/@value")[0]
print("lt"+lt)
# 获取公钥的 URL
public_key_url = "https://zhlgd.whut.edu.cn/tpass/rsa?skipWechat=true"

# 获取公钥
response = session.post(public_key_url)
data = response.json()
public_key_str = data['publicKey']
# 确保公钥是正确的 PEM 格式
if not public_key_str.startswith("-----BEGIN PUBLIC KEY-----"):
    public_key_str = "-----BEGIN PUBLIC KEY-----\n" + public_key_str + "\n-----END PUBLIC KEY-----"

print(public_key_str)
# 将公钥字符串转换为 RSA 公钥对象
public_key = RSA.importKey(public_key_str)




# 用户名和密码
username = ""
password = ""

# 加密用户名和密码
encrypted_username = rsa_encrypt(username, public_key)
encrypted_password = rsa_encrypt(password, public_key)

print(f"Encrypted Username: {encrypted_username}")
print(f"Encrypted Password: {encrypted_password}")

# 模拟登录请求
login_url = "http://zhlgd.whut.edu.cn/tpass/login?service=http%3A%2F%2Fzhlgd.whut.edu.cn%2Ftp_up%2F"
payload = {
    "rsa": "",
    "ul": encrypted_username,
    "pl": encrypted_password,
    "lt": lt,
    "execution": "e1s1",
    "_eventId": "submit"
}
print(payload)
for cookie in session.cookies:
    print (f"{cookie.name}: {cookie.value}")
# session.cookies.update({
#         "cas_hash": "",
#         "Language": "zh_CN",
#         "tp_up": "",
#         "route": "",
#         "JSESSIONID": ""
#     })
# 发送登录请求
response = session.post(
            "https://zhlgd.whut.edu.cn/tpass/login?service=https%3A%2F%2Fzhlgd.whut.edu.cn%2Ftp_up%2Fview%3Fm%3Dup",
            headers={
                 "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "zh-CN,zh;q=0.9",
                "Cache-Control": "max-age=0",
                "Connection": "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
                "Host": "zhlgd.whut.edu.cn",
                "Origin": "https://zhlgd.whut.edu.cn",
                "Referer": "https://zhlgd.whut.edu.cn/tpass/login?service=https%3A%2F%2Fzhlgd.whut.edu.cn%2Ftp_up%2F",
                "Sec-Ch-Ua": '"Not=A?Brand";v="99", "Chromium";v="118"',
                "Sec-Ch-Ua-Mobile": "?0",
                "Sec-Ch-Ua-Platform": '"Windows"',
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-User": "?1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
            },
            data=urlencode(
                payload
            ),

        )

print(response.text)
print(response.url.startswith("http://zhlgd.whut.edu.cn/tp_up/view"))
res = session.get("http://cwsf.whut.edu.cn/casLogin")
print(res.text)
