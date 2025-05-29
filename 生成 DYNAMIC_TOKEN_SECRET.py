import secrets
import string

# 生成一个包含字母、数字和标点符号的64位随机字符串
# secrets.token_urlsafe(n) 会生成一个包含 n 字节随机数据的 Base64 URL 安全文本字符串。
# 48 字节大约能生成 64 个字符的 Base64 编码字符串。
dynamic_token_secret = secrets.token_urlsafe(48) 

print(f"DYNAMIC_TOKEN_SECRET: {dynamic_token_secret}")

# 或者，如果你想要更可控的字符集（例如，只包含ASCII字母和数字）：
# length = 64
# alphabet = string.ascii_letters + string.digits
# dynamic_token_secret_custom = ''.join(secrets.choice(alphabet) for i in range(length))
# print(f"Custom DYNAMIC_TOKEN_SECRET: {dynamic_token_secret_custom}")
