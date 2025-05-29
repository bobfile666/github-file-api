import secrets
import base64

# 1. 生成32字节的随机原始数据
raw_mek_bytes = secrets.token_bytes(32) # 32 bytes = 256 bits

# 2. 将原始字节数据进行Base64编码，得到字符串
mek_base64_encoded = base64.b64encode(raw_mek_bytes).decode('utf-8')

print(f"MASTER_ENCRYPTION_KEY (Base64 Encoded): {mek_base64_encoded}")
print(f"Length of Base64 Encoded MEK: {len(mek_base64_encoded)}") # 应该是44个字符

# 验证一下解码过程（可选，用于理解）
# decoded_bytes = base64.b64decode(mek_base64_encoded)
# assert decoded_bytes == raw_mek_bytes
# print(f"Length of raw MEK bytes: {len(decoded_bytes)}") # 应该是32
