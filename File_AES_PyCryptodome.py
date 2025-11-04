from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

def set_key_length(length):
    # 随机生成初始密钥和初始向量
    key = get_random_bytes(length)
    iv = get_random_bytes(16)
    return key, iv

def generate_cipher(key, iv):
    # 创建 AES 密码对象，固定为CBC模式
    return AES.new(key, AES.MODE_CBC, iv)

def encrypt_file(plaint_file, cipher_file, cipher):
    # 以二进制模式从明文文件中读取数据
    with open(plaint_file, 'rb') as f:
        # 直接得到 bytes，无需 encode()
        data = f.read()
    # 加密
    c = cipher.encrypt(pad(data, AES.block_size))
    # 写入加密文件（二进制模式）
    with open(cipher_file, 'wb') as f:
        f.write(c)
    print("加密成功！")
    print("原密文：",c)
    print("密文的十六进制表示：", c.hex()+"\n")  # 可用于调试或保存 key/iv/c 信息

def decrypt_file(cipher_file, plaint_file, cipher_de):
    # 以二进制模式从密文文件中读取数据
    with open(cipher_file, 'rb') as f:
        # 直接得到 bytes，无需 encode()
        data = f.read()
    # 解密
    m = unpad(cipher_de.decrypt(data), AES.block_size)
    # 写解密文件（二进制模式）
    with open(plaint_file, 'wb') as f:  # 明文可能包含任意字节，建议也用二进制写入
        f.write(m)
    print("解密成功！")
    print("解密后的明文：\n",m.decode()+"\n")


if __name__ == '__main__':
    is_length_wrong = True
    length = 0
    while is_length_wrong:
        print("请选择密钥长度：")
        print("1. AES-128")
        print("2. AES-192")
        print("3. AES-256")
        choice = int(input())
        if choice == 1:
            length = 16
            is_length_wrong = False
        elif choice == 2:
            length = 24
            is_length_wrong = False
        elif choice == 3:
            length = 32
            is_length_wrong = False
        else:
            print("无效的选择！")

    key, iv = set_key_length(length)

    cipher=generate_cipher(key, iv)
    # 假设 plaintext.txt 已存在，并且是二进制安全的（或文本文件）
    encrypt_file('plain_text.txt', 'cipher_text.txt', cipher)

    cipher_de=generate_cipher(key, iv)
    decrypt_file('cipher_text.txt', 'plain_text_decrypted.txt', cipher_de)