from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os

def generate_key_iv(length):
    # 随机生成初始密钥和初始向量
    key = os.urandom(length)
    iv = os.urandom(16)
    return key, iv

def get_ciphers(key,iv):
    cipher = Cipher(algorithms.AES(key),modes.CBC(iv),backend=default_backend())
    encryptor = cipher.encryptor()
    decryptor = cipher.decryptor()
    return encryptor,decryptor

def get_padders():
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    return padder,unpadder

def encrypt_file(plain_file,cipher_file,padder,encryptor):
    with open(plain_file,'rb') as f:
        data = f.read()
    data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    with open(cipher_file,'wb') as f:
        f.write(ciphertext)
    print("加密成功！")
    print("密文（字节序列）：\n",ciphertext)
    print("密文的十六进制表示：\n",ciphertext.hex()+"\n")

def decrypt_file(cipher_file,plain_file,unpadder,decryptor):
    with open(cipher_file,'rb') as f:
        data = f.read()
    data = decryptor.update(data) + decryptor.finalize()
    plaintext = unpadder.update(data) + unpadder.finalize()
    with open(plain_file,'wb') as f:
        f.write(plaintext)
    print("解密成功！")
    print("明文（字节序列）：\n",plaintext)
    print("明文的字符串形式表示：\n",plaintext.decode()+"\n")

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
            print("无效的选择！\n")

    key,iv = generate_key_iv(length)
    padder,unpadder = get_padders()
    encryptor,decryptor = get_ciphers(key,iv)

    encrypt_file('plaintext.txt','ciphertext.txt',padder,encryptor)
    decrypt_file('ciphertext.txt','plaintextdecrypted.txt',unpadder,decryptor)
