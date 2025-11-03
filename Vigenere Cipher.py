#维吉尼亚密码加密算法
def E_Vigenere_Cipher(key,m):
    m1=m.replace(' ','').upper()
    key=key.upper()
    c=''
    for i in range(len(m1)):
        c+=chr(((ord(m1[i])-65)+(ord(key[i%len(key)])-65))%26+65)
    return c.lower()
#维吉尼亚密码解密算法
def D_Vigenere_Cipher(key,c):
    c1=c.replace(' ','').upper()
    key=key.upper()
    m=''
    for i in range(len(c1)):
        m+=chr(((ord(c1[i])-65)-(ord(key[i%len(key)])-65))%26+65)
    return m.lower()
#维吉尼亚密码测试函数
def Test_Vigenere_Cipher():
    key=input('请输入密钥：')
    m=input('请输入明文：')
    c=E_Vigenere_Cipher(key,m)
    print('密文为%s'%c)
    m=D_Vigenere_Cipher(key,c)
    print('恢复后的明文为%s'%m)
if __name__=='__main__':
    Test_Vigenere_Cipher()