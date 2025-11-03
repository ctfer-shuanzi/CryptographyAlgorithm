#A-Z:65-90,a-z:97-122
#移位密码加密算法
def E_Shift_Cipher(key,m):
    m1=m.upper()
    c=''
    for i in m1:
        if i==' ':
            c+=i
        else:
            c+=chr((ord(i)-65+key)%26+65)
    return c.lower()
#移位密码解密算法
def D_Shift_Cipher(key,c):
    c1=c.upper()
    m=''
    for i in c1:
        if i==' ':
            m+=i
        else:
            m+=chr((ord(i)-65-key)%26+65)
    return m.lower()
#移位密码测试函数
def Test_Shift_Cipher():
    key=int(input('请输入密钥：'))
    while key<0 or key>25:
        print('密钥参数不合理，请输入0-25范围内的数：')
        key=int(input())
    m=input('请输入想要加密的明文：')
    print('加密后的密文为:%s'%E_Shift_Cipher(key,m))
    print('再对密文进行解密得到明文:%s'%D_Shift_Cipher(key,E_Shift_Cipher(key,m)))
    option=int(input('是否要对某段密文进行暴力破解？若是，输入1，否则输入0：'))
    if option:
        c=input('请输入想要暴力破解的密文：')
        print()
        BF_Shift_Cipher(c)
    else:
        return
#穷举攻击函数
def BF_Shift_Cipher(c):
    for key in range(1,26):
        print('key=%d m=%s'%(key,D_Shift_Cipher(key,c)))
        print()
if __name__=="__main__":
    Test_Shift_Cipher()

