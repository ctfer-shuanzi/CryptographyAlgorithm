import gmpy2
#A-Z:65-90,a-z:97-122
#求a与b的最大公因子
def gcd(a,b):
    if a<b:
        a,b=b,a
    if b==0:
        if a>=0:
            return a
        else:
            return -a
    else:
        return gcd(b,a%b)
#仿射密码加密算法
def E_Affine_Cipher(a,b,m):
    m=m.upper()
    c=''
    for i in m:
        if i==' ':
            c+=i
        else:
            c+=chr((a*(ord(i)-65)+b)%26+65)
    return c.lower()
#仿射密码解密算法
def D_Affine_Cipher(a,b,c):
    c=c.upper()
    m=''
    for i in c:
        if i==' ':
            m+=i
        else:
            m+=chr((gmpy2.invert(a,26)*(ord(i)-65-b)%26+65))
    return m.lower()
#仿射密码测试函数
def Test_Affine_Cipher():
    a=int(input('请输入参数a：'))
    while gcd(a,26)!=1:
        print('参数a不合理，请输入Z/*26中的数：')
        a=int(input())
    b=int(input('请输入参数b：'))
    while b not in range(0,26):
        print('参数b不合理，请输入0-25范围内的数：')
        b=int(input())
    m=input('请输入想要加密的明文：')
    c=E_Affine_Cipher(a,b,m)
    print('加密后的密文为:%s'%c)
    print('再对密文进行解密得到明文:%s'%D_Affine_Cipher(a,b,c))
if __name__=="__main__":
    c=E_Affine_Cipher(7,21,"security")
    print(c)
    m=D_Affine_Cipher(7,21,"vlxijh")
    print(m)
    Test_Affine_Cipher()

