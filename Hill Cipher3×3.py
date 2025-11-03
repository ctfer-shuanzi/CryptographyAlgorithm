#求a与b的最大公因子
def gcd(a,b):
    while b!=0:
        a,b=b,a%b
    return abs(a)

#求a%b的逆元
def ExtEuclid(a,b):
    if gcd(a, b) != 1:
        raise ValueError(f"{a} 和 {b} 不互质，没有逆元！")
    X3=b
    Y3=a
    X2,Y2=0,1
    Q=X3//Y3
    while Y3!=1:
        X2,Y2=Y2,X2-Q*Y2
        X3,Y3=Y3,X3-Q*Y3
        Q=X3//Y3
    return Y2%b

#伴随矩阵
def adj(key):
    adj_k = [[0,0,0], [0,0,0], [0,0,0]]
    adj_k[0][0]=(key[1][1]*key[2][2]-key[2][1]*key[1][2])%26
    adj_k[0][1]=(key[2][1]*key[0][2]-key[0][1]*key[2][2])%26
    adj_k[0][2]=(key[0][1]*key[1][2]-key[0][2]*key[1][1])%26
    adj_k[1][0]=(key[2][0]*key[1][2]-key[1][0]*key[2][2])%26
    adj_k[1][1]=(key[0][0]*key[2][2]-key[0][2]*key[2][0])%26
    adj_k[1][2]=(key[1][0]*key[0][2]-key[0][0]*key[1][2])%26
    adj_k[2][0] = (key[1][0] * key[2][1] - key[2][0] * key[1][1]) % 26
    adj_k[2][1] = (key[0][1] * key[2][0] - key[0][0] * key[2][1]) % 26
    adj_k[2][2] = (key[0][0] * key[1][1] - key[0][1] * key[1][0]) % 26
    return adj_k

#行列式
def det(key):
    result=(key[0][0]*key[1][1]*key[2][2]+key[0][1]*key[1][2]*key[2][0]
            +key[0][2]*key[1][0]*key[2][1]-key[2][0]*key[1][1]*key[0][2]
            -key[2][1]*key[1][2]*key[0][0]-key[2][2]*key[1][0]*key[0][1])%26
    return result%26

#逆矩阵
def RevMatrix(key):
    adj_k=adj(key)
    det_k=det(key)
    inv_det=ExtEuclid(det_k,26)
    result=[[0,0,0],[0,0,0],[0,0,0]]
    for i in range(3):
        for j in range(3):
            result[i][j]=(adj_k[i][j]*inv_det)%26
    return result

#输出矩阵
def display_key(key):
    for i in range(3):
        for j in range(3):
            print("%2d "%key[i][j],end=" ")
        print("\n")

#字母转为数字
def aTOn(ch):
    c=ch.lower()
    return ord(c)-ord('a')

#数字转为字母
def nTOa(n):
    return chr(n+ord('a'))

#希尔密码加密函数
def E_Hill_Cipher(pt,k):
    m = [ch.lower() for ch in pt if ch.isalpha()]
    while len(m)%3!=0:
        m.append('x')
    c=[]
    for n in range(0,len(m),3):
        for j in range(3):
            c.append((aTOn(m[n])*k[0][j]+aTOn(m[n+1])*k[1][j]+aTOn(m[n+2])*k[2][j])%26)
    c=[nTOa(num) for num in c]
    str=''
    for i in c:
        str+=i
    return str

#希尔密码解密函数
def D_Hill_Cipher(Cipher,k):
    k_1=RevMatrix(k)
    c=list(Cipher)
    m=[]
    for n in range(0,len(c),3):
        for j in range(3):
            m.append((aTOn(c[n])*k_1[0][j]+aTOn(c[n+1])*k_1[1][j]+aTOn(c[n+2])*k_1[2][j])%26)
    m=[nTOa(num) for num in m]
    str=''
    for i in m:
        str+=i
    return str

#希尔密码测试函数
def Test_Hill_Cipher():
    m=input("请输入你要加密的明文:")
    k=[[0,0,0],[0,0,0],[0,0,0]]
    for i in range(3):
        k[i][0],k[i][1],k[i][2]=(
            eval(input(f"请输入3×3密钥矩阵第{i+1}行的三个数,用逗号隔开（如：11，2，19）:")))
    while gcd(det(k),26)!=1:
        print("密钥参数错误，行列式与26不互素，请重新输入：\n")
        for i in range(3):
            k[i][0], k[i][1], k[i][2] = (
                eval(input(f"请输入3×3密钥矩阵第{i + 1}行的三个数,用逗号隔开（如：11，2，19）:")))
    print("解密密钥如下：")
    display_key(RevMatrix(k))
    c=E_Hill_Cipher(m,k)
    print(f"加密后的明文为：{c}")
    m1=D_Hill_Cipher(c,k)
    print(f"再对密文进行恢复得到明文:{m1}")
#主函数
if __name__=="__main__":
    Test_Hill_Cipher()

