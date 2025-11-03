import numpy as np
from collections import Counter
import wordninja
# 计算重合指数（IC）
def IC(c):
    #统计c中每个字幕出现的次数，返回值为一个字典，键为字母，值为出现次数
    freq = Counter(c)
    #计算字符长度
    total = len(c)
    #计算所有字母的IC之和
    ic = sum([f * (f - 1) for f in freq.values()]) / (total * (total - 1))
    #返回结果
    return ic

#猜测密钥长度
def Guess_Length(c,max_m=10):
    #假设密钥长度最大为10
    ic_list=[]
    for m in range(1,max_m):
        #将不同长度情况下的密文进行分组
        groups=[c[i::m] for i in range(m)]
        #求每组的平均IC值
        avg_ic=np.mean([IC(g) for g in groups])
        #将元组(密钥长度，平均IC值)保存到列表ic_list
        ic_list.append((m,avg_ic))
    #x表示列表的元组，x[1]表示平均IC值
    # key为-x[1]表示按IC值降序进行排列
    ic_list.sort(key=lambda x:-x[1])
    return ic_list

# 恢复密钥（频率分析）
def Recover_Key(c, m):
    english_freq = {
        'a': 0.08167, 'b': 0.01492, 'c': 0.02782, 'd': 0.04253, 'e': 0.12702,
        'f': 0.02228, 'g': 0.02015, 'h': 0.06094, 'i': 0.06966, 'j': 0.00153,
        'k': 0.00772, 'l': 0.04025, 'm': 0.02406, 'n': 0.06749, 'o': 0.07507,
        'p': 0.01929, 'q': 0.00095, 'r': 0.05987, 's': 0.06327, 't': 0.09056,
        'u': 0.02758, 'v': 0.00978, 'w': 0.02360, 'x': 0.00150, 'y': 0.01974,
        'z': 0.00074
    }
    key = []
    for i in range(m):
        group = c[i::m]
        best_shift = 0
        best_score = float('-inf')#初始化为负无穷
        for shift in range(26):
            decrypted = [chr(((ord(c) - ord('a') - shift) % 26) + ord('a')) for c in group]
            freq = Counter(decrypted)
            score = sum([freq.get(c, 0) * english_freq[c] for c in english_freq])
            if score > best_score:
                best_score = score
                best_shift = shift
        key.append(chr(best_shift + ord('a')))
    k=''
    for i in key:
        k+=i
    return k

# 解密
def decrypt(ct, key):
    pt = []
    key_len = len(key)
    #i为密文中某个字符索引，c为字符本身
    for i, c in enumerate(ct):
        shift = ord(key[i % key_len]) - ord('a')
        p = chr(((ord(c) - ord('a') - shift) % 26) + ord('a'))
        pt.append(p)
    p=''
    for i in pt:
        p+=i
    return p
if __name__=='__main__':
    ciphertext = ("vvhqwvvrhmusgjgthkihtssejchlsfcbgvwcrlryqtfsvgahwkcuh"
                  "wauglqhnslrljshbltspisprdxljsveeghlqwkasskuwepwqtwvs"
                  "pgoelkcqyfnsvwljsniqkgnrgybwlwgoviokhkazkqkxzgyhcecmei"
                  "ujoqkwfwvefqhkijrclrlkbienqfrjljsdhgrhlsfqtwlauqrhwdmw"
                  "lgusgikkflryvcwvspgpmlkassjvoqxeggveyggzmljcxxljsvpai"
                  "vwikvrdrygfrjljslveggveyggeiapuuisfpbtgnwwmuczrvtwglrwugumnczvile")
    # 1. 猜测密钥长度
    ic_results = Guess_Length(ciphertext, max_m=10)
    print("猜测密钥长度及IC值：")
    for m, ic in ic_results:
        print(f"m={m}, IC={ic:.4f}")

    # 2. 选择最可能的密钥长度（IC最高的）
    best_m = ic_results[0][0]
    print(f"\n最可能的密钥长度：{best_m}")

    # 3. 恢复密钥
    key = Recover_Key(ciphertext, best_m)
    print(f"恢复的密钥：{key}")

    # 4. 解密
    plaintext = decrypt(ciphertext, key)
    print(f"\n解密后的明文：\n{plaintext}")
    print(" ".join(wordninja.split(plaintext)))

