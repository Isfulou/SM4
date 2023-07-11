import socket
import pickle


Sbox = [
    [0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05],
    [0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99],
    [0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62],
    [0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6],
    [0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8],
    [0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35],
    [0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87],
    [0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e],
    [0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1],
    [0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3],
    [0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f],
    [0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51],
    [0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8],
    [0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0],
    [0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84],
    [0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48]
]

FK_list = ['A3B1BAC6', '56AA3350', '677D9197', 'B27022DC']

CK = [
    '00070E15', '1C232A31', '383F464D', '545B6269',

    '70777E85', '8C939AA1', 'A8AFB6BD', 'C4CBD2D9',

    'E0E7EEF5', 'FC030A11', '181F262D', '343B4249',

    '50575E65', '6C737A81', '888F969D', 'A4ABB2B9',

    'C0C7CED5', 'DCE3EAF1', 'F8FF060D', '141B2229',

    '30373E45', '4C535A61', '686F767D', '848B9299',

    'A0A7AEB5', 'BCC3CAD1', 'D8DFE6ED', 'F4FB0209',

    '10171E25', '2C333A41', '484F565D', '646B7279'
]


# 客户端加密
class SM4_Cilent:
    def __init__(self, M, K, F):
        self.M_hex = self.get_hex(M)
        self.K_hex = self.get_hex(K)
        self.M_group = self.get_group(self.M_hex, 1, F)
        self.K_group = self.get_group(self.K_hex, 0, '1')
        self.rk = self.get_rk(self.K_group)
        self.cipher = self.get_cipher(self.M_group, self.rk)
        self.cipher_text = self.output(self.cipher)

    # 字符进行utf-8编码然后以十六进制返回
    def get_hex(self, M):
        M = M.encode('utf-8')
        list_M = list(M)
        list_Hex = []
        for i in range(len(list_M)):
            list_Hex.append(hex(list_M[i])[2:].zfill(2))

        #字符串转化为十六进制
        M_hex = []
        for n in range(len(list_Hex)):
            M_hex.append(hex(int(list_Hex[n], base=16))[2:].zfill(2))
        return M_hex

    # 分组
    def get_group(self, M_hex, flag, F):
        M_bit = []
        for i in range(len(M_hex)):
            M_bit.append(bin(int(M_hex[i], base=16))[2:].zfill(8))
        # 列表转化为字符串,方便后续填充
        M_bin_str = ''.join(M_bit)
        M_bin_temp = []
        for i in range(len(M_bin_str)):
            M_bin_temp.append(M_bin_str[i])

        # 根据明文密文选择填充方式
        if flag:
            if F == '1':
                M_bin_temp = self.zero(M_bin_temp)
            elif F == '2':
                M_bin_temp = self.PKCS7(M_bin_temp)
            elif F == '3':
                M_bin_temp = self.Ansix923(M_bin_temp)
        else:
            #密钥采用0bit填充
            if len(M_bin_temp) < 128:
                while len(M_bin_temp) < 128:
                    M_bin_temp.append('0')

        #以128bit为一组进行分组
        M_bin_temp = ''.join(M_bin_temp)
        M_bin_list = []
        x = 0
        while x < len(M_bin_temp):
            M_bin_list.append(M_bin_temp[x:x + 128])
            x += 128

        M_group = []
        for n in range(len(M_bin_list)):
            M_group.append(hex(int(M_bin_list[n], base=2))[2:].zfill(16))
        return M_group

    # 获取子密钥
    def get_rk(self, K_group):
        # 将初始密钥分为四组,每组32bit
        K_group = ''.join(K_group)
        mk = []
        a = 0
        while a < len(K_group):
            mk.append(K_group[a:a + 8])
            a += 8

        # 四组密钥分别与系统函数进行异或操作
        wheel = []
        for i in range(len(mk)):
            wheel.append(hex(int(mk[i], base=16) ^ int(FK_list[i], base=16))[2:].zfill(8))

        rk = []
        # 32轮密钥扩展
        for flag in range(32):
            t = 0
            # K[i+1]和K[i+2]和K[i+3]进行异或
            T = hex(int(wheel[t + 1], base=16) ^ int(wheel[t + 2], base=16) ^ int(wheel[t + 3], base=16))[2:].zfill(8)
            # 与固定参数及进行异或
            T = hex(int(T, base=16) ^ int(CK[flag], base=16))[2:].zfill(8)
            S = []
            n = 0
            while n < len(T):
                S.append(T[n:n + 2])
                n += 2
            # 四个盒子依次进行S盒替换
            S_before = []
            for i in range(4):
                x = int(S[i][0:1], base=16)
                y = int(S[i][1:], base=16)
                S_before.append(hex(Sbox[x][y])[2:].zfill(2))

            # 分别进行循环左移13位,23位
            S_after = ''.join(S_before)
            S_after = bin(int(S_after, base=16))[2:].zfill(32)
            S_13 = S_after[13:] + S_after[0:13]
            S_23 = S_after[23:] + S_after[0:23]

            # 将一位后的数据与原始数据进行异或运算
            RK_before = hex(int(S_after, base=2) ^ int(S_13, base=2) ^ int(S_23, base=2))[2:].zfill(8)
            # 与K[i]异或得到最后子密钥
            RK = hex(int(RK_before, base=16) ^ int(wheel[t], base=16)).zfill(8)
            rk.append(RK)
            for m in range(3):
                wheel[m] = wheel[m + 1]
            wheel[3] = RK[2:]
        return rk

    # 密文生成
    def get_cipher(self, M_group, rk):
        group_temp = [['0' for i in range(1)] for n in range(len(M_group))]
        for x in range(len(M_group)):
            group_temp[x][0] = M_group[x]

        # 将每组明文按32bit为一组分为四组
        group_x = [[['0' for x in range(4)] for y in range(len(group_temp))] for z in range(len(M_group))]
        for x in range(len(M_group)):
            for y in range(len(group_x)):
                t = 0
                for z in range(4):
                    group_x[x][y][z] = group_temp[x][0][t:t + 8]
                    t += 8
                    group_x[x][y][z] = hex(int(group_x[x][y][z], base=16))[2:].zfill(8)
        cipher = []
        for x in range(len(M_group)):
            # print('[+]第{0}组开始开始加密:'.format(x+1))
            for y in range(1):
                for time in range(32):
                    t = 0
                    funciper = hex(int(group_x[x][y][t + 1], base=16) ^ int(group_x[x][y][t + 2], base=16) ^ int(
                        group_x[x][y][t + 3], base=16) ^ int(rk[time], base=16))[2:].zfill(8)
                    # 将结果分为四组
                    S = []
                    n = 0
                    while n < len(funciper):
                        S.append(funciper[n:n + 2])
                        n += 2
                    # T变换
                    # 先将异或后的结果进行S盒替换
                    S_after = []
                    for i in range(len(S)):
                        x1 = int(S[i][0:1], base=16)
                        y1 = int(S[i][1:], base=16)
                        S_after.append(hex(Sbox[x1][y1])[2:].zfill(2))
                    #print("S盒置换后:",S_after)

                    # 线性变化L
                    L_hex = ''.join(S_after)
                    L_bin = bin(int(L_hex, base=16))[2:].zfill(32)

                    # 循环左移10bit,2bit,18bit,24bit利用切片直接循环左移(简单粗暴)
                    L_10 = L_bin[10:] + L_bin[0:10]
                    L_2 = L_bin[2:] + L_bin[0:2]
                    L_18 = L_bin[18:] + L_bin[0:18]
                    L_24 = L_bin[24:] + L_bin[0:24]

                    # 四部分做异或
                    L = int(L_bin, base=2) ^ int(L_10, base=2) ^ int(L_2, base=2) ^ int(L_18, base=2) ^ int(L_24,
                                                                                                            base=2)
                    C = hex(int(group_x[x][y][t], base=16) ^ L)[2:].zfill(8)
                    for m in range(3):
                        group_x[x][y][m] = group_x[x][y][m + 1]
                    group_x[x][y][len(group_x[x][y]) - 1] = C
                # 进行反序变化得到最终密文
                cipher_temp = []
                j = len(group_x[x][y]) - 1
                while j >= 0:
                    cipher_temp.append(group_x[x][y][j])
                    j -= 1
                cipher_list = ''.join(cipher_temp)
                cipher_text = []
                k = 0
                while k < len(cipher_list):
                    cipher_text.append(cipher_list[k:k + 2])
                    k += 2
                cipher.append(cipher_text)
        return cipher

    # 输出密文格式化
    def output(self, cipher):
        cipher_text = []
        for i in range(len(cipher)):
            cipher_text.append(' '.join(cipher[i]))
        cipher_temp = ''.join(cipher_text)
        cipher_list = cipher_temp.split(" ")
        cipher_s = ''.join(cipher_list)
        ciphers = []
        a = 0
        while a < len(cipher_s):
            ciphers.append(cipher_s[a:a + 2])
            a += 2
        return ' '.join(ciphers)

    # 填充方式
    # 零填充
    def zero(self, M):
        while len(M) % 128 != 0:
            M.append('0')
        return M

    # PKCS7填充
    def PKCS7(self, M):
        M = ''.join(M)
        list_M = []
        a = 0
        #bit转字节
        while a < len(M):
            list_M.append(hex(int(M[a:a + 8], base=2))[2:].zfill(2))
            a += 8
        #以字节为单位
        length = (16 - len(list_M)) % 16
        t = hex(length)[2:].zfill(2)
        if length != 0:
            for i in range(length):
                list_M.append(t)
        else:
            for i in range(16):
                list_M.append('10')
        list = []
        for i in range(len(list_M)):
            list.append(bin(int(list_M[i], base=16))[2:].zfill(8))
        M_bin = ''.join(list)
        return M_bin



    # Ansix923填充方式
    def Ansix923(self, M):
        M = ''.join(M)
        list_M = []
        a = 0
        while a < len(M):
            list_M.append(hex(int(M[a:a + 8], base=2))[2:].zfill(2))
            a += 8
        length = (16 - len(list_M)) % 16
        t = hex(length)[2:].zfill(2)
        for i in range(length - 1):
            list_M.append('00')
        list_M.append(t)
        list = []
        for i in range(len(list_M)):
            list.append(bin(int(list_M[i], base=16))[2:].zfill(8))
        M_bin = ''.join(list)
        return M_bin



# 使用rc4对传递给服务器端的数据及进行加密
class RC4:
    def __init__(self, M):
        self.K = 'CuitYyds@!2021ikun'
        self.M = M
        self.S = self.KSA(self.K)
        self.C = self.PRGA(self.S, self.M)
        self.M_ascii = []
        self.M_ascii = [ord(m) for m in self.M]

        self.M_bin = []
        for i in range(len(self.M_ascii)):
            self.M_bin.append(bin(self.M_ascii[i])[2:])
        self.C_bin = []
        for j in range(len(self.C)):
            self.C_bin.append(bin(self.C[j])[2:])
        self.C_M = self.EnRC4(self.M_bin, self.C_bin)


    def KSA(self,K):
        # 种子密钥
        K = [ord(c) for c in K]  #将密钥转化为ascii码值

        # S表线性填充,0填充到255
        S = list(range(256))

        # 对临时表T用密钥进行填充
        T = []
        keylength = len(K)
        # print(keylength)
        for i in range(0, 256):
            T.append(K[i % keylength])

        # S表置换
        j = 0
        for i in range(256):
            j = (j + S[i] + T[i]) % 256
            S[i], S[j] = S[j], S[i]   #交换

        return S


    def PRGA(self,S, M):
        i, j = 0, 0
        K = []
        for r in range(0,len(M)):
            i = (i+1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % 256
            K.append(S[t])
        return K

    def EnRC4(self,M_bin, C_bin):
        Cipher = []
        for i in range(len(M_bin)):
            Cipher.append(hex((int(M_bin[i], base=2) ^ int(C_bin[i], base=2)) & 0xff)[2:].zfill(2))
        x = ' '.join(Cipher)
        return  x

# 在windows下的dos窗口中没法显示颜色,可以在pycharm编辑器或者在Linux中可以看到颜色字体
def menu():
    print("\033[31m _       __       __                                __            _____  __  ___ __ __     ______ __ _               __ \033[0m")
    print('\033[32m| |     / /___   / /_____ ____   ____ ___   ___     / /_ ____     / ___/ /  |/  // // /    / ____// /(_)___   ____   / /_\033[0m')
    print('\033[33m| | /| / // _ \ / // ___// __ \ / __ `__ \ / _ \   / __// __ \    \__ \ / /|_/ // // /_   / /    / // // _ \ / __ \ / __/\033[0m')
    print('\033[34m| |/ |/ //  __// // /__ / /_/ // / / / / //  __/  / /_ / /_/ /   ___/ // /  / //__  __/  / /___ / // //  __// / / // /_  \033[0m')
    print('\033[35m|__/|__/ \___//_/ \___/ \____//_/ /_/ /_/ \___/   \__/ \____/   /____//_/  /_/   /_/     \____//_//_/ \___//_/ /_/ \__/  \033[0m')

if __name__ == '__main__':
    menu()
    s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = '127.0.0.1'
    port = 10086
    s1.connect((ip, port))
    flag = 0
    while True:
        M = input('请输入明文: ')
        K = input('请输入128bit密钥: ')
        if len(K) > 16:
            print('不合法的密钥长度!')
        else:
            F = input('请选择填充方式:\n1.zero\n2.PKCS7\n3.Ansix923\n选择:')
            if F == '1' or F == '2' or F == '3':
                client = SM4_Cilent(M, K, F)
                length = len(M)
                C = client.cipher_text
                rk = ' '.join(client.rk)
                rc41 = RC4(C)
                rc42 = RC4(rk)
                rc43 = RC4(str(length))
                c = rc41.C_M
                RK = rc42.C_M
                length = rc43.C_M
                print('-'*100)
                print('SM4客户端加密结果:\033[35m{0}\033[0m'.format(C))
                # print('SM4客户端加密结果:{0}'.format(C))
                print('-'*100)
                # 创建socket管道向服务器端发送数据
                data = []
                send_data = c
                data.append(send_data)
                data.append(RK)
                data.append(length)
                serialized_data = pickle.dumps(data)
                print('开始向服务器端传递数据...................................')
                s1.send(serialized_data)

                server_data = s1.recv(1024)
                print('服务器端回应:', server_data.decode('utf-8'))
                a = input('continue.........')
                print('\n')
                if flag == 10:
                    print('白嫖结束,快点充钱成为vip')
                    s1.close()
                    break
                else:
                    flag += 1
            else:
                print('nonononono!')
                break
    input('end <enter>')
