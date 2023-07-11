import pickle
import socket

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


# 服务器端解密
class SM4_server:
    def __init__(self, c, rk, length):
        self.RK = rk[::-1] #密钥逆序
        self.C = c.split(" ")
        self.C_group = self.get_group(self.C)
        self.plaint = self.get_plaint(self.C_group, self.RK)
        self.plain_text = self.get_format(self.plaint, length)

    # 密文转化与分组
    def get_group(self, C):
        C_hex = []
        for i in range(len(C)):
            C_hex.append(hex(int(C[i], base=16))[2:].zfill(2))
        # 将密文按照16bit为一小组分组
        i = 0
        C_hexs = ''.join(C_hex)
        X = []
        while i < len(C_hexs):
            X.append(C_hexs[i: i + 4])
            i = i + 4
        # 一维列表转二维,每一个一维列表以128bit为一组
        X_s = [['0' for i in range(8)] for n in range(len(X) // 8)]
        t = 0
        for x in range(len(X) // 8):
            for y in range(8):
                X_s[x][y] = X[t]
                t += 1
        return X_s

    def get_plaint(self, X, rk):
        # 分组,每一小组转化为与系统函数等长,便于后续运算
        X_h = [['0' for x in range(4)] for n in range(len(X))]
        for x in range(len(X)):
            a = 0
            for y in range(4):
                X_h[x][y] = ''.join(X[x][a:a + 2])
                a += 2

        print("X_h:",X_h)
        plaint_text = []
        # 32轮变化
        for flag in range(len(X_h)):
            for time in range(32):
                # 将后三位和rk进行异或
                t = 0
                funciper = hex(int(X_h[flag][t + 1], base=16) ^ int(X_h[flag][t + 2], base=16) ^ int(X_h[flag][t + 3],
                                                                                                     base=16) ^ int(
                    rk[time], base=16))[2:].zfill(8)
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
                    x = int(S[i][0:1], base=16)
                    y = int(S[i][1:], base=16)
                    S_after.append(hex(Sbox[x][y])[2:].zfill(2))

                # 线性变化L
                L_hex = ''.join(S_after)
                L_bin = bin(int(L_hex, base=16))[2:].zfill(32)

                # 循环左移10bit,2bit,18bit,24bit利用切片直接循环左移(简单粗暴)
                L_10 = L_bin[10:] + L_bin[0:10]
                L_2 = L_bin[2:] + L_bin[0:2]
                L_18 = L_bin[18:] + L_bin[0:18]
                L_24 = L_bin[24:] + L_bin[0:24]

                # 四部分做异或
                L = int(L_bin, base=2) ^ int(L_10, base=2) ^ int(L_2, base=2) ^ int(L_18, base=2) ^ int(L_24, base=2)

                C = hex(int(X_h[flag][t], base=16) ^ L)[2:].zfill(8)
                for m in range(3):
                    X_h[flag][m] = X_h[flag][m + 1]
                X_h[flag][len(X_h[flag]) - 1] = C
            plaint = []
            y = len(X_h[flag]) - 1
            while y >= 0:
                plaint.append(X_h[flag][y])
                y -= 1
            plaint_list = ''.join(plaint)
            # print('反序变化: ', ' '.join(plaint))
            x = 0
            while x < len(plaint_list):
                plaint_text.append(plaint_list[x:x + 2])
                x += 2
        # print('明文: ', ' '.join(plaint_text))
        return ''.join(plaint_text)

    # 将十六进制明文还原
    def get_format(self, plaint, length):
        try:
            plaint_text = bytes.fromhex(plaint)
            plaint_text = plaint_text.decode('utf-8')
            plaint_text = plaint_text[0:length]
        except:
            i = 0
            plaint_text = []
            while i < len(plaint):
                plaint_text.append(plaint[i:i + 2])
                i += 2
            plaint_text = ''.join(plaint_text)
            plaint_text = plaint_text[0:length]
        return plaint_text

# 使用rc4对客户端传过来的数据进行解密
class RC4:
    def __init__(self, C_M):
        self.K = 'CuitYyds@!2021ikun'
        self.C_M = C_M
        self.S = self.KSA(self.K)
        self.C_L = self.C_M.split(" ")
        self.C = self.PRGA(self.S, self.C_L)
        self.C_bin = []
        for j in range(len(self.C)):
            self.C_bin.append(bin(self.C[j])[2:])

        self.plaint = self.DeRC4(self.C_L, self.C_bin)


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

    def DeRC4(self,C_M, C_bin):
        plaint_text = []
        C_Mbin = []
        for i in range(len(C_M)):
            C_Mbin.append(bin(int(C_M[i], base=16))[2:])

        for c in range(len(C_M)):
            plaint_text.append(chr(int(C_Mbin[c], base=2) ^ int(C_bin[c], base=2)))

        p = ''.join(plaint_text)
        return p
# 在windows下的dos窗口中没有颜色显示
def menu():
    print('\033[31m_       __       __                                 __            _____  __  ___ __ __     _____                          \033[0m')
    print('\033[33m| |     / /___   / /_____ ____   ____ ___   ___     / /_ ____     / ___/ /  |/  // // /    / ___/ ___   _____ _   __ ___   _____\033[0m')
    print('\033[32m| | /| / // _ \ / // ___// __ \ / __ `__ \ / _ \   / __// __ \    \__ \ / /|_/ // // /_    \__ \ / _ \ / ___/| | / // _ \ / ___/\033[0m')
    print('\033[36m| |/ |/ //  __// // /__ / /_/ // / / / / //  __/  / /_ / /_/ /   ___/ // /  / //__  __/   ___/ //  __// /    | |/ //  __// /    \033[0m')
    print('\033[35m|__/|__/ \___//_/ \___/ \____//_/ /_/ /_/ \___/   \__/ \____/   /____//_/  /_/   /_/     /____/ \___//_/     |___/ \___//_/     \033[0m')


if __name__ == '__main__':
    # print('*'*40, '服务器端', '*'*40)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ip = '127.0.0.1'
    port = 10086
    s.bind((ip, port))
    s.listen(5)
    # 服务器端创建连接
    flag = 0
    menu()
    print('等待连接中..........................')
    while True:
        sock, addr = s.accept()
        while True:
            texts = sock.recv(2048)
            deserialized_data = pickle.loads(texts)
            print('客户端传递的密文:', deserialized_data)
            rc41 = RC4(deserialized_data[0])
            rc42 = RC4(deserialized_data[1])
            rc43 = RC4(deserialized_data[2])
            C = rc41.plaint
            rk = rc42.plaint
            rk = rk.split(" ")
            print("密文:",C)
            length = int(rc43.plaint)
            server = SM4_server(C, rk, length)
            print('-'*100)
            print('服务器端解密结果: \033[34m{0}\033[0m'.format(server.plain_text))
            print('-'*100)
            print("\n")
            sock.send('successful'.encode('utf-8'))
            if flag == 10:
                print('对方还没充钱!')
                sock.close()
                break
            else:
                flag += 1




