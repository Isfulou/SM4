# SM4实现在客户端加密并输出十六进制密文,在服务器端解密出明文

### 注意事项
需要先运行服务器端再运行客户端
项目中的ip为本机地址可以根据需要改为其他地址
需要python3的环境,需要pickle和socket两个模块
可以实现任意长度任意字符串(中文,英文,数字,特殊字符的加密)
使用RC4加密作为客户端和服务器端传输的安全加固
