from pwn import *

host = '75.119.130.114'
port = 38139

flag = ""
blocksFound = 0
t = remote(host, port)
block = 'TUDCTF{'
chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_@?!-,.}'
while True:
    for c in chars:
        payload = (16-len(block)-1)*"0" + flag + block + c + (16-len(block)-1)*"0"
        t.sendline(payload.encode())
        t.recvuntil(b':')
        msg = t.recvline().decode('utf-8').replace("Here's your encrypted message: ", "").replace('\n', '').replace(" ", '')
        mine = msg[blocksFound*32:blocksFound*32 + 32]
        their = msg[(blocksFound*2 + 1)*32:(blocksFound*2 + 1)*32 + 32]
        if mine == their:
            block += c
            print("Block of flag: ", block)
            if c == "}":
                flag += block
                print("Final flag: " + flag)
                exit()

        if len(block) == 16:
            flag += block
            block = ""
            blocksFound += 1