Author: Luxy (Frank)

Name of the challenge: AWS Encryption

Solves: 9

Points awarded: 229

Tags: Crypto, AESh*t

## Description

Amazon just launched a new encryption service, but I'm not sure if their choice of AES mode is smart...

Connection info: ncat 75.119.130.114 38138

## Writeup

```Python
# simple padding oracle attack
from os import urandom
from Cryptodome.Cipher import AES
FLAG = open('flag.txt', 'r').read()
secret = urandom(16)

print("""
###################################################################################
   ___  ____     __  ____   __ __  ____  ______   ___   ____   ____  ______    ___
  /  _]|    \   /  ]|    \ |  |  ||    \|      | /   \ |    \ |    ||      |  /  _]
 /  [_ |  _  | /  / |  D  )|  |  ||  o  )      ||     ||  _  | |  | |      | /  [_
|    _]|  |  |/  /  |    / |  ~  ||   _/|_|  |_||  O  ||  |  | |  | |_|  |_||    _]
|   [_ |  |  /   \_ |    \ |___, ||  |    |  |  |     ||  |  | |  |   |  |  |   [_
|     ||  |  \     ||  .  \|     ||  |    |  |  |     ||  |  | |  |   |  |  |     |
|_____||__|__|\____||__|\_||____/ |__|    |__|   \___/ |__|__||____|  |__|  |_____|
###################################################################################
""")
print("""Welcome to the AWS Encryptonite service!
For only 1000$ per month, we will encrypt your data for you!
But because we're so nice and generous, we'll give you a free trial!
Just send us your data and we'll encrypt it for you!

Because of our secret padding scheme (TM), your data is more secure than ever before.
""")
while True:
    try:
        print("Enter your message: ", end="")
        msg = input() + FLAG
        msg = msg + (16 - len(msg) % 16) * chr(16 - len(msg) % 16)
        msg = bytes(msg, encoding="ascii")
        cipher = AES.new(secret, AES.MODE_ECB)
        print("Here's your encrypted message: " + cipher.encrypt(msg).hex())
    except KeyboardInterrupt:
        exit()
    except Exception as e:
        print("Oops, something went wrong!\nWe'll report this to Jeff Bezos!")

```

By looking at the Python script, we can see how the actual encryption works. Our input is concatenated with the flag, and if it is not long enough to fill the blocks, a random padding is added at the end. So the hashed value looks like this in the end: input + flag (+ padding).

Now with this in mind, we can start by finding out the block size of the actual cipher. In this case, since the padding is calculated by modulo 16, we know that the block size in this case is also 16. By further analysing the code, we also see that the encryption uses ECB as mode of operation, meaning that every block is encrypted separately and that they have no influence on each other. Now this makes things a bit easier for us!

So with this in mind, we need to lay out our attack strategy, which would be somehow getting the values into separate blocks, so that we can try and guess the values inside of the block. But how should we do this? We first have to figure out how long our flag is, we can do this by testing different lengths of input, as our padding is determined based on the length of input concatenated to the flag. An exmpty input gives us "40a4b7e49eb7c1efe23588730c755e6ef13e5870f3474cc2b25ef608d389a5260227e105632e8cb6581d0cd4957fd708" for example (differs for each run, as the secret is random each run), so a hash of length 96 (in hex), or 48 characters, meaning 3 blocks. Any message with input of size up to 13, gives us a block of the same size, any input bigger than this increased the size of the output hash, meaning that our flag is 34 long in its hashed form according to the padding from the code, which is always at least 1 character. 
Let's start by mapping out what the blocks look like with input of size 13:

```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
iiiiiiiiiiiiifff    ffffffffffffffff    fffffffffffffffr
```

If we give an input of size 14 or more (14 in this case), we get this:
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
iiiiiiiiiiiiiiff    ffffffffffffffff    ffffffffffffffff    rrrrrrrrrrrrrrrr
```
Where i is input, f is flag and r is random, e.g., padding.

With this in mind, we can develop our attack strategy. Since every block is encrypted separately, we could try and bruteforce single blocks, since they always hash to the same value. But how do we do this? Simple, padding!

So by padding our input in a clever way, we can shift the flag to a different block, such that all the values are the same, and that way we can bruteforce it. Let's visualise this:
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
000000000000000i    000000000000000f    ffffffffffffffff    ffffffffffffffff    frrrrrrrrrrrrrrr
```

By padding our input with 0's at the front and at the back, we can make the first block the same as the second, except for our actual input. We can then go through every possible character for the input and check if the hashes of block 1 and block 2 are the same. If they are, we know that our input character was the same as the first character of the flag. We then repeat the same step for every character of the flag, but simply removing a few 0's. For example:

```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
00000000000000ii    00000000000000ff    ffffffffffffffff    ffffffffffffffff    rrrrrrrrrrrrrrrr
```

```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
0000000000000iii    0000000000000fff    ffffffffffffffff    fffffffffffffffr
```

And so on. With this method, we can easily find the first block of the flag. With this method, we end up with: "TUDCTF{Am4z0n_3n".

Our blocks now look like this:
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
iiiiiiiiiiiiiiii    ffffffffffffffff    ffffffffffffffff    ffrrrrrrrrrrrrrr
```

So, now we have the first block and first part of the flag, what next? We need to change it up a bit for the second block, as we cannot simply split our flag up and pad in the middle of it. For example this would not work:
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
iiiiiiiiiiiiiiii    000000000000000n    ffffffffffffffff    000000000000000f    ffffffffffffffff    frrrrrrrrrrrrrrr
```
Where n is the new input.

This is the case, since the whole input gets appended to the front of the flag, so how should we do it? Easy, we can simply pad as much as we need, so our second block is still completely correct except for the new input. This works as follows:
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
000000000000000i    iiiiiiiiiiiiiiin    000000000000000f    ffffffffffffffff    ffffffffffffffff    frrrrrrrrrrrrrrr
```

Now we can repeat the previous procedure but instead of comparing block one and two, we compare block 2 and 4. If they match, we know that the newly chosen character is the next one in the flag. We then decrease the amount of padding and repeat it for the rest of the block.

```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
00000000000000ii    iiiiiiiiiiiiiinn    00000000000000ff    ffffffffffffffff    ffffffffffffffff    rrrrrrrrrrrrrrrr
```
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
0000000000000iii    iiiiiiiiiiiiinnn    0000000000000fff    ffffffffffffffff    fffffffffffffffr
```
Until the whole second block is full with new characters. With this, we get "cryPti0n_5erV1c3", so now we have: "TUDCTF{Am4z0n_3ncryPti0n_5erV1c3" as our flag, but it looks like there is still something missing, as the curly braces are not closed yet... So let's keep going until we find a character '}' that makes the hash match, because then we know we're at the end!

Our blocks now look like this:
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
iiiiiiiiiiiiiiii    nnnnnnnnnnnnnnnn    ffffffffffffffff    ffffffffffffffff    ffrrrrrrrrrrrrrr
```

For the next block, we repeat the same as for block 2, by just padding it with 0's before the whole flag found so far and after (the n's from the previous block now become i's here):
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
000000000000000i    iiiiiiiiiiiiiiii    iiiiiiiiiiiiiiin    000000000000000f    ffffffffffffffff    ffffffffffffffff    frrrrrrrrrrrrrrr
```
```
xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx    xxxxxxxxxxxxxxxx
00000000000000ii    iiiiiiiiiiiiiiii    iiiiiiiiiiiiiinn    00000000000000ff    ffffffffffffffff    ffffffffffffffff    rrrrrrrrrrrrrrrr
```

The code needs to run for 2 more characters, as only "s}" were left of the flag. We can also see this from our illustration, so it all makes sense in the end! So finally we end up with "TUDCTF{Am4z0n_3ncryPti0n_5erV1c3s}" as the flag!

Here is the code that I wrote to solve this challenge:

```Python
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
        myBlock = msg[blocksFound*32:blocksFound*32 + 32]
        flagBlock = msg[(blocksFound*2 + 1)*32:(blocksFound*2 + 1)*32 + 32]
        if myBlock == flagBlock:
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
```

Thanks for the great challenge and also the great CTF! I had a lot of fun playing it and once again learned a lot!