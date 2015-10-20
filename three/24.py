import util_3
import random

def encrypt(message, seed):
    mt = util_3.MT19937(seed)
    enc = ""
    for each in message:
        enc += chr(ord(each) ^ (mt.extract_number() & 0xff))
    return enc.encode('hex')

def recover_key(data, cipher):
    for each in xrange(32768, 65535):
        if (encrypt(data, each)) == cipher:
            return each

data = ''.join([chr(random.randint(1,255)) for _ in xrange(random.randint(3,16))]) + ('A' * 14)
seed = random.randint(32768,65535)
cipher = encrypt(data,seed)
assert recover_key(data, cipher) == seed

