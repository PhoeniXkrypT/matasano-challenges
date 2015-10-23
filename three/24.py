import util_3
import random
import time

def mt19937_encrypt(message, seed):
    mt = util_3.MT19937(seed)
    enc = ""
    for each in message:
        enc += chr(ord(each) ^ (mt.extract_number() & 0xff))
    return enc.encode('hex')

def recover_key(data, cipher):
    return [each for each in xrange(32768, 65535) if (mt19937_encrypt(data, each)) == cipher][0]

def generate_password_token(seed):
    mt = util_3.MT19937(seed)
    return mt.extract_number()

def crack_password_token(token):
    current_time = int(time.time())
    for i in xrange(50):
        mt = util_3.MT19937(current_time-i)
        if mt.extract_number() == token:
            return current_time - i

data = ''.join([chr(random.randint(1,255)) for _ in xrange(random.randint(3,16))]) + ('A' * 14)
seed = random.randint(32768,65535)
cipher = mt19937_encrypt(data,seed)
assert recover_key(data, cipher) == seed
seed = int(time.time())
token = generate_password_token(seed)
assert crack_password_token(token) == seed
