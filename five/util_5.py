import sys
import random
from hashlib import sha256

import util_2
import util_4

p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
p = int(p, 16)
g = 2

class dh_user(object):
    global p, g
    def __init__(self):
        self.var = random.randint(20, 100) % p

    def public_value(self):
        return pow(g, self.var, p)

    def get_common_secret(self, pub):
        return pow(pub, self.var, p)

class Send_Receive():
    def __init__(self, key, msg):
        self.msg = msg
        self.key = key
        self.blocksize = 16

    def send(self):
        s = str(self.key)
        sha_s = util_4.SHA1(s, len(s)).hexdigest()
        iv = util_2.get_random_string(16)
        return util_2.AES_CBC_encrypt(util_2.pkcs7_padding(self.msg, self.blocksize), sha_s[0:16], iv, self.blocksize) + iv

    def receive(self):
        s = str(self.key)
        sha_s = util_4.SHA1(s, len(s)).hexdigest()
        return util_2.pkcs7_unpadding(util_2.AES_CBC_decrypt(self.msg[0:-16], sha_s[0:16], self.msg[-16:], self.blocksize), self.blocksize)

def attack():
    # protocol without MITM
    user1 = dh_user()
    A = user1.public_value()
    user2 = dh_user()
    B = user2.public_value()

    sa = user1.get_common_secret(p)
    sb = user2.get_common_secret(p)

    # A --> M
    a_msg = Send_Receive(sa, "test message").send()
    # at M
    sm = '0'
    decoded_a_msg = Send_Receive(sm, a_msg).receive()
    # M --> B
    a_msg_b = Send_Receive(sb, a_msg).receive()

    # B --> M
    b_msg = Send_Receive(sb, "replay msg").send()
    # at M
    decoded_b_msg = Send_Receive(sm, b_msg).receive()
    # M --> A
    b_msg_a = Send_Receive(sa, b_msg).receive()
    return (b_msg_a == "replay msg") and (a_msg_b == "test message")

def main():
    try:
        if sys.argv[1] == "33":
            user1 = dh_user()
            A = user1.public_value()
            user2 = dh_user()
            B = user2.public_value()
            assert sha256(str(user1.get_common_secret(B))).hexdigest() == sha256(str(user2.get_common_secret(A))).hexdigest()
        elif sys.argv[1] == "34":
            assert attack() == True
        else:
            raise util_4.ArgumentError("Give argument between 33 and 40")
    except util_4.ArgumentError, e:
        print e

if __name__ == '__main__':
    main()
