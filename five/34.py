import random

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

def main():
    # protocol without MITM
    user1 = dh_user()
    A = user1.public_value()
    user2 = dh_user()
    B = user2.public_value()
    sa = Send_Receive(user1.get_common_secret(B), "test message").send()
    sb = Send_Receive(user2.get_common_secret(A), sa).receive()
    assert sb == "test message"

if __name__ == '__main__':
    main()
