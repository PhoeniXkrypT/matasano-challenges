import sys
import random
from hashlib import sha256

import util_2
import util_4

p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
p = int(p, 16)

class DHUser(object):
    global p
    def __init__(self, g=2):
        self.var = random.randint(20, 100) % p
        self.g = g

    def public_value(self):
        return pow(self.g, self.var, p)

    def get_common_secret(self, pub):
        return pow(pub, self.var, p)

class SendReceive():
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

def mitm_attack(user1, user2, temp):
    A = user1.public_value()
    B = user2.public_value()
    if temp == '1':
        global p
        sa = user1.get_common_secret(p)
        sb = user2.get_common_secret(p)
        sm = '0'
    elif temp == '2':
        sa = user1.get_common_secret(B)
        sb = user2.get_common_secret(A)
        if (A == B): # a and b are either odd or even
            sm = A
        else:
            sm = 1
    # at A
    a_msg = SendReceive(sa, "test message").send()
    # at M
    decoded_a_msg = SendReceive(sm, a_msg).receive()
    # at B
    a_msg_b = SendReceive(sb, a_msg).receive()
    b_msg = SendReceive(sb, a_msg_b).send()
    # at M
    decoded_b_msg = SendReceive(sm, b_msg).receive()
    # at A
    b_msg_a = SendReceive(sa, b_msg).receive()
    return (b_msg_a == "test message")

def main():
    try:
        if sys.argv[1] == "33":
            user1 = DHUser()
            A = user1.public_value()
            user2 = DHUser()
            B = user2.public_value()
            assert sha256(str(user1.get_common_secret(B))).hexdigest() == sha256(str(user2.get_common_secret(A))).hexdigest()
        elif sys.argv[1] == "34":
            user1 = DHUser()
            user2 = DHUser()
            assert mitm_attack(user1, user2, '1') == True
        elif sys.argv[1] == "35":
            for each in [1, p, (p-1)]:
                user1 = DHUser(each)
                user2 = DHUser(each)
                assert mitm_attack(user1, user2, '2') == True
        else:
            raise util_4.ArgumentError("Give argument between 33 and 40")
    except util_4.ArgumentError, e:
        print e
    except IndexError, e:
        print "Error : Follow format util_5.py <question_number>"

if __name__ == '__main__':
    main()
