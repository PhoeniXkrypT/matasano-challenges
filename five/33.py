import random
from hashlib import sha256

p = "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff"
p = int(p, 16)
g = 2

class user1(object):
    global p, g
    def __init__(self):
        self.a = random.randint(20, 100) % p

    def send(self):
        return pow(g, self.a, p)

    def secret(self, B):
        s = pow(B, self.a, p)
        return sha256(str(s)).hexdigest()

class user2(object):
    global p, g
    def __init__(self):
        self.b = random.randint(20, 100) % p

    def send(self):
        return pow(g, self.b, p)

    def secret(self, A):
        s = pow(A, self.b, p)
        return sha256(str(s)).hexdigest()

user_1 = user1()
A = user_1.send()
user_2 = user2()
B = user_2.send()
assert user_1.secret(B) == user_2.secret(A)
