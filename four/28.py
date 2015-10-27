import util_2
from hashlib import sha1

def sha1_authentication(key, message):
    return sha1(key + message).hexdigest()

def tamper(key, message, mac):
    for i, each in enumerate(message):
        new_message = message[:i] + chr(ord(each) + 1) + message[i:]
    if sha1(key + new_message).hexdigest() == mac:
        return True
    return False

def reproduce(message, mac):
    for _ in xrange(5000):
        if sha1(util_2.get_random_string(16) + message) == mac:
            return True
    return False

message = 'A' * 15
key = util_2.get_random_string(16)
mac = sha1_authentication(key, message)
assert tamper(key, message, mac) == False
assert reproduce(message, mac) == False
