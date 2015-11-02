import util_1
import util_2
import util_3
import test
import binascii

def sha_glue_padding(message_length):
    length = bin(message_length * 8)[2:].rjust(64,"0")
    msg_remains = ((message_length % 64) * 8) + 1
    return ("1" + "0" * ((448 - msg_remains % 512) % 512) + length)

def attack(message, mac):
    mac_chunk = [int(mac[i:i+8],16) for i in xrange(0, len(mac), 8)]
    new_msg = ";admin=true"
    keylength = 1
    while True:
        message_length = len(message) + keylength
        glue_padding = sha_glue_padding(message_length)
        glue_padding = binascii.unhexlify('%x' % int(glue_padding, 2))
        length = bin(message_length * 8)[2:].rjust(64, "0")
        new_mac = test.SHA1(new_msg, length, mac_chunk[0], mac_chunk[1], mac_chunk[2], mac_chunk[3], mac_chunk[4]).hexdigest()
        if test.SHA1(key + message + glue_padding + new_msg, length).hexdigest() == new_mac:
            return True
        keylength+=1
    return False
    
message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
key = "YELLOW SUBMARINE"
length = bin(len(key + message) * 8)[2:].rjust(64, "0")
mac = test.SHA1(key + message, length).hexdigest()
print attack(message, mac)
