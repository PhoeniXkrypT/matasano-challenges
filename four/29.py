import util_1
import util_2
import util_3
import test
import binascii

def sha_glue_padding(message):
    length = bin(len(message) * 8)[2:].rjust(64,"0")
    msg_remains = ((len(message) % 64) * 8) + 1
    return ("1" + "0" * ((448 - msg_remains % 512) % 512) + length)

def attack():
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    key = "YELLOW SUBMARINE"
    print "MAC"
    mac = test.SHA1(key + message).hexdigest()
    mac_chunk = [int(mac[i:i+8],16) for i in xrange(0, len(mac), 8)]
    new_msg = ";admin=true"
    message_length = len(message) + len(key)
    _message = key + message
    glue_padding = sha_glue_padding(_message)
    glue_padding = binascii.unhexlify('%x' % int(glue_padding, 2))
    print "NEW MAC"
    new_mac = test.SHA1(new_msg, mac_chunk[0], mac_chunk[1], mac_chunk[2], mac_chunk[3], mac_chunk[4]).hexdigest()
    print "new_mac",new_mac
    print "HASH"
    print test.SHA1(key + message + glue_padding + new_msg).hexdigest()

attack()

"""
def attack():
    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    key = "YELLOW SUBMARINE"
    mac = test.SHA1(key + message).hexdigest()
    mac_chunk = [int(mac[i:i+8],16) for i in xrange(0, len(mac), 8)]
    new_msg = ";admin=true"
    keylength = 1
    while True:
        print keylength
        message_length = len(message) + keylength
        glue_padding = sha_glue_padding(message_length)
        new_mac = test.SHA1(new_msg, mac_chunk[0], mac_chunk[1], mac_chunk[2], mac_chunk[3], mac_chunk[4]).hexdigest()
        if keylength == 16:
            print new_mac, test.SHA1(key + message + glue_padding + new_msg).hexdigest()
        if test.SHA1(key + message + glue_padding + new_msg).hexdigest() == new_mac:
            print " === ", new_mac
            return True
        keylength += 1
    return False

print attack()
"""
