import util_2
import test
import binascii

def sha1_hash_length_extension():
    key = util_2.get_random_string(16)

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
            new_mac = test.SHA1(new_msg, message_length+len(glue_padding)+len(new_msg), mac_chunk[0], mac_chunk[1], mac_chunk[2], mac_chunk[3], mac_chunk[4]).hexdigest()
            if sha_sign(message + glue_padding + new_msg) == new_mac:
                return True
            keylength+=1
        return False

    def sha_sign(message):
        return test.SHA1(key + message, len(key+message)).hexdigest()

    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = sha_sign(message)
    return attack(message, mac)

assert sha1_hash_length_extension() == True
