import util_2
import test
import struct

def md4_length_extension():
    #key = util_2.get_random_string(16)
    key = "YELLOW SUBMARINE"

    def md4_glue_padding(message_length):
        l = (message_length % 64) + 64 * int(message_length/64)
        return ("\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8))

    def md4_sign(message):
        md = test.MD4()
        md.add(key + message)
        return md.finish().encode('hex')

    def attack(message, mac):
        mac_chunk = list(struct.unpack("<4I",mac.decode('hex')))
        new_msg = ";admin=true"

        message_length = len(message) + 16
        glue_padding = md4_glue_padding(message_length)
        md_modified = test.MD4(message_length + len(glue_padding + new_msg), mac_chunk)
        md_modified.add(new_msg)
        new_mac = md_modified.finish().encode('hex')
        temp = md4_sign(message + glue_padding + new_msg)
        return (temp == new_mac)


    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = md4_sign(message)
    return attack(message, mac)

print md4_length_extension()

"""

        keylength = 10
        while keylength<17:
            message_length = len(message) + keylength
            glue_padding = md4_glue_padding(message_length)
            md_modified = test.MD4(message_length + len(glue_padding + new_msg), mac_chunk)
            md_modified.add(new_msg)
            new_mac = md_modified.finish().encode('hex')
            print keylength, new_mac
            print md4_sign(message + glue_padding + new_msg)
            if md4_sign(message + glue_padding + new_msg) == new_mac:
                return True
            keylength += 1
        return False
"""
