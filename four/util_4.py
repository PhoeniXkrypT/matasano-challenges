import sys
import struct
import string

import util_1
import util_2
import util_3

class ArgumentError(Exception):
    pass

def edit_api(cipher, offset, newtext, key='c62a824f5d01d4bca11d4382cddfca19'.decode('hex')):
    plaintext = util_3.ctr_stream(cipher, key)
    new_plaintext = plaintext[:offset] + newtext + plaintext[offset:]
    return util_3.ctr_stream(new_plaintext, key)

def break_read_write_ctr(cipher):
    new_cipher = edit_api(cipher, 0, 'A' * len(cipher))
    key = ''.join([chr(ord(i) ^ ord(j)) for i,j in zip(new_cipher, 'A' * len(cipher))])
    return ''.join([chr(ord(i) ^ ord(j)) for i,j in zip(cipher, key)])

def ctr_bitflipping_attack():
    AES_KEY = util_2.get_random_string(16)

    def encrypt_modify(input_string):
        pre = "comment1=cooking%20MCs;userdata="
        post = ";comment2=%20like%20a%20pound%20of%20bacon"
        if (';' in input_string) or ('=' in input_string):
            input_string = input_string.replace(';', '').replace('=', '')
        return util_3.ctr_stream(pre + input_string + post, AES_KEY)

    def decrypt_search_admin(cipher):
        message = util_3.ctr_stream(cipher, AES_KEY)
        return (";admin=true;" in message)

    cipher = encrypt_modify(" admin true")
    for i in xrange(256):
        for j in xrange(256):
            new_cipher = cipher[:32] + chr(i) + cipher[33:38] + chr(j) + cipher[39:]
            if decrypt_search_admin(new_cipher):
                return True
    return False

def cbc_key_as_iv():
    blocksize = 16
    key = util_2.get_random_string(blocksize)

    def recover_key(cipher):
        new_cipher = cipher[:16] + '\x00' * blocksize + cipher[:16] + cipher[48:]
        msg = util_2.pkcs7_unpadding(util_2.AES_CBC_decrypt(new_cipher, key, key, blocksize), blocksize)
        if not(all(each in string.printable for each in msg)):
            return util_1.fixed_xor(msg[:16].encode('hex'), msg[32:48].encode('hex')).decode('hex')
        return 0

    message = "comment1=cooking%20MCs;userdata=testuser;comment2=%20like%20a%20pound%20of%20bacon"
    cipher = util_2.AES_CBC_encrypt(util_2.pkcs7_padding(message, blocksize), key, key, blocksize)
    return (key == recover_key(cipher))

class SHA1(object):

    def __init__(self, message, msg_len, _h0=0x67452301, _h1=0xefcdab89, _h2=0x98badcfe, _h3=0x10325476, _h4=0xc3d2e1f0):
        self._h0,self._h1, self._h2, self._h3, self._h4 = _h0, _h1, _h2, _h3, _h4

        length = bin((msg_len) * 8)[2:].rjust(64, "0")
        while len(message) > 64:
            self._handle(''.join(bin(ord(i))[2:].rjust(8, "0")
                for i in message[:64]))
            message = message[64:]
        message = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in message) + "1"
        message += "0" * ((448 - len(message) % 512) % 512) + length
        for i in range(len(message) // 512):
            self._handle(message[i * 512:i * 512 + 512])

    def _handle(self, chunk):
        lrot = lambda x, n: (x << n) | (x >> (32 - n))
        w = []
        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))
        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
                & 0xffffffff)
        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        for i in range(80):
            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6
            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d
        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff

    def _digest(self):
        return (self._h0, self._h1, self._h2, self._h3, self._h4)

    def hexdigest(self):
        return ''.join(hex(i)[2:].rjust(8, "0")
            for i in self._digest())

    def digest(self):
        hexdigest = self.hexdigest()
        return bytes(int(hexdigest[i * 2:i * 2 + 2], 16)
            for i in range(len(hexdigest) // 2))

def sha1_authentication(key, message):
    return SHA1(key + message, len(key + message)).hexdigest()

def tamper(key, message, mac):
    for i, each in enumerate(message):
        new_message = message[:i] + chr(ord(each) + 1) + message[i:]
        if SHA1(key + new_message, len(key + new_message)).hexdigest() == mac:
            return True
    return False

def reproduce(message, mac):
    for _ in xrange(5000):
        if SHA1(util_2.get_random_string(16) + message, 16 + len(message)).hexdigest() == mac:
            return True
    return False

def sha1_length_extension():
    key = util_2.get_random_string(16)
    def sha_sign(message):
        return SHA1(key + message, len(key+message)).hexdigest()
        
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
            glue_padding = ''.join([chr(int(glue_padding[i:i+8], 2)) for i in xrange(0, len(glue_padding), 8)])
            new_mac = SHA1(new_msg, message_length + len(glue_padding + new_msg), mac_chunk[0], \
                           mac_chunk[1], mac_chunk[2], mac_chunk[3], mac_chunk[4]).hexdigest()
            if sha_sign(message + glue_padding + new_msg) == new_mac:
                return True
            keylength+=1
        return False

    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = sha_sign(message)
    return attack(message, mac)

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4(object):
    def __init__(self, h=[0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476], _len=0, data=""):
        self.remainder = data
        self.count = 0
        if _len:
            self.h = h
        else:
            self.h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
        self._len = _len

    def _add_chunk(self, chunk):
        self.count += 1
        X = list(struct.unpack("<16I", chunk) + (None,) * (80-16))
        h = [x for x in self.h]
        # Round 1
        s = (3, 7, 11, 19)
        for r in xrange(16):
            i = (16 - r) % 4
            k = r
            h[i] = leftrotate((h[i] + F(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4]) + X[k]) % 2**32, s[r % 4])
        # Round 2
        s = (3, 5, 9, 13)
        for r in xrange(16):
            i = (16 - r) % 4
            k = 4 * (r % 4) + r // 4
            h[i] = leftrotate((h[i] + G(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4]) + X[k] + 0x5a827999) % 2**32, s[r % 4])
        # Round 3
        s = (3, 9, 11, 15)
        k = (0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15) #wish I could function
        for r in xrange(16):
            i = (16 - r) % 4
            h[i] = leftrotate((h[i] + H(h[(i + 1) % 4], h[(i + 2) % 4], h[(i + 3) % 4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r % 4])

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def add(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in xrange(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk + 64] )
        return self

    def finish(self):
        if self._len:
            self.count = int(self._len/64)
        l = len(self.remainder) + 64 * self.count
        self.add("\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8))
        out = struct.pack("<4I", *self.h)
        return out
        
def md4_length_extension():
    key = util_2.get_random_string(16)
    def md4_sign(message):
        md = MD4()
        md.add(key + message)
        return md.finish().encode('hex')

    def md4_glue_padding(message_length):
        l = (message_length % 64) + 64 * int(message_length/64)
        return ("\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8))

    def attack(message, mac):
        new_msg = ";admin=true"
        keylength = 1
        while True:
            message_length = len(message) + keylength
            glue_padding = md4_glue_padding(message_length)
            md_modified = MD4(list(struct.unpack("<4I",mac.decode('hex'))), message_length + len(glue_padding + new_msg))
            md_modified.add(new_msg)
            new_mac = md_modified.finish().encode('hex')
            if md4_sign(message + glue_padding + new_msg) == new_mac:
                return True
            keylength += 1
        return False

    message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
    mac = md4_sign(message)
    return attack(message, mac)

def main():
    try:
        if sys.argv[1] == "25":
            plaintext = (''.join([line.strip() for line in open('out_7.txt')])).decode('hex')
            cipher = util_3.ctr_stream(plaintext, 'c62a824f5d01d4bca11d4382cddfca19'.decode('hex'))
            assert break_read_write_ctr(cipher) == plaintext
        elif sys.argv[1] == "26":
            assert ctr_bitflipping_attack() == True
        elif sys.argv[1] == "27":
            assert cbc_key_as_iv() == True
        elif sys.argv[1] == "28":
            message, key = 'A' * 15, util_2.get_random_string(16)
            mac = sha1_authentication(key, message)
            assert tamper(key, message, mac) == False
            assert reproduce(message, mac) == False
        elif sys.argv[1] == "29":
            assert sha1_length_extension() == True
        elif sys.argv[1] == "30":
            assert md4_length_extension() == True
        else:
            raise ArgumentError("Give argument between 25 and 32")
    except ArgumentError, e:
        print e

if __name__ == '__main__':
    main()
