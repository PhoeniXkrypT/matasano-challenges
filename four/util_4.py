import sys

from hashlib import sha1

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
        new_cipher = cipher[:16] + '\x00'*blocksize + cipher[:16] + cipher[48:]
        msg = util_2.pkcs7_unpadding(util_2.AES_CBC_decrypt(new_cipher, key, key, blocksize), blocksize)
        return util_1.fixed_xor(msg[:16].encode('hex'), msg[32:48].encode('hex')).decode('hex')

    message = "comment1=cooking%20MCs;userdata=testuser;comment2=%20like%20a%20pound%20of%20bacon"
    cipher = util_2.AES_CBC_encrypt(util_2.pkcs7_padding(message, blocksize), key, key, blocksize)
    recovered_key = recover_key(cipher)
    return (key == recovered_key)

class SHA1(object):
    _h0, _h1, _h2, _h3, _h4, = (
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

    def __init__(self, message):
        length = bin(len(message) * 8)[2:].rjust(64, "0")
        while len(message) > 64:
            self._handle(''.join(bin(i)[2:].rjust(8, "0")
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
    return SHA1(key + message).hexdigest()

def tamper(key, message, mac):
    for i, each in enumerate(message):
        new_message = message[:i] + chr(ord(each) + 1) + message[i:]
        if SHA1(key + new_message).hexdigest() == mac:
            return True
    return False

def reproduce(message, mac):
    for _ in xrange(5000):
        if SHA1(util_2.get_random_string(16) + message) == mac:
            return True
    return False

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
        else:
            raise ArgumentError("Give argument between 25 and 32")
    except ArgumentError, e:
        print e

if __name__ == '__main__':
    main()
