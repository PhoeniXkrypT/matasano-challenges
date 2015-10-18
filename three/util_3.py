import sys
import time
import struct
import base64
import random
from Crypto.Cipher import AES
from collections import OrderedDict

import util_1
import util_2

def CBC_padding_oracle():
    AES_KEY = '\xc6*\x82O]\x01\xd4\xbc\xa1\x1dC\x82\xcd\xdf\xca\x19'
    random_strings = {0: 'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=', 1: 'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=', 2: 'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==', 3: 'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==', 4: 'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl', 5: 'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==', 6: 'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==', 7: 'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=', 8: 'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=', 9: 'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'}
    index = random.randrange(0,10)

    def random_CBC_encrypt(blocksize=16):
        input_string = random_strings[index]
        padded_string = util_2.pkcs7_padding(input_string, blocksize)
        IV = util_2.get_random_string(blocksize)
        return util_2.AES_CBC_encrypt(padded_string, AES_KEY, IV, blocksize), IV

    def check_padding(cipher, IV, blocksize=16):
        padded_cipher = util_2.AES_CBC_decrypt(cipher, AES_KEY, IV, blocksize)
        try:
            message = util_2.pkcs7_unpadding(padded_cipher, blocksize)
            return 200
        except util_2.PaddingException, e:
            return 500

    def padding_attack(current_block, prev_block, blocksize=16):
        position = 1
        intermediate = ""
        while position <= blocksize:
            for val in xrange(1, 256):
                IV = chr(0)*(blocksize-position) + chr(val) + (util_1.fixed_xor(intermediate.encode('hex'), \
                                                              (chr(position)*len(intermediate)).encode('hex')).decode('hex'))
                if check_padding(current_block, IV) == 200:
                    intermediate = chr(ord(chr(position)) ^ ord(chr(val))) + intermediate
                    position += 1
                    break
        result = util_1.fixed_xor(intermediate.encode('hex'), prev_block.encode('hex'))
        return result.decode('hex')

    def attacker_function(cipher, IV, blocksize=16):
        cipher_blocks = [cipher[i:i+blocksize] for i in xrange(0, len(cipher), blocksize)]
        message = padding_attack(cipher_blocks[0], IV)
        for i in xrange(1, len(cipher_blocks)):
            message += padding_attack(cipher_blocks[i], cipher_blocks[i-1])
        return base64.b64decode(message)

    cipher, IV = random_CBC_encrypt()
    decrypted = attacker_function(cipher, IV)
    if '00000'+str(index) in decrypted:
        return 200
    else :
        return 404

def ctr_stream(input_string, key, nonce=0, blocksize=16):
    counter = 0
    out_message = ""

    blocks = [input_string[i:i+blocksize] for i in xrange(0, len(input_string), blocksize)]
    for each in blocks:
        intermediate = util_1.AES_ECB_encrypt(struct.pack("<Q", nonce) + struct.pack("<Q", counter), key)[:len(each)]
        out_message += util_1.fixed_xor(each.encode('hex'), intermediate.encode('hex')).decode('hex')
        counter += 1
    return out_message

def _int32(x):
    # Get the 32 least significant bits.
    return int(0xFFFFFFFF & x)

class MT19937:

    def __init__(self, seed):
        # Initialize the index to 0
        self.index = 624
        self.mt = [0] * 624
        self.mt[0] = seed  # Initialize the initial state to the seed
        for i in range(1, 624):
            self.mt[i] = _int32(
                1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    def extract_number(self):
        if self.index >= 624:
            self.twist()
        y = self.mt[self.index]

        # Right shift by 11 bits
        y = y ^ y >> 11
        # Shift y left by 7 and take the bitwise and of 2636928640
        y = y ^ y << 7 & 2636928640
        # Shift y left by 15 and take the bitwise and of y and 4022730752
        y = y ^ y << 15 & 4022730752
        # Right shift by 18 bits
        y = y ^ y >> 18
        self.index = self.index + 1
        return _int32(y)

    def twist(self):
        for i in range(0, 624):
            # Get the most significant bit & add it to the less significant
            # bits of the next number
            y = _int32((self.mt[i] & 0x80000000) +
                       (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1

            if y % 2 != 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
        self.index = 0

def crack_seed(r_number):
    current = int(time.time())
    for i in xrange(4,15):
        mt = MT19937(current - i)
        if r_number == mt.extract_number() :
            return current-i

def gen_rng_unix():
    time.sleep(random.randint(2,6))
    seed = int(time.time())
    rng = MT19937(seed)
    time.sleep(random.randint(4,15))
    return rng.extract_number(), seed

def main():
    if sys.argv[1] == "17":
        assert CBC_padding_oracle() == 200
    elif sys.argv[1] == "18":
        assert ctr_stream(base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='), 'YELLOW SUBMARINE') == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
    elif sys.argv[1] == "21":
        m_twister = MT19937(150)
        assert m_twister.extract_number() == 3902338276
    elif sys.argv[1] == "22":
        number, seed = gen_rng_unix()
        assert crack_seed(number) == seed

if __name__ == '__main__':
    main()
