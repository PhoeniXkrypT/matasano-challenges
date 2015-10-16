import sys
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

def ctr_stream_decrypt(cipher, key, blocksize=16):
    nonce, counter = 0, 0
    message = ""

    cipher_blocks = [cipher[i:i+blocksize] for i in xrange(0,len(cipher), blocksize)]
    for each in cipher_blocks:
        intermediate = util_1.AES_ECB_encrypt(struct.pack("<Q", nonce) + struct.pack("<Q", counter), key)[:len(each)]
        message += util_1.fixed_xor(each.encode('hex'), intermediate.encode('hex')).decode('hex')
        counter += 1
    return message


def main():
    if sys.argv[1] == "17":
        assert CBC_padding_oracle() == 200
    elif sys.argv[1] == "18":
        assert ctr_stream_decrypt(base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPw    eyyMTJULu/6/kXX0KSvoOLSFQ=='), 'YELLOW SUBMARINE') == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
