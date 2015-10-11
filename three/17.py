import sys
import base64
import random
from Crypto.Cipher import AES
from collections import OrderedDict

import util_1
import util_2

def CBC_padding_oracle():
    AES_KEY = '\xc6*\x82O]\x01\xd4\xbc\xa1\x1dC\x82\xcd\xdf\xca\x19'
    def random_CBC_encrypt(blocksize=16):
        random_strings = {0: 'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=', 1: 'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    2: 'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==', 3: 'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    4: 'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl', 5: 'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    6: 'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==', 7: 'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    8: 'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=', 9: 'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'}
        input_string = random_strings[random.randrange(0,10)]
        padded_string = util_2.pkcs7_padding(input_string, blocksize)
        IV = util_2.get_random_string(blocksize)
        return util_2.AES_CBC_encrypt(padded_string, AES_KEY, IV, blocksize), IV

    def check_padding(cipher, IV, blocksize=16):
        padded_cipher = util_2.AES_CBC_decrypt(cipher, AES_KEY, IV, blocksize)
        try:
            message = util_2.pkcs7_unpadding(padded_cipher, blocksize)
            return True
        except PaddingException, e:
            return False

    cipher, IV = random_CBC_encrypt()
    print check_padding(cipher, IV)

CBC_padding_oracle()
