import base64
import random
import urlparse
from Crypto.Cipher import AES
from collections import OrderedDict

import util_1 as util
import util_2

get_random_string = lambda l : ''.join([chr(random.randint(0,255)) for i in xrange(l)])

def cbc_bitflipping_attack():
    AES_KEY = '.Rm\x10o\xaae\xf3coy}\xbf\x00\xa4&'

    def encrypt_modify(input_string, blocksize=16):
        pre = "comment1=cooking%20MCs;userdata="
        post = ";comment2=%20like%20a%20pound%20of%20bacon"
        if (';' in input_string) or ('=' in input_string):
            input_string = input_string.replace(';', '').replace('=', '')
        input_string = pre + input_string + post
        padded = util_2.pkcs7_padding(input_string, blocksize)
        return util_2.AES_CBC_encrypt(padded, AES_KEY, chr(0)* blocksize, blocksize)

    def decrypt_search_admin(cipher, blocksize=16):
        padded_message = util_2.AES_CBC_decrypt(cipher, AES_KEY, chr(0)*blocksize, blocksize)
        message = util_2.pkcs7_unpadding(padded_message, blocksize)
        return (";admin=true;" in message)

    enc_data = encrypt_modify((chr(0)*21)+" admin true")
    for i in xrange(256):
        for j in xrange(256):
            enc_data = enc_data[:37] + chr(i) + enc_data[38:43] + chr(j) + enc_data[44:]
            if decrypt_search_admin(enc_data):
                return True
    return False

assert cbc_bitflipping_attack() == True
