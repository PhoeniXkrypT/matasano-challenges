import base64
import random
from Crypto.Cipher import AES

import util_1 as util
import util_2 as utils

get_random_string = lambda l : ''.join([chr(random.randint(0,255)) for i in xrange(l)])

AES_KEY = '.Rm\x10o\xaae\xf3coy}\xbf\x00\xa4&'

def _encryption_oracle(message, blocksize=16):
    pre = 'c\xb3\xd1\xc8CL\x0e\xf0+\xe8'
    target = 'VHdvIHJvYWRzIGRpdmVyZ2VkIGluIGEgd29vZCwgYW5kIEktCkkgdG9vayB0aGUgb25lIGxlc3MgdHJhdmVsZWQgYnks'
    modified_message = utils.pkcs7_padding(pre + message + base64.b64decode(target), blocksize)
    return util.AES_ECB_encrypt(modified_message, AES_KEY)

def find_prefix_length():
    for i in xrange(32, 48):
        enc = _encryption_oracle('A' * i)
        blocks = [enc[16*j:16*(j+1)] for j in xrange(1, (len(enc)//16)+1)]
        for k in xrange(0,len(blocks)-1):
            if blocks[k] == blocks[k+1]:
                return (48 - i), k
    return None

_len = 128
decoded_string = ""
pre_len, pre_blocks = find_prefix_length()
pad_len = 16 - pre_len
for index in xrange(_len-1, 0, -1):
    inputs_dict = {}
    test_input = 'A' * (index + pad_len)
    for i in xrange(256):
        inputs_dict[_encryption_oracle(test_input + decoded_string + chr(i))[pre_blocks*16 : _len+pad_len]] = chr(i)
    try:
        decoded_string += inputs_dict[_encryption_oracle(test_input)[pre_blocks*16 : _len+pad_len]]
    except KeyError,e :
        pass

assert decoded_string == "Two roads diverged in a wood, and I-\nI took the one less traveled by,\x01"
