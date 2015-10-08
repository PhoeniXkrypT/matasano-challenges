import random
import util_1 as util
import util_2 as utils
from collections import Counter

def check_ECB(ciphers, blocksize):
    repeated_blocks = []
    for each in ciphers:
        each = each.decode('hex')
        commom_block_count = Counter([each[i:i+blocksize] for i in xrange(0, len(each), blocksize)]).most_common()
        if commom_block_count[0][1] > 1:
            repeated_blocks.append((commom_block_count[0][1], each))
    return repeated_blocks

def generate_AESkeys():
    return ''.join([chr(random.randint(0, 255)) for i in xrange(16)])

def encryption_oracle(message):
    key = generate_AESkeys()
    blocksize = len(key)
    modified_message = ''.join([chr(random.randint(0,255)) for i in xrange(random.randint(5,10))]) + message + ''.join([chr(random.randint(0,255)) for i in xrange(random.randint(5,10))])
    modified_message = utils.pkcs7_padding(modified_message, blocksize)
    mode = random.randrange(2)
    # 0 = ECB, 1 = CBC
    if mode == 0:
        return util.AES_ECB_encrypt(modified_message, key), mode
    else:
        IV = ''.join([chr(random.randint(0,255)) for i in xrange(blocksize)])
        return utils.AES_CBC_encrypt(modified_message, key, IV, blocksize), mode

def encryption_mode_detector(cipher):
    blocksize = 16
    try:
        if max(check_ECB([cipher.encode('hex')], blocksize))[0] > 1:
            return 0
    except ValueError,e:
        return 1

cipher, mode = encryption_oracle("A" * 500)
if encryption_mode_detector(cipher):
    assert mode == 1
else:
    assert mode == 0
