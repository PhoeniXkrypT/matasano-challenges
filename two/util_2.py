import sys
import base64
import random
from Crypto.Cipher import AES

import util_1 as util

def pkcs7_padding(message, blocksize):
    if len(message) % blocksize == 0:
        padding_value = blocksize
    else:
        padding_value = blocksize - (len(message) % blocksize)
    return message + (chr(padding_value) * padding_value)

def pkcs7_unpadding(message, blocksize):
   # if len(message) % blocksize != 0:
   padding_value = message[-1]
   return message[:-ord(padding_value)]

def AES_CBC_encrypt(message, key, IV, blocksize):
    message_blocks = [message[i:i+blocksize] for i in\
                       xrange(0, len(message), blocksize)]
    cipher_blocks =[]
    prev_block = IV.encode('hex')
    for current_block in message_blocks:
        intermediate = util.fixed_xor(current_block.encode('hex'), prev_block)
        current_cipher =util.AES_ECB_encrypt(intermediate.decode('hex'), key)
        cipher_blocks.append(current_cipher)
        prev_block = current_cipher.encode('hex')
    return ''.join(cipher_blocks)

def AES_CBC_decrypt(cipher, key, IV, blocksize):
    cipher_blocks = [cipher[i:i+blocksize] for i in \
                     xrange(0, len(cipher), blocksize)]
    decrypted_blocks=[]
    prev_block = IV.encode('hex')
    for current_block in cipher_blocks:
        intermediate = util.AES_ECB_decrypt(current_block, key).encode('hex')
        decrypted_blocks.append(util.fixed_xor(intermediate, \
                                 prev_block).decode('hex'))
        prev_block = current_block.encode('hex')
    return ''.join(decrypted_blocks)

def generate_AESkeys(blocksize):
    return ''.join([chr(random.randint(0, 255)) for i in xrange(blocksize)])

def encryption_oracle(message, blocksize):
    key = generate_AESkeys(blocksize)
    modified_message = ''.join([chr(random.randint(0,255)) for i in xrange(random.randint(5,10))]) + message + \
                       ''.join([chr(random.randint(0,255)) for i in xrange(random.randint(5,10))])
    modified_message = pkcs7_padding(modified_message, blocksize)
    mode = random.randrange(2)      # 0 = ECB, 1 = CBC
    if mode == 0:
        return util.AES_ECB_encrypt(modified_message, key), mode
    else:
        IV = ''.join([chr(random.randint(0,255)) for i in xrange(blocksize)])
        return AES_CBC_encrypt(modified_message, key, IV, blocksize), mode

def encryption_mode_detector(cipher, blocksize):
    try:
        if max(util.check_ECB([cipher.encode('hex')], blocksize))[0] > 1:
            return 0
    except ValueError,e:
        return 1

def main():
    if sys.argv[1] == "9":
        assert pkcs7_padding("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"
    elif sys.argv[1] == "10":
        lines = ''.join([line.strip() for line in open('set2_10.txt')])
        blocksize = 16
        assert AES_CBC_decrypt(base64.b64decode(lines), "YELLOW SUBMARINE", (chr(0) * blocksize), blocksize).encode('hex') == ''.join([line.strip() for line in open('out_10.txt')])
    elif sys.argv[1] == "11":
        blocksize = 16
        cipher, mode = encryption_oracle("A" * 1500, blocksize)
        detected_mode = encryption_mode_detector(cipher, blocksize)
        assert mode == detected_mode


if __name__ == '__main__':
    main()
