import sys
import base64
from Crypto.Cipher import AES

import util_1 as util

def pkcs7_padding(message, blocksize):
    if len(message) % blocksize == 0:
        padding_value = blocksize
    else:
        padding_value = blocksize - (len(message) % blocksize)
    return message + (chr(padding_value) * padding_value)

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

def main():
    if sys.argv[1] == "9":
        assert pkcs7_padding("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"
    elif sys.argv[1] == "10":
        lines = ''.join([line.strip() for line in open('set2_10.txt')])
        blocksize = 16
        assert AES_CBC_decrypt(base64.b64decode(lines), "YELLOW SUBMARINE", (chr(0) * blocksize), blocksize).encode('hex') == ''.join([line.strip() for line in open('out_10.txt')])


if __name__ == '__main__':
    main()
