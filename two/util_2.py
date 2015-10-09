import sys
import base64
import random
from Crypto.Cipher import AES

import util_1 as util

get_random_string = lambda l : ''.join([chr(random.randint(0,255)) for i in xrange(l)])

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

def generate_AESkeys(blocksize = 16):
    return ''.join([chr(random.randint(0, 255)) for i in xrange(blocksize)])

def encryption_oracle(message, blocksize=16):
    key = generate_AESkeys()
    modified_message = get_random_string(random.randint(5,10)) + message + \
                       get_random_string(random.randint(5,10))
    modified_message = pkcs7_padding(modified_message, blocksize)
    mode = random.randrange(2)      # 0 = ECB, 1 = CBC
    if mode == 0:
        return util.AES_ECB_encrypt(modified_message, key), mode
    else:
        IV = get_random_string(blocksize)
        return AES_CBC_encrypt(modified_message, key, IV, blocksize), mode

def encryption_mode_detector(cipher):
    try:
        if max(util.check_ECB([cipher.encode('hex')]))[0] > 1:
            return 0
    except ValueError,e:
        return 1

def byte_at_a_time():
    AES_KEY = '.Rm\x10o\xaae\xf3coy}\xbf\x00\xa4&'

    def _encryption_oracle(message, blocksize=16):
        unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        modified_message = pkcs7_padding(message + base64.b64decode(unknown_string), blocksize)
        return util.AES_ECB_encrypt(modified_message, AES_KEY)

    def detect_ECB_blocksize():
        for i in xrange(5, 100):
            enc = _encryption_oracle('A' * 2 * i)
            try:
                if util.check_ECB([enc.encode('hex')])[0][0] > 1:
                    return i
                else:
                    return None
            except IndexError,e:
                pass

    assert detect_ECB_blocksize() == 16
    decoded_string = ""
    _len = 144
    for index in xrange(_len-1, 5, -1):
        inputs_dict = {}
        test_input = 'A' * index
        for i in xrange(256):
            inputs_dict[_encryption_oracle(test_input + decoded_string + chr(i))[:_len]] = chr(i)
        try:
            decoded_string += inputs_dict[_encryption_oracle(test_input)[:_len]]
        except KeyError,e :
            pass
    return decoded_string


def main():
    if sys.argv[1] == "9":
        assert pkcs7_padding("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"
    elif sys.argv[1] == "10":
        lines = ''.join([line.strip() for line in open('set2_10.txt')])
        blocksize = 16
        assert AES_CBC_decrypt(base64.b64decode(lines), "YELLOW SUBMARINE", (chr(0) * blocksize), blocksize).encode('hex') == ''.join([line.strip() for line in open('out_10.txt')])
    elif sys.argv[1] == "11":
        cipher, mode = encryption_oracle("A" * 60)
        detected_mode = encryption_mode_detector(cipher)
        assert mode == detected_mode
    elif sys.argv[1] == "12":
        assert byte_at_a_time() == "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"

if __name__ == '__main__':
    main()
