import sys
import base64
import random
import urlparse
import urllib
from Crypto.Cipher import AES
from collections import OrderedDict

import util_1

get_random_string = lambda l : ''.join([chr(random.randint(0,255)) for i in xrange(l)])

class PaddingException(Exception):
    pass

def pkcs7_padding(message, blocksize):
    if len(message) % blocksize == 0:
        padding_value = blocksize
    else:
        padding_value = blocksize - (len(message) % blocksize)
    return message + (chr(padding_value) * padding_value)

def pkcs7_unpadding(message, blocksize):
   if len(message) % blocksize != 0:
       raise PaddingException("Bad padding")
   padding_value = message[-1]
   if message[-ord(padding_value):] != padding_value * ord(padding_value):
       raise PaddingException("Bad padding")
   return message[:-ord(padding_value)]

def AES_CBC_encrypt(message, key, IV, blocksize):
    message_blocks = [message[i:i+blocksize] for i in\
                       xrange(0, len(message), blocksize)]
    cipher_blocks =[]
    prev_block = IV.encode('hex')
    for current_block in message_blocks:
        intermediate = util_1.fixed_xor(current_block.encode('hex'), prev_block)
        current_cipher =util_1.AES_ECB_encrypt(intermediate.decode('hex'), key)
        cipher_blocks.append(current_cipher)
        prev_block = current_cipher.encode('hex')
    return ''.join(cipher_blocks)

def AES_CBC_decrypt(cipher, key, IV, blocksize):
    cipher_blocks = [cipher[i:i+blocksize] for i in \
                     xrange(0, len(cipher), blocksize)]
    decrypted_blocks=[]
    prev_block = IV.encode('hex')
    for current_block in cipher_blocks:
        intermediate = util_1.AES_ECB_decrypt(current_block, key).encode('hex')
        decrypted_blocks.append(util_1.fixed_xor(intermediate, \
                                 prev_block).decode('hex'))
        prev_block = current_block.encode('hex')
    return ''.join(decrypted_blocks)

def encryption_oracle(message, blocksize=16):
    key = get_random_string(blocksize)
    modified_message = get_random_string(random.randint(5,10)) + message + \
                       get_random_string(random.randint(5,10))
    modified_message = pkcs7_padding(modified_message, blocksize)
    mode = random.randrange(2)      # 0 = ECB, 1 = CBC
    if mode == 0:
        return util_1.AES_ECB_encrypt(modified_message, key), mode
    else:
        IV = get_random_string(blocksize)
        return AES_CBC_encrypt(modified_message, key, IV, blocksize), mode

def encryption_mode_detector(cipher):
    try:
        if max(util_1.check_ECB([cipher.encode('hex')]))[0] > 1:
            return 0
    except ValueError,e:
        return 1

def byte_at_a_time(num):
    AES_KEY = '.Rm\x10o\xaae\xf3coy}\xbf\x00\xa4&'
    pre = get_random_string(random.randrange(5,12))

    def s_encryption_oracle(message, blocksize=16):
        unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        modified_message = pkcs7_padding(message + base64.b64decode(unknown_string), blocksize)
        return util_1.AES_ECB_encrypt(modified_message, AES_KEY)

    def h_encryption_oracle(message, blocksize=16):
        target = 'VHdvIHJvYWRzIGRpdmVyZ2VkIGluIGEgd29vZCwgYW5kIEktCkkgdG9vayB0aGUgb25lIGxlc3MgdHJhdmVsZWQgYnks'
        modified_message = pkcs7_padding(pre + message + base64.b64decode(target), blocksize)
        return util_1.AES_ECB_encrypt(modified_message, AES_KEY)

    def detect_ECB_blocksize():
        for i in xrange(5, 100):
            enc = s_encryption_oracle('A' * 2 * i)
            try:
                if util_1.check_ECB([enc.encode('hex')])[0][0] > 1:
                    return i
                else:
                    return None
            except IndexError,e:
                pass

    def find_prefix_length():
        for i in xrange(32, 48):
            enc = h_encryption_oracle('A' * i)
            blocks = [enc[16*j:16*(j+1)] for j in xrange(1, (len(enc)//16)+1)]
            for k in xrange(0,len(blocks)-1):
                if blocks[k] == blocks[k+1]:
                    return (48 - i), k
        return None

    if num == 0:
        assert detect_ECB_blocksize() == 16
        decoded_string = ""
        _len = 144
        for index in xrange(_len-1, 5, -1):
            inputs_dict = {}
            test_input = 'A' * index
            for i in xrange(256):
                inputs_dict[s_encryption_oracle(test_input + decoded_string + chr(i))[:_len]] = chr(i)
            try:
                decoded_string += inputs_dict[s_encryption_oracle(test_input)[:_len]]
            except KeyError,e :
                pass
    elif num == 1:
        _len = 128
        decoded_string = ""
        pre_len, pre_blocks = find_prefix_length()
        pad_len = 16 - pre_len
        for index in xrange(_len-1, 0, -1):
            inputs_dict = {}
            test_input = 'A' * (index + pad_len)
            for i in xrange(256):
                inputs_dict[h_encryption_oracle(test_input + decoded_string + chr(i))[pre_blocks*16 : _len+pad_len]] = chr(i)
            try:
                decoded_string += inputs_dict[h_encryption_oracle(test_input)[pre_blocks*16 : _len+pad_len]]
            except KeyError,e :
                pass
    return decoded_string

def admin_profile():
    key = get_random_string(16)
    parsing_routine = lambda data : dict(urlparse.parse_qsl(data))

    def profile_for(mail_id):
        if ('&' in mail_id) or ('=' in mail_id):
            mail_id = mail_id.replace('&', '').replace('=','')
        data = {'email':mail_id, 'uid':10, 'role':'user'}
        return '&'.join(['%s=%s'%(each,data[each]) for each in ['email', 'uid','role']])

    def profile_encrypt(mail, key, blocksize=16):
        encoded_profile = profile_for(mail)
        return util_1.AES_ECB_encrypt(pkcs7_padding(encoded_profile, blocksize), key)

    def profile_decrypt(cipher, key, blocksize=16):
        encoded_profile = pkcs7_unpadding(util_1.AES_ECB_decrypt(cipher, key), blocksize)
        return parsing_routine(encoded_profile)

    def create_admin(crafted_input, key):
        encrypted = profile_encrypt(crafted_input, key)
        add_admin = encrypted[:16] + encrypted[32:48] + encrypted[16:32]
        return profile_decrypt(add_admin, key)

    assert parsing_routine('foo=bar&baz=qux&zap=zazzle') == {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}
    assert profile_decrypt(profile_encrypt('foo@bar.com', key), key) == {'role': 'user', 'email': 'foo@bar.com', 'uid': '10'}
    return create_admin("abc@got.coadmin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b.in", key)

def cbc_bitflipping_attack():
    AES_KEY = get_random_string(16)

    def encrypt_modify(input_string, blocksize=16):
        pre = "comment1=cooking%20MCs;userdata="
        post = ";comment2=%20like%20a%20pound%20of%20bacon"
        if (';' in input_string) or ('=' in input_string):
            input_string = input_string.replace(';', '').replace('=', '')
        input_string = pre + input_string + post
        padded = pkcs7_padding(input_string, blocksize)
        return AES_CBC_encrypt(padded, AES_KEY, chr(0)* blocksize, blocksize)

    def decrypt_search_admin(cipher, blocksize=16):
        padded_message = AES_CBC_decrypt(cipher, AES_KEY, chr(0)*blocksize, blocksize)
        message = pkcs7_unpadding(padded_message, blocksize)
        return (";admin=true;" in message)

    enc_data = encrypt_modify((chr(0)*21)+" admin true")
    for i in xrange(256):
        for j in xrange(256):
            enc_data = enc_data[:37] + chr(i) + enc_data[38:43] + chr(j) + enc_data[44:]
            if decrypt_search_admin(enc_data):
                return True
    return False

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
        assert byte_at_a_time(0) == "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n"
    elif sys.argv[1] == "13":
        assert admin_profile() == {'role': 'admin', 'email': 'abc@got.co.in', 'uid': '10'}
    elif sys.argv[1] == "14":
        assert byte_at_a_time(1) == "Two roads diverged in a wood, and I-\nI took the one less traveled by,\x01"
    elif sys.argv[1] == "15":
        assert pkcs7_unpadding("ICE ICE BABY\x04\x04\x04\x04", 16) == "ICE ICE BABY"
        try:
            assert pkcs7_unpadding("ICE ICE BABY\x05\x05\x05\x05", 16) == "Bad padding"
            assert pkcs7_unpadding("ICE ICE BABY\x01\x02\x03\x04", 16) == "Bad padding"
        except PaddingException, e:
            pass
    elif sys.argv[1] == "16":
        assert cbc_bitflipping_attack() == True


if __name__ == '__main__':
    main()
