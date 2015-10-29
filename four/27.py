import util_1
import util_2
import util_3

import string

def cbc_key_as_iv():
    blocksize = 16
    key = util_2.get_random_string(blocksize)

    def recover_key(cipher):
        new_cipher = cipher[:16] + '\x00' * blocksize + cipher[:16] + cipher[48:]
        msg = util_2.pkcs7_unpadding(util_2.AES_CBC_decrypt(new_cipher, key, key, blocksize), blocksize)
        if not(all(each in string.printable for each in msg)):
            return util_1.fixed_xor(msg[:16].encode('hex'), msg[32:48].encode('hex')).decode('hex')
        return 0

    message = "comment1=cooking%20MCs;userdata=testuser;comment2=%20like%20a%20pound%20of%20bacon"
    cipher = util_2.AES_CBC_encrypt(util_2.pkcs7_padding(message, blocksize), key, key, blocksize)
    recovered_key = recover_key(cipher)
    return (key == recovered_key)

assert cbc_key_as_iv() == True
