import struct
import base64

import util_1

def ctr_stream(blocksize=16):
    cipher = base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    key = 'YELLOW SUBMARINE'
    nonce, counter = 0, 0
    message = ""

    cipher_blocks = [cipher[i:i+blocksize] for i in xrange(0,len(cipher), blocksize)]
    for each in cipher_blocks:
        intermediate = util_1.AES_ECB_encrypt(struct.pack("<Q", nonce) + struct.pack("<Q", counter), key)[:len(each)]
        message += util_1.fixed_xor(each.encode('hex'), intermediate.encode('hex')).decode('hex')
        counter += 1
    return message

assert ctr_stream() == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "


