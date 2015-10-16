import struct
import base64

import util_1

def ctr_stream(input_string, key, nonce=0, blocksize=16):
    counter = 0
    out_message = ""

    blocks = [input_string[i:i+blocksize] for i in xrange(0, len(input_string), blocksize)]
    for each in blocks:
        intermediate = util_1.AES_ECB_encrypt(struct.pack("<Q", nonce) + struct.pack("<Q", counter), key)[:len(each)]
        out_message += util_1.fixed_xor(each.encode('hex'), intermediate.encode('hex')).decode('hex')
        counter += 1
    return out_message

assert ctr_stream(base64.b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPw    eyyMTJULu/6/kXX0KSvoOLSFQ=='), 'YELLOW SUBMARINE') == "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "

