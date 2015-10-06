from Crypto.Cipher import AES
import util_1 as util
import base64

def AES_CBC_decrypt(cipher, key, IV, blocksize):
    cipher_blocks = [cipher[i:i+blocksize] for i in \
                     xrange(0, len(cipher), blocksize)]
    decrypted_blocks=[]
    prev_block = IV.encode('hex')
    for current_block in cipher_blocks:
        temp = util.AES_ECB_decrypt(current_block, key).encode('hex')
        decrypted_blocks.append(util.fixed_xor(temp, prev_block).decode('hex'))
        prev_block = current_block.encode('hex')
    return ''.join(decrypted_blocks)

lines = ''.join([line.strip() for line in open('set2_10.txt')])
blocksize = 16
assert AES_CBC_decrypt(base64.b64decode(lines), "YELLOW SUBMARINE",\
                      (chr(0) * blocksize), blocksize).encode('hex') == \
       ''.join([line.strip() for line in open('out_10.txt')])
