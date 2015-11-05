import util_4
import time

def hmac_sha1(key, message, blocksize=64):
    if len(key) > blocksize:
        key = util_4.SHA1(key, len(key)).hexdigest()
    key = key.ljust(blocksize, '\x00')
    o_key_pad = ''.join([chr(ord(each) ^ 0x5c) for each in key])
    i_key_pad = ''.join([chr(ord(each) ^ 0x36) for each in key])
    intermediate = util_4.SHA1(i_key_pad + message, len(i_key_pad + message)).hexdigest()
    return util_4.SHA1(o_key_pad + intermediate, len(o_key_pad + intermediate)).hexdigest()

def server_check(filename, signature):
    file_mac = hmac_sha1(key, filename)
    return (200 if insecure_compare(signature, file_mac) else 500)

def insecure_compare(signature, file_mac):
    for i,j in zip(signature, file_mac):
        time.sleep(0.05)
        if i!=j:
            return False
    return True

key = "A" * 50
mac = hmac_sha1(key, "HELLO")
print server_check("HELLO", mac)
