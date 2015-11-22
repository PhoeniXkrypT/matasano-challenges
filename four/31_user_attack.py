import urllib
import web
import time

import util_4

def hmac_sha1(key, message, blocksize=64):
    if len(key) > blocksize:
        key = util_4.SHA1(key, len(key)).hexdigest()
    key = key.ljust(blocksize, '\x00')
    o_key_pad = ''.join([chr(ord(each) ^ 0x5c) for each in key])
    i_key_pad = ''.join([chr(ord(each) ^ 0x36) for each in key])
    intermediate = util_4.SHA1(i_key_pad + message, len(i_key_pad + message)).hexdigest()
    return util_4.SHA1(o_key_pad + intermediate, len(o_key_pad + intermediate)).hexdigest()

def user():
    key = 'A' * 16
    filename = 'hello'
    mac = hmac_sha1(key, filename)
    return mac, filename
    
def attack(filename):
    signature_crack = ['\x00'] * 20
    for i in xrange(20):
        timings = {}
        for j in xrange(256):
            temp = signature_crack[:i] + [chr(j)] + signature_crack[i+1:]
            start = time.time()
            send_file_sig(filename, ''.join(temp).encode('hex'))
            timings[int((time.time()-start) * 1000)] = j
        signature_crack[i] = chr(timings[max(timings)])
        print [chr(timings[max(timings)])]
    return ''.join(signature_crack).encode('hex')

def send_file_sig(filename, signature):
    baseurl = "http://0.0.0.0:8080/file=" + filename + "&signature=" + signature
    response = urllib.urlopen(baseurl)
    return response.getcode()
    
def main():
    mac, filename = user()
    assert send_file_sig(filename, mac) == 200
    print [each for each in mac.decode('hex')]
    cracked_mac = attack(filename)
    assert cracked_mac == mac

if __name__ == '__main__':
    main()
