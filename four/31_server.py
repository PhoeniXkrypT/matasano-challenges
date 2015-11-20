import web
import urlparse
import time

import util_4

urls = ( '/file=\w+&signature=\w+', 'index')

class index:
    
    def GET(self):
        url = web.url()
        filename = url[url.rfind('/file=')+6 : url.rfind('&')]
        signature = url[url.rfind('signature=')+10 : ]
        if not(self.server_check(filename, signature)):
            self.send_response(500)
        return 
    
    def hmac_sha1(self, message, blocksize=64):
        key = 'A' * 16
        if len(key) > blocksize:
            key = util_4.SHA1(key, len(key)).hexdigest()
        key = key.ljust(blocksize, '\x00')
        o_key_pad = ''.join([chr(ord(each) ^ 0x5c) for each in key])
        i_key_pad = ''.join([chr(ord(each) ^ 0x36) for each in key])
        intermediate = util_4.SHA1(i_key_pad + message, len(i_key_pad + message)).hexdigest()
        return util_4.SHA1(o_key_pad + intermediate, len(o_key_pad + intermediate)).hexdigest()

    def server_check(self, filename, signature):
        file_mac = self.hmac_sha1(filename)
        return self.insecure_compare(signature.decode('hex'), file_mac.decode('hex'))

    def insecure_compare(self, signature, file_mac):
        for i,j in zip(signature, file_mac):
            if i!=j:
                return False
            time.sleep(0.05)
        return True
    
def main():
    app = web.application(urls, globals())
    app.run()

if __name__ == '__main__':
    main()