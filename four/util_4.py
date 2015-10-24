import sys
import util_3

class ArgumentError(Exception):
    pass

def edit(cipher, offset, newtext, key='\xc6*\x82O]\x01\xd4\xbc\xa1\x1dC\x82\xcd\xdf\xca\x19'):
    plaintext = util_3.ctr_stream(cipher, key)
    new_plaintext = plaintext[:offset] + newtext + plaintext[offset:]
    return util_3.ctr_stream(new_plaintext, key)

def retrive_plain(cipher):
    new_cipher = edit(cipher, 0, 'A' * len(cipher))
    key = ''.join([chr(ord(i) ^ ord(j)) for i,j in zip(new_cipher, 'A' * len(cipher))])
    return ''.join([chr(ord(i) ^ ord(j)) for i,j in zip(cipher, key)])

def main():
    try:
        if sys.argv[1] == "25":
            plaintext = (''.join([line.strip() for line in open('out_7.txt')])).decode('hex')
            cipher = util_3.ctr_stream(plaintext, '\xc6*\x82O]\x01\xd4\xbc\xa1\x1dC\x82\xcd\xdf\xca\x19')
            assert retrive_plain(cipher) == plaintext
        else:
            raise ArgumentError("Give argument between 25 and 32")
    except ArgumentError, e:
        print e

if __name__ == '__main__':
    main()
