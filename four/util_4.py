import sys
import util_3

class ArgumentError(Exception):
    pass

def edit_api(cipher, offset, newtext, key='c62a824f5d01d4bca11d4382cddfca19'.decode('hex')):
    plaintext = util_3.ctr_stream(cipher, key)
    new_plaintext = plaintext[:offset] + newtext + plaintext[offset:]
    return util_3.ctr_stream(new_plaintext, key)

def break_read_write_ctr(cipher):
    new_cipher = edit_api(cipher, 0, 'A' * len(cipher))
    key = ''.join([chr(ord(i) ^ ord(j)) for i,j in zip(new_cipher, 'A' * len(cipher))])
    return ''.join([chr(ord(i) ^ ord(j)) for i,j in zip(cipher, key)])

def main():
    try:
        if sys.argv[1] == "25":
            plaintext = (''.join([line.strip() for line in open('out_7.txt')])).decode('hex')
            cipher = util_3.ctr_stream(plaintext, 'c62a824f5d01d4bca11d4382cddfca19'.decode('hex'))
            assert break_read_write_ctr(cipher) == plaintext
        else:
            raise ArgumentError("Give argument between 25 and 32")
    except ArgumentError, e:
        print e

if __name__ == '__main__':
    main()
