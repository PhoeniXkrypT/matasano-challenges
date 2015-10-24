import sys
import util_2
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

def ctr_bitflipping_attack():
    AES_KEY = util_2.get_random_string(16)

    def encrypt_modify(input_string):
        pre = "comment1=cooking%20MCs;userdata="
        post = ";comment2=%20like%20a%20pound%20of%20bacon"
        if (';' in input_string) or ('=' in input_string):
            input_string = input_string.replace(';', '').replace('=', '')
        return util_3.ctr_stream(pre + input_string + post, AES_KEY)

    def decrypt_search_admin(cipher):
        message = util_3.ctr_stream(cipher, AES_KEY)
        return (";admin=true;" in message)

    cipher = encrypt_modify(" admin true")
    for i in xrange(256):
        for j in xrange(256):
            new_cipher = cipher[:32] + chr(i) + cipher[33:38] + chr(j) + cipher[39:]
            if decrypt_search_admin(new_cipher):
                return True
    return False

def main():
    try:
        if sys.argv[1] == "25":
            plaintext = (''.join([line.strip() for line in open('out_7.txt')])).decode('hex')
            cipher = util_3.ctr_stream(plaintext, 'c62a824f5d01d4bca11d4382cddfca19'.decode('hex'))
            assert break_read_write_ctr(cipher) == plaintext
        elif sys.argv[1] == "26":
            assert ctr_bitflipping_attack() == True
        else:
            raise ArgumentError("Give argument between 25 and 32")
    except ArgumentError, e:
        print e

if __name__ == '__main__':
    main()
