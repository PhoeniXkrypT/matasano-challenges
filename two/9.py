import binascii

def pkcs7_padding(message, blocksize):
    if len(message) == blocksize :
        padding_value = blocksize
    else:
        padding_value = blocksize - (len(message) % blocksize)
    message += (binascii.unhexlify('%02x' % padding_value) * padding_value)
    return message

def main():
    assert pkcs7_padding("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"

if __name__ == '__main__':
    main()
