import sys

def pkcs7_padding(message, blocksize):
    if len(message) % blocksize == 0:
        padding_value = blocksize
    else:
        padding_value = blocksize - (len(message) % blocksize)
    return message + (chr(padding_value) * padding_value)

def main():
    if sys.argv[1] == "9":
        assert pkcs7_padding("YELLOW SUBMARINE", 20) == "YELLOW SUBMARINE\x04\x04\x04\x04"

if __name__ == '__main__':
    main()
