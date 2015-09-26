import sys
import base64

def hex_to_base64(hexstring):
    return base64.b64encode(hexstring.decode("hex"))

def fixed_xor(hexstring_one, hexstring_two):
    assert len(hexstring_one) == len(hexstring_two)
    decoded_one, decoded_two = hexstring_one.decode("hex"), \
                               hexstring_two.decode("hex")
    xored_string = ''.join([chr(ord(i) ^ ord(j))  \
                            for i,j in zip(decoded_one, decoded_two)])
    return xored_string.encode("hex")

def main():
    if sys.argv[1] == "1":
        assert hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    elif sys.argv[1] == "2":
        assert fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"

if __name__ == '__main__':
    main()

