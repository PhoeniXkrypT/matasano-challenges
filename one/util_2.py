def fixed_xor(hexstring_one, hexstring_two):
    assert len(hexstring_one) == len(hexstring_two)
    decoded_one, decoded_two = hexstring_one.decode("hex"), \
            hexstring_two.decode("hex")
    xored_string = ''.join([chr(ord(i) ^ ord(j))  \
            for i,j in zip(decoded_one, decoded_two)])
    return xored_string.encode("hex")

def main():
    assert fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"

if __name__ == '__main__':
    main()

