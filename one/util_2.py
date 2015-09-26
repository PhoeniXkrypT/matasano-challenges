
def fixed_xor(hexstring_one, hexstring_two):
    assert len(hexstring_one) == len(hexstring_two)
    decoded_one = hexstring_one.decode("hex")
    decoded_two = hexstring_two.decode("hex")
    xored_string = ""
    for i, j in zip(decoded_one, decoded_two):
        xored_string += chr(ord(i) ^ ord(j))
    return xored_string.encode("hex")

def main():
    assert fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"

if __name__ == '__main__':
    main()

