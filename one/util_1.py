import sys
import string
import base64

std_freq = {
    'A':8.167, 'B':1.492, 'C':2.782, 'D':4.253, 'E':12.702,
    'F':2.228, 'G':2.015, 'H':6.094, 'I':6.996, 'J':0.153,
    'K':0.772, 'L':4.025, 'M':2.406, 'N':6.749, 'O':7.507,
    'P':1.929, 'Q':0.095, 'R':5.987, 'S':6.327, 'T':9.056,
    'U':2.758, 'V':0.978, 'W':2.360, 'X':0.150, 'Y':1.974,
    'Z':0.074 }
eng_text = string.letters + string.digits + string.whitespace + ". ' ! ?"

class SingleXorException(Exception):
    pass

def hex_to_base64(hexstring):
    return base64.b64encode(hexstring.decode("hex"))

def fixed_xor(hexstring_one, hexstring_two):
    assert len(hexstring_one) == len(hexstring_two)
    decoded_one, decoded_two = hexstring_one.decode("hex"), \
                               hexstring_two.decode("hex")
    xored_string = ''.join([chr(ord(i) ^ ord(j))  \
                            for i,j in zip(decoded_one, decoded_two)])
    return xored_string.encode("hex")

class SingleXor(object):
    def __init__(self, cipher):
        self.cipher = cipher.decode('hex')

    def decrypt(self):
        printable_strings, p_string_index, freq_diff = [], [], []
        for key in xrange(256):
            temp = ''.join([chr(ord(i) ^ key) for i in self.cipher])
            if all(i in string.printable for i in temp):
                    printable_strings.append(temp)
                    p_string_index.append(key)
        # find freq difference with standard values
        for each_string in printable_strings:
            freq_table = {i : 0 for i in string.uppercase}
            length = float(len(each_string))
            each_string = filter(lambda x:x in string.letters, \
                                               each_string.upper())
            for each in each_string:
                    freq_table[each] += 1
            freq_table = {i : freq_table[i]/length for i in freq_table}
            freq_diff.append(sum([abs(std_freq[a] - freq_table[a]) \
                                  for a in std_freq]))
        try:
            position = freq_diff.index(min(freq_diff))
            possible_data = printable_strings[position]
            if all(i in eng_text for i in possible_data):
                return (possible_data, p_string_index[position])
        except ValueError, e:
            raise SingleXorException("Freqency difference empty")
        raise SingleXorException("Other characters")

class RepeatingXor(object):
    def __init__(self, data, key):
        self.data = data
        self.key = key

    def encrypt(self):
        repeat_key = ''.join([self.key for i in \
                              xrange(0, len(self.data), len(self.key))])
        repeat_key = repeat_key[:len(self.data)]
        xored_string = ''.join([chr(ord(i) ^ ord(j)) \
                                for i,j in zip(self.data, repeat_key)])
        return xored_string.encode('hex')


def main():
    if sys.argv[1] == "1":
        assert hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    elif sys.argv[1] == "2":
        assert fixed_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") == "746865206b696420646f6e277420706c6179"
    elif sys.argv[1] == "3":
        string_xor = SingleXor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        assert string_xor.decrypt()[0] == "Cooking MC's like a pound of bacon"
    elif sys.argv[1] == "4":
        lines = [line.strip() for line in open('set1_4.txt')]
        for each in lines:
            string_xor = SingleXor(each)
            try:
                assert string_xor.decrypt()[0] == "Now that the party is jumping\n"
            except SingleXorException, e:
                pass
    elif sys.argv[1] == "5":
        repeat_xor = RepeatingXor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE")
        assert repeat_xor.encrypt() == '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'

if __name__ == '__main__':
    main()

