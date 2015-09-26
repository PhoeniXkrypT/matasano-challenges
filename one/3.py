import string
std_freq = {
    'A':8.167, 'B':1.492, 'C':2.782, 'D':4.253, 'E':12.702,
    'F':2.228, 'G':2.015, 'H':6.094, 'I':6.996, 'J':0.153,
    'K':0.772, 'L':4.025, 'M':2.406, 'N':6.749, 'O':7.507,
    'P':1.929, 'Q':0.095, 'R':5.987, 'S':6.327, 'T':9.056,
    'U':2.758, 'V':0.978, 'W':2.360, 'X':0.150, 'Y':1.974,
    'Z':0.074 }

class SingleXor(object):
    def __init__(self, cipher):
        self.cipher = cipher

    def decrypt(self):
        decoded_data = self.cipher.decode('hex')
        printable_stings = []
        freq_diff = []
        for key in xrange(256):
            temp = ""
            flag = False
            for char in decoded_data:
                xored_char = chr(ord(char) ^ key)
                if xored_char in string.printable:
                    temp += xored_char
                else:
                    flag = True
                    break
            if not flag:
                printable_stings.append(temp)
        # find freq difference with standard values
        for each_string in printable_stings:
            freq_table = {i : 0 for i in string.uppercase}
            for each in each_string.upper():
                if each in string.uppercase:
                    freq_table[each] += 1/float(len(each_string))
            freq_diff.append(sum([abs(std_freq[a]-freq_table[b]) \
                                  for a,b in zip(std_freq, freq_table)]))
        position = freq_diff.index(min(freq_diff))
        print printable_stings[position]


string_xor = SingleXor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
string_xor.decrypt()
