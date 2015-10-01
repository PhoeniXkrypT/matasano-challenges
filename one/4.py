import string
import sys
import base64
from collections import Counter

std_freq = {
    'A':8.167, 'B':1.492, 'C':2.782, 'D':4.253, 'E':12.702,
    'F':2.228, 'G':2.015, 'H':6.094, 'I':6.996, 'J':0.153,
    'K':0.772, 'L':4.025, 'M':2.406, 'N':6.749, 'O':7.507,
    'P':1.929, 'Q':0.095, 'R':5.987, 'S':6.327, 'T':9.056,
    'U':2.758, 'V':0.978, 'W':2.360, 'X':0.150, 'Y':1.974,
    'Z':0.074 }

class SingleXorException(Exception):
    pass

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
            return (possible_data, p_string_index[position])
        except ValueError, e:
            raise SingleXorException("Freqency difference empty")
        raise SingleXorException("Other characters")



lines = [line.strip() for line in open('set1_4.txt')]
possible_text =[]
for each in lines:
    string_xor = SingleXor(each)
    try:
        possible_text.append(string_xor.decrypt())
    except SingleXorException, e:
        pass
index_coincidence, ratio=[],[]
for data in possible_text:
    length = float(len(data[0]))
    each_string = filter(lambda x:x in string.letters, data[0].upper())
    ratio.append(len(each_string)/length)
print possible_text[ratio.index(max(ratio))][0]


"""    freq_table = Counter(each_string)
    index_coincidence.append(sum(freq_table[each]*(freq_table[each]-1) for each in freq_table)/(length*(length-1)))
index = index_coincidence.index(min(index_coincidence, key=lambda i:abs(i-0.0667)))
print possible_text,"\n", index_coincidence"""
