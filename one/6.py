import binascii
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
            #if all(i in eng_text for i in possible_data):
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

def edit_distance(string_one, string_two):
    string_one_binary, string_two_binary = bin(int(binascii.hexlify(string_one), 16)), bin(int(binascii.hexlify(string_two), 16))
    return sum([1 for i,j in zip(string_one_binary, \
                string_two_binary) if i!=j])

def find_keysize(lines):
    edits=[]
    for KEYSIZE in xrange(2, 41):
        chunks = [lines[i:i+KEYSIZE] for i in \
                  xrange(0, len(lines), KEYSIZE)]
        edits.append(sum(edit_distance(one, two)/KEYSIZE \
                for one, two in zip(chunks, chunks[1:]))/float(len(chunks[1:])))
    return [edits.index(each)+2 for each in sorted(edits)[:2]]

def transpose_blocks(keysize, data):
    cipher_blocks = [data[i:i+keysize] for i in xrange(0, len(data), keysize)]
    blocks =[]
#        [blocks.append(''.join([each[i] for each in cipher_blocks])) for i in xrange(len(cipher_blocks[0]))]
    for i in xrange(len(cipher_blocks[0])):
        temp=[]
        for each in cipher_blocks:
            try:
                temp.append(each[i])
            except IndexError, e:
                pass
        blocks.append(''.join(temp))
    return blocks

_lines = ''.join([line.strip() for line in open('set1_6.txt')])
lines = base64.b64decode(_lines)
keysize = find_keysize(lines)
blocks_trans = transpose_blocks(keysize[1], lines)
temp=[]
for i, each in enumerate(blocks_trans):
    single_xor = SingleXor(each.encode('hex'))
    temp.append(chr(single_xor.decrypt()[1]))
key = ''.join(temp)
print key
repeat_xor = RepeatingXor(lines, key)
repeat_xor.encrypt().decode('hex')
