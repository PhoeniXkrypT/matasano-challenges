import util_3

def clone_mt19937():
    def reverse_right_shift(value, shift, mult=0xffffffff):
        output, i = 0, 0
        while i * shift < 32:
            compartment = int(bin(0xffffffff << (32 - shift))[-32:], 2) >> (shift * i)
            part_output = value & compartment
            value ^= (part_output >> shift) & mult
            output |= part_output
            i += 1
        return output

    def reverse_left_shift(value, shift, mult=0xffffffff):
        output, i = 0, 0
        while i * shift < 32:
            compartment = int(bin((0xffffffff >> (32- shift)) << (shift * i))[-32:], 2)
            part_output = value & compartment
            value ^= (part_output << shift) & mult
            output |= part_output
            i += 1
        return output

    def untemper(value):
        value = reverse_right_shift(value, 18)
        value = reverse_left_shift(value, 15, 4022730752)
        value = reverse_left_shift(value, 7, 2636928640)
        value = reverse_right_shift(value, 11)
        return value

    def temper(value):
        value = value ^ value >> 11
        value = value ^ value << 7 & 2636928640
        value = value ^ value << 15 & 4022730752
        value = value ^ value >> 18
        return value

    mt = util_3.MT19937(15015)
    rand_numbers, states = [], []
    for i in xrange(624):
        rand_numbers.append(mt.extract_number())
    for each in rand_numbers:
        states.append(untemper(each))
    return [1 for i in xrange(len(states)) if temper(states[i]) != rand_numbers[i]]

assert clone_mt19937() == []
