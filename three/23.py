import temp

def clone_mt19937():
    def reverse_right_shift(value, shift):
        result, i = 0, 0
        while i * shift < 32:
            mask = int(bin(0xffffffff << (32 - shift))[-32:], 2) >> (shift * i)
            part = value & mask
            value ^= part >> shift
            result |= part
            i += 1
        return result

    def reverse_left_shift(value, shift, mult):
        result, i = 0, 0
        while i * shift < 32:
            mask = (0xffffffff >> (32- shift)) << (shift * i)
            part = value & mask
            value ^= (part << shift) & mult
            result |= part
            i += 1
        return result

    def untemper(value):
        value = reverse_right_shift(value, 18)
        value = reverse_left_shift(value, 15, 4022730752)
        value = reverse_left_shift(value, 7, 2636928640)
        value = reverse_right_shift(value, 11)
        return value

    def temper(y):
        y = y ^ y >> 11
        y = y ^ y << 7 & 2636928640
        y = y ^ y << 15 & 4022730752
        y = y ^ y >> 18
        return y

    mt = temp.MT19937(15015)
    rngs, states = [], []
    for i in xrange(624):
        rngs.append(mt.extract_number())
    for each in rngs:
        states.append(untemper(each))
    for i in xrange(len(states)):
        if temper(states[i]) != rngs[i]:
            return 0
    return 1

assert clone_mt19937() == 1
