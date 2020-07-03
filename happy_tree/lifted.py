import z3
from Crypto.Util.number import long_to_bytes

def u32(chars):
    ret = z3.BitVecVal(0, 32)
    ret = z3.ZeroExt(24, chars[0]) | (z3.ZeroExt(24, chars[1]) << 8) | (z3.ZeroExt(24, chars[2]) << 16) | (z3.ZeroExt(24, chars[3]) << 24)
    return ret

def p32(num):
    return [num & 0xff, (num >> 8) & 0xff, (num >> 16) & 0xff, (num >> 24) & 0xff]

def first_check(flag):
    loc_7 = flag
    for i in range(0x186a0):
        tmp1 = loc_7 << 0xd # 0x56582884
        tmp2 = tmp1 ^ loc_7 # 0x56586f00
        tmp3 = tmp2 >> 0x11 # 0x5657e20c
        tmp4 = tmp3 ^ tmp2 # 0x56586cf8
        tmp5 = tmp4 << 5 # 0x56583590
        tmp6 = tmp5 ^ tmp4 # 0x56586c58
        loc_7 = tmp6
    return loc_7

flag = []
for i in range(36):
    flag.append(z3.BitVec(f'flag_{i}', 8))

all_consts = [2724054634, 11141174, 3327000602, 916260948, 4049325967, 1807620453, 426167697, 3569744893, 2957679387]
xor_consts = [0, 2863311530, 0, 2863311530, 0, 2863311530, 0, 2863311530, 0]

def constrain(s, chars, idx):
    if idx == 0:
        s.add(chars[0] == ord('f'))
        s.add(chars[1] == ord('l'))
        s.add(chars[2] == ord('a'))
        s.add(chars[3] == ord('g'))
    if idx == 1:
        s.add(chars[0] == ord('}'))

    for c in chars:
        s.add(c >= ord(' '), c <= ord('~'))

for idx, (xor, num) in enumerate(zip(xor_consts, all_consts)):
    part = z3.BitVec('part', 32)
    s = z3.Solver()
    s.add(first_check(part ^ xor) == num)
    constrain(s, p32(part), idx)
    print(s.check())
    print(s.model())
    print(s.modle().eval(part))
    print(long_to_bytes(s.modle().eval(part).as_long()))