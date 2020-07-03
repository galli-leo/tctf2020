from pwn import *
import z3
import binascii

jmp_tbl = "0C0000002400000008000000140000002000000024000000240000002400000024000000240000002400000024000000240000002400000024000000240000001800000024000000100000002400000024000000240000001C000000040000002400000000000000"
def res(a):
    idx = ord(a) - ord('a')
    val = jmp_tbl[4*idx:4*idx+2]
    return int(val, 16)

def jmp_idx(a):
    idx = a - ord('a')
    return idx
    

flag = []
for i in range(62 - 6):
    flag.append(z3.BitVec(f'flag_{i}', 8))

allowed = ['a', 'c', 'd', 'e', 'q', 's', 'w', 'x', 'z']

s = z3.Solver()
for c in flag:
    constr = []
    for a in allowed:
        constr.append(c == ord(a))
    s.add(z3.Or(*constr))

inp_str = "0000770000007300000000006400007700006400000000006100000065007700710061006500000000000000006100007A640000737771000000007700007378006400000000007A770000000000006478"

inp = []
idx = 0
for i in range(0, len(inp_str), 2):
    c = inp_str[i:i+2]
    c = int(c, 16)
    if c == 0:
        inp.append(flag[idx])
        idx += 1
    else:
        inp.append(z3.BitVecVal(c, 8))

def check(arr):
    for i in range(len(arr)):
        for j in range(i + 1, len(arr)):
            a = arr[i]
            b = arr[j]
            s.add(a != b)

def sub4(inp):
    for i in range(0, 81, 9):
        arr = inp[i:i+9]
        check(arr)

idx_tbl = "000102030A0C0D0E130405060F1819212A33070810111A22232B3409121B242D36373F480B14151C1D1E252E2716171F2028313A4243262F3038394041494A29323B3C3D444B4C4D2C353E4546474E4F50"

def sub2(inp):
    for i in range(0, 81, 9):
        arr = []
        for j in range(9):
            k = i + j
            idx = idx_tbl[2*k:2*k + 2]
            idx = int(idx, 16)
            arr.append(inp[idx])
        check(arr)

def sub3(inp):
    for i in range(9):
        arr = []
        for j in range(9):
            arr.append(inp[j*9 + i])
        check(arr)

sub2(inp)
sub3(inp)
sub4(inp)


print(s.check())
print(s.model())
print("".join([chr(s.model().eval(c).as_long()) for c in flag]))