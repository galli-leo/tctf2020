from numpy import uint32

def check(flag):
    loc_7 = uint32(flag)
    vals = {}
    for i in range(0x186a0):
        tmp1 = uint32(loc_7 << 0xd) # 0x56582884
        tmp2 = uint32(tmp1 ^ loc_7) # 0x56586f00
        tmp3 = uint32(tmp2 >> 0x11) # 0x5657e20c
        tmp4 = uint32(tmp3 ^ tmp2) # 0x56586cf8
        tmp5 = uint32(tmp4 << 5) # 0x56583590
        tmp6 = uint32(tmp5 ^ tmp4) # 0x56586c58
        loc_7 = tmp6
        # if loc_7 in vals:
        #     print("repeated at: ", i, tmp1, tmp2, tmp3, tmp4, tmp5)
        #     print(vals[loc_7])
        # idx = i
        # vals[tmp1] = (idx, "tmp1")
        # vals[tmp2] = (idx, "tmp2")
        # vals[tmp3] = (idx, "tmp3")
        # vals[tmp4] = (idx, "tmp4")
        # vals[tmp5] = (idx, "tmp5")
        # vals[loc_7] = (idx, "loc_7")
    return loc_7

def check2(flag):
    loc_7 = flag
    vals = {}
    for i in range(0x186a0):
        tmp1 = loc_7 << 0xd # 0x56582884
        tmp2 = (tmp1 ^ loc_7) # 0x56586f00
        tmp3 = (tmp2 >> 0x11) # 0x5657e20c
        tmp4 = (tmp3 ^ tmp2) # 0x56586cf8
        tmp5 = (tmp4 << 5) # 0x56583590
        tmp6 = (tmp5 ^ tmp4) # 0x56586c58
        loc_7 = tmp6
        # if loc_7 in vals:
        #     print("repeated at: ", i, tmp1, tmp2, tmp3, tmp4, tmp5)
        #     print(vals[loc_7])
        # idx = i
        # vals[tmp1] = (idx, "tmp1")
        # vals[tmp2] = (idx, "tmp2")
        # vals[tmp3] = (idx, "tmp3")
        # vals[tmp4] = (idx, "tmp4")
        # vals[tmp5] = (idx, "tmp5")
        # vals[loc_7] = (idx, "loc_7")
    return loc_7