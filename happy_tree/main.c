#include <stdio.h>
#include <stdint.h>

uint32_t lut_0[256];
uint32_t lut_1[256];
uint32_t lut_2[256];
uint32_t lut_3[256];

uint32_t old_check(uint32_t num) {
    for (int i = 0; i < 0x186a0; i++) {
        // uint32_t tmp1 = num << 13;
        // uint32_t tmp2 = num ^ tmp1;
        // uint32_t tmp3 = tmp2 >> 17;
        // uint32_t tmp4 = tmp2 ^ tmp3;
        // uint32_t tmp5 = tmp4 << 5;
        // num = tmp5 ^ tmp4;
        uint32_t tmp2 = num ^ (num << 13);
        num = tmp2 ^ (tmp2 << 5) ^ (tmp2 >> 17) ^ ((tmp2 >> 17) << 5);
    }
    return num;
}

uint32_t check(uint32_t tmp2) {
    // for (int i = 0; i < 0x186a0; i++) {
    //     // uint32_t tmp1 = num << 13;
    //     // uint32_t tmp2 = num ^ tmp1;
    //     // uint32_t tmp3 = tmp2 >> 17;
    //     // uint32_t tmp4 = tmp2 ^ tmp3;
    //     // uint32_t tmp5 = tmp4 << 5;
    //     // num = tmp5 ^ tmp4;
    //     uint32_t tmp2 = num ^ (num << 13);
    //     tmp2 = tmp2 ^ (tmp2 << 5) ^ (tmp2 >> 17) ^ ((tmp2 >> 17) << 5);
    // }
    return lut_0[tmp2 & 0xff] ^ (lut_1[(tmp2 >> 8) & 0xff]) ^ lut_2[(tmp2 >> 16) & 0xff] ^ lut_3[(tmp2 >> 24) & 0xff];
    return tmp2;
}

void build_lut(uint32_t* lut, uint32_t b) {
    uint32_t start = (0x1 << (b * 8));
    for (int i = 0; i < 256; i++) {
        lut[i] = old_check(start * i);
    }
}



int main(int argc, char* argv[]) {
    printf("Building luts...\n");
    build_lut(lut_0, 0);
    build_lut(lut_1, 1);
    build_lut(lut_2, 2);
    build_lut(lut_3, 3);
    printf("Running bruteforce...\n");
    printf("Test: 0x%x\n", check(0x67616c66));
    printf("test2: 0x%x, 0x%x, 0x%x, 0x%x\n", lut_0[0x66], lut_1[0x6c], lut_2[0x61], lut_3[0x67]);
    uint32_t all_consts[] = {2724054634, 11141174, 3327000602, 916260948, 4049325967, 1807620453, 426167697, 3569744893, 2957679387};
    uint32_t xor_consts [] = {0, 2863311530, 0, 2863311530, 0, 2863311530, 0, 2863311530, 0};

    for (int i = 0; i < 9; i++) {
        printf("Running for part %d\n", i);
        uint32_t c = all_consts[i];
        uint32_t xor = xor_consts[i];
        uint32_t num = 0;
        for (; num < 0xffffffff; num++) {
            if (check(num ^ xor) == c) break;
            if (num % 0x10000000 == 0) {
                printf("Progress: %08x/%08x\n", num, 0xffffffff);
            }
        }

        printf("Found result: 0x%x\n", num);
        long result = num;
        printf("as string: %s\n", &result);
    }


    return 0;
}