#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <chrono>

/* AES-128 simple implementation template and testing */


/* AES Constants */

// forward sbox
const uint8_t SBOX[256] = {
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const uint8_t rCon[12] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

/* AES state type */
typedef uint32_t t_state[4];

/* Helper functions */
void hexprint16(uint8_t *p) {
    for (int i = 0; i < 16; i++)
        printf("%02hhx ", p[i]);
    puts("");
}

void hexprintw(uint32_t w) {
    for (int i = 0; i < 32; i += 8)
        printf("%02hhx ", (w >> i) & 0xffU);
}

void hexprintws(uint32_t *p, int cnt) {
    for (int i = 0; i < cnt; i++)
        hexprintw(p[i]);
    puts("");
}

void printstate(t_state s) {
    hexprintw(s[0]);
    hexprintw(s[1]);
    hexprintw(s[2]);
    hexprintw(s[3]);
    puts("");
}

inline uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3) {
    return a0 | (uint32_t) a1 << 8 | (uint32_t) a2 << 16 | (uint32_t) a3 << 24;
}

inline uint8_t wbyte(uint32_t w, int pos) {
    return (w >> (pos * 8)) & 0xff;
}

// **************** AES  functions ****************
uint32_t subWord(uint32_t w) {
    return word(SBOX[wbyte(w, 0)], SBOX[wbyte(w, 1)], SBOX[wbyte(w, 2)], SBOX[wbyte(w, 3)]);
}

void subBytes(t_state s) {
    s[0] = subWord(s[0]);
    s[1] = subWord(s[1]);
    s[2] = subWord(s[2]);
    s[3] = subWord(s[3]);
}


void shiftRows(t_state s) {
    uint32_t one = word(wbyte(s[0], 0), wbyte(s[1], 1), wbyte(s[2], 2), wbyte(s[3], 3));
    uint32_t two = word(wbyte(s[1], 0), wbyte(s[2], 1), wbyte(s[3], 2), wbyte(s[0], 3));
    uint32_t three = word(wbyte(s[2], 0), wbyte(s[3], 1), wbyte(s[0], 2), wbyte(s[1], 3));
    uint32_t four = word(wbyte(s[3], 0), wbyte(s[0], 1), wbyte(s[1], 2), wbyte(s[2], 3));
    s[0] = one;
    s[1] = two;
    s[2] = three;
    s[3] = four;
}

uint8_t xtime(uint8_t a) {
    uint8_t mask = 1 << 7; //mask msb
    if (a & mask) {
        //if starts with 1
        a = a << 1;
        return (a ^ (0x1b));
    } else {
        return (a << 1);
    }
}

// not mandatory - mix a single column
uint32_t mixColumn(uint32_t c) {
    uint8_t zero, one, two, three;
    zero = wbyte(c, 0);
    one = wbyte(c, 1);
    two = wbyte(c, 2);
    three = wbyte(c, 3);

    uint8_t resB0, resB1, resB2, resB3;
    resB0 = xtime(zero) ^ (xtime(one) ^ one) ^ two ^ three;
    resB1 = zero ^ xtime(one) ^ (xtime(two) ^ two) ^ three;
    resB2 = zero ^ one ^ xtime(two) ^ (xtime(three) ^ three);
    resB3 = (xtime(zero) ^ zero) ^ one ^ two ^ xtime(three);

    return word(resB0, resB1, resB2, resB3);

}


void mixColumns(t_state s) {
    s[0] = mixColumn(s[0]);
    s[1] = mixColumn(s[1]);
    s[2] = mixColumn(s[2]);
    s[3] = mixColumn(s[3]);
}

uint32_t rotWord(uint32_t w) {
    return word(wbyte(w, 1), wbyte(w, 2), wbyte(w, 3), wbyte(w, 0));
}

/*
* Key expansion from 128bits (4*32b)
* to 11 round keys (11*4*32b)
* each round key is 4*32b
*/
void expandKey(uint8_t k[16], uint32_t ek[44]) {
    uint32_t tmp;
    //copy key to ek
    for (int i = 0; i < 4; i++) {
        ek[i] = word(k[4 * i], k[4 * i + 1], k[4 * i + 2], k[4 * i + 3]);
    }

    //i < (# words in a block) * # of rounds + 1
    for (int i = 4; i < (4 * (10 + 1)); i++) {
        tmp = ek[i - 1];
        if (i % 4 == 0) {
            tmp = subWord(rotWord(tmp)) ^ rCon[i / 4];
        }
        ek[i] = ek[i - 4] ^ tmp;
    }
}


/* Adding expanded round key (prepared before) */
void addRoundKey(t_state s, uint32_t ek[], short index) {
    s[0] ^= ek[index];
    s[1] ^= ek[index + 1];
    s[2] ^= ek[index + 2];
    s[3] ^= ek[index + 3];
}

void aes(uint8_t *in, uint8_t *out, uint32_t *expKey) {
    //... Initialize ...
    unsigned short round = 0;

    t_state state;

    //init state from PT (in)
    for (int i = 0; i < 4; i++) {
        state[i] = word(in[4 * i], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
    }


    addRoundKey(state, expKey, 0);


    //round 1 - 9
    for (int i = 1; i <= 9; i++) {
        subBytes(state);
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, expKey, i * 4);
    }

    //round 10
    subBytes(state);
    shiftRows(state);
    addRoundKey(state, expKey, 40);


    for (int i = 0; i < 16; i++) {
        if (i < 4) out[i] = wbyte(state[0], i % 4);
        else if (i < 8) out[i] = wbyte(state[1], i % 4);
        else if (i < 12) out[i] = wbyte(state[2], i % 4);
        else out[i] = wbyte(state[3], i % 4);
    }
}

//****************************
// MAIN function: AES testing
//****************************
int main(int argc, char *argv[]) {


    // test aes encryption

    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t in[16] = {0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
    uint8_t out[16] = {0, /*...*/ };
    uint8_t res_out[16] = {0xa3, 0x3a, 0xca, 0x68, 0x72, 0xa2, 0x27, 0x74, 0xbf, 0x99, 0xf3, 0x71, 0xaa, 0x99, 0xd2, 0x5a};


    uint32_t expKey[11 * 4];

    int rounds = 1000000;
    if (argc > 1) {
        rounds = atoi(argv[1]);
    }
    printf("Running AES128-simple %d times.\n", rounds);

    auto start = std::chrono::high_resolution_clock::now();
    expandKey(key, expKey);
    for (int i = 0; i < rounds; i++) {
        aes(in, in, expKey);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    printf("Duration: %ld milliseconds.\n\n", duration.count());

    return in[0];
}
