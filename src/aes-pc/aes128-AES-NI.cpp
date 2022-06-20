#include <stdio.h>
#include <stdint.h>
#include <immintrin.h>
#include <chrono>


/* AES Constants */
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

inline uint32_t word(uint8_t a0, uint8_t a1, uint8_t a2, uint8_t a3) {
    return a0 | (uint32_t) a1 << 8 | (uint32_t) a2 << 16 | (uint32_t) a3 << 24;
}

inline uint8_t wbyte(uint32_t w, int pos) {
    return (w >> (pos * 8)) & 0xff;
}


/**
 * Key expansion
 * */
inline __m128i getNextRoundKey(__m128i key_reg, const int round) {
    __m128i keygen_res = _mm_aeskeygenassist_si128(key_reg, rCon[round]);
    __m128i tmp1 = _mm_shuffle_epi32(keygen_res, 0b11111111);
    //copy previous key
    __m128i key_reg_tmp = key_reg;
    //shift previous key by 1 word
    key_reg_tmp = _mm_slli_si128(key_reg_tmp, 4);
    //xor prev with shifted prev
    key_reg = _mm_xor_si128(key_reg, key_reg_tmp);
    //copy xor key
    key_reg_tmp = key_reg;
    //shift by 2 words
    key_reg_tmp = _mm_slli_si128(key_reg_tmp, 8);
    //xor
    key_reg_tmp = _mm_xor_si128(key_reg, key_reg_tmp);

    //produce final round key
    key_reg = _mm_xor_si128(tmp1, key_reg_tmp);
    return key_reg;
}

void aes(uint8_t *in, uint8_t *out, uint8_t *key) {
    t_state state;

    //init state from PT (in)
    for (int i = 0; i < 4; i++) {
        state[i] = word(in[4 * i], in[4 * i + 1], in[4 * i + 2], in[4 * i + 3]);
    }


    __m128i state_reg = _mm_loadu_si128((__m128i const *) state);
    __m128i key_reg = _mm_loadu_si128((__m128i const *) key);

    //add first round key
    state_reg = _mm_xor_si128(state_reg, key_reg);

    //round 1 - 9
    for (int i = 1; i <= 9; i++) {
        //compute round key
        key_reg = getNextRoundKey(key_reg, i);
        //encrypt round
        state_reg = _mm_aesenc_si128(state_reg, key_reg);
    }

    //round 10
    //compute final round key
    key_reg = getNextRoundKey(key_reg, 10);
    state_reg = _mm_aesenclast_si128(state_reg, key_reg);

    //save back to t_state
    _mm_storeu_si128((__m128i *) state, state_reg);

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

    int test_failed = 0;

    uint8_t key[16] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    uint8_t in[16] = {0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
    uint8_t out[16] = {0, /*...*/ };
    uint8_t res_out[16] = {0xa3, 0x3a, 0xca, 0x68, 0x72, 0xa2, 0x27, 0x74, 0xbf, 0x99, 0xf3, 0x71, 0xaa, 0x99, 0xd2, 0x5a};

    int rounds = 1000000;
    if (argc > 1) {
        rounds = atoi(argv[1]);
    }
    printf("Running AES128-AES-NI %d times.\n", rounds);

    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < rounds; i++) {
        aes(in, in, key);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
    printf("Duration: %ld milliseconds.\n\n", duration.count());

    return in[0];

}
