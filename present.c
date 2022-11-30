#include "sis_present.h"
#include "xil_io.h"
#include "xparameters.h"

#define BASE_ADDR 0x44a00000

#define STATUS_REG SIS_PRESENT_S_AXI_SLV_REG0_OFFSET
#define CONFIG_REG SIS_PRESENT_S_AXI_SLV_REG1_OFFSET

#define PLAINTEXT0 SIS_PRESENT_S_AXI_SLV_REG2_OFFSET
#define PLAINTEXT1 SIS_PRESENT_S_AXI_SLV_REG3_OFFSET

#define KEY0 SIS_PRESENT_S_AXI_SLV_REG4_OFFSET
#define KEY1 SIS_PRESENT_S_AXI_SLV_REG5_OFFSET
#define KEY2 SIS_PRESENT_S_AXI_SLV_REG6_OFFSET

#define CIPHER_TEXT0 SIS_PRESENT_S_AXI_SLV_REG7_OFFSET
#define CIPHER_TEXT1 SIS_PRESENT_S_AXI_SLV_REG8_OFFSET

#define read_reg(offset) SIS_PRESENT_mReadReg(BASE_ADDR, offset)
#define write_reg(offset, data) SIS_PRESENT_mWriteReg(BASE_ADDR, offset, data)

//P permutation: P[i] = 16 * i mod 63 with i != 63, P[63] = 63 otherwise
int8_t P[] = {0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
                    4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
                    8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                    12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63};
uint8_t Sbox[] = {0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2};


void get_subkeys(uint64_t *key, uint64_t *subkeys) {
    uint64_t high = key[0];
    uint16_t low = key[1];
    subkeys[0] = high;
    for(int roundkey = 1; roundkey < 32; roundkey++) {
    	// rotate the first 61 bit of high-low key to the right
        uint64_t tmp1 = high;
        high = high << 61 | ((uint64_t)low << 45) | (high >> 19);
        low = (tmp1 >> 3) & 0xffff;
        // Sbox the 4 most significant bit
        high = (high & 0x0fffffffffffffffLL) | ((uint64_t) Sbox[high >> 60] << 60);
        //xor the bit 15-19 with the current round key
        high = high ^ (roundkey >> 1);
        low = low ^ ((roundkey & 1) << 15);
        subkeys[roundkey] = high;
    }
}

uint64_t present_encrypt(uint64_t *text, uint64_t *key) {
    uint64_t subkeys[32];
    get_subkeys(key, subkeys);   //generate subkeys
    uint64_t result = text[0];
    for(int roundkey = 0; roundkey < 31; roundkey++) {
    	// add round key aka xor current value with the subkeys[roundkey]
        result = result ^ subkeys[roundkey];
        // Sboxlayer map each 4-bit chunk accordingly to Sbox map
        uint8_t chunk = (uint8_t) &result;
        for(int i = 0; i < 8; i++) chunk[i] = (Sbox[chunk[i] >> 4] << 4) | Sbox[chunk[i] & 0xf];
        uint64_t permute = 0;
        // permutation each bit of result by the P permutation
        for(int i = 0; i < 64; i++) permute |= (result >> (63 - i) & 1) << (63 - P[i]);
        result = permute;
    }
    return result ^ subkeys[31];
}

int main(void)
{

	//xil_printf("------Hello present--------\n");

	while(!read_reg(CONFIG_REG)) {} // waiting CPU for enable encryption
	// when config reg is set to 1, set status register to busy
	write_reg(STATUS_REG, 1);
	//key array of 2 u64 value  represented as low bit and high bit which stored in key register in order from highest bit to lowest
	u64 key[2] = {(read_reg(KEY0) << 32) | read_reg(KEY1), read_reg(KEY2)};
	// 64 bit plain text store in 2 PLAIN_TEXT register as the lowest and highest part 
	u64 text[1] = {(read_reg(PLAIN_TEXT0) << 32) | read_reg(PLAIN_TEXT1) };
	u64 encrypted = present_encrypt(text, key);
	//xil_printf("Result is %08llx",  encrypted >> 32);
	//xil_printf("%08llx", encrypted & 0xffffffff);
	// write to the output register the encryption text
	write_reg(CIPHER_TEXT0, encrypted >> 32);         // 32 first bit
	write_reg(CIPHER_TEXT1, encrypted & 0xffffffff);  // 32 last bit
	//notify the CPU for the encrypted text
	write_reg(STATUS_REG, 0);
	return 0;
}
