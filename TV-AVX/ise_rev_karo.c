#include <stdio.h>
#include <inttypes.h>
#include <immintrin.h>

const static uint8_t p_box[16] = {8, 5, 13, 16, 12, 14, 2, 7, 4, 10, 3, 1, 15, 6, 9, 11};

const static uint8_t x_box[16] = {7, 47, 3, 23, 31, 19, 5, 29, 13, 17, 43, 6, 37, 11, 41, 2};

const static uint8_t flag[32] = {0x64,0x4e,0x77,0x65,0x2c,0x60,0x64,0x7c,0x63,0x6a,0x45,0x71,0x7a,0x63,0x42,0x6e,0x75,0x5b,0x71,0x6a,0x78,0x7a,0x73,0x2d,0x3c,0x70,0x74,0x35,0x51,0x54,0x76,0x6c };

size_t get_input(uint8_t* buf, size_t size) {
	size_t i = 0;
	while (i < size) {
		uint8_t ch = getchar();
		if (ch == '\n' || ch == '\0') {
			break;
		}
		buf[i] = ch;
		i++;
	}
	return i;
}

// PKCS5 Padding
void pad(uint8_t* buf, size_t size, size_t padded_sz) {
	if (size > padded_sz) {
		printf("More bytes read than expected, exiting...\n");
		exit(1);
	}
	if (size == padded_sz) {
		return;
	}
	uint8_t pad = padded_sz - size;
	for (size_t j = size; j < padded_sz; j++) {
		buf[j] = pad;
	}
}

int check_login(const uint8_t* pw, size_t sz) {
	if (sz % 16) {
		printf("Input size not multiple of block length, exiting...\n");
		exit(1);
	}

	uint8_t* cipher = (uint8_t*)malloc(sz * sizeof(uint8_t));
	for (size_t i = 0; i < sz; i += 16) {
		__m128i ones = _mm_set_epi8(1, 1, 1, 1, 1, 1, 1, 1,
					    1, 1, 1, 1, 1, 1, 1, 1); 	
		__m128i mask = _mm_lddqu_si128((__m128i*)(p_box));
		__m128i xorer = _mm_lddqu_si128((__m128i*)(x_box));

		mask = _mm_sub_epi8(mask, ones);
		__m128i loaded = _mm_lddqu_si128((__m128i*)(pw + i));
		__m128i shuffled = _mm_shuffle_epi8(loaded, mask);
		shuffled = _mm_xor_si128(shuffled, xorer);	
		_mm_storeu_si128((__m128i*)(cipher + i), shuffled);
	}
	
	for (size_t i = 0; i < sz; i++) {
		if (cipher[i] != flag[i]) {
			free(cipher);
			return 0;
		}
	}
	free(cipher);
	return 1;
}

int main(int argc, char** argv) {
	printf("Welcome my homies\n");
	
	uint8_t pw[32];
	printf("Enter key:\n> ");
	size_t bytes_read = get_input(pw, 32);
	if (bytes_read < 1) {
		printf("Please enter a key.\n");
		exit(1);
	}
	pad(pw, bytes_read, 32);
	int status = check_login(pw, 32);
	if (status) {
		printf("Ahh yeah,this is the flag\n");
	} else {
		printf("He He boi you were wrong\n");
	}
}
