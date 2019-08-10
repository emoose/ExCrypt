#include <stdlib.h>
#include <string.h>

#include "excrypt.h"

// MD5 code based on Brad Conte's md5.c

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x ^ y ^ z)
#define I(x,y,z) (y ^ (x | ~z))

#define FF(a,b,c,d,m,s,t) { a += F(b,c,d) + m + t; \
                            a = b + ROTL32(a,s); }
#define GG(a,b,c,d,m,s,t) { a += G(b,c,d) + m + t; \
                            a = b + ROTL32(a,s); }
#define HH(a,b,c,d,m,s,t) { a += H(b,c,d) + m + t; \
                            a = b + ROTL32(a,s); }
#define II(a,b,c,d,m,s,t) { a += I(b,c,d) + m + t; \
                            a = b + ROTL32(a,s); }

void md5_process_block(EXCRYPT_MD5_STATE* state)
{
  uint32_t a, b, c, d, m[16], i, j;

  // MD5 specifies big endian byte order, but this implementation assumes a little
  // endian byte order CPU. Reverse all the bytes upon input, and re-reverse them
  // on output (in md5_final()).
  for (i = 0, j = 0; i < 16; ++i, j += 4)
    m[i] = (state->buffer[j]) + (state->buffer[j + 1] << 8) + (state->buffer[j + 2] << 16) + (state->buffer[j + 3] << 24);

  a = state->state[0];
  b = state->state[1];
  c = state->state[2];
  d = state->state[3];

  FF(a, b, c, d, m[0], 7, 0xd76aa478);
  FF(d, a, b, c, m[1], 12, 0xe8c7b756);
  FF(c, d, a, b, m[2], 17, 0x242070db);
  FF(b, c, d, a, m[3], 22, 0xc1bdceee);
  FF(a, b, c, d, m[4], 7, 0xf57c0faf);
  FF(d, a, b, c, m[5], 12, 0x4787c62a);
  FF(c, d, a, b, m[6], 17, 0xa8304613);
  FF(b, c, d, a, m[7], 22, 0xfd469501);
  FF(a, b, c, d, m[8], 7, 0x698098d8);
  FF(d, a, b, c, m[9], 12, 0x8b44f7af);
  FF(c, d, a, b, m[10], 17, 0xffff5bb1);
  FF(b, c, d, a, m[11], 22, 0x895cd7be);
  FF(a, b, c, d, m[12], 7, 0x6b901122);
  FF(d, a, b, c, m[13], 12, 0xfd987193);
  FF(c, d, a, b, m[14], 17, 0xa679438e);
  FF(b, c, d, a, m[15], 22, 0x49b40821);

  GG(a, b, c, d, m[1], 5, 0xf61e2562);
  GG(d, a, b, c, m[6], 9, 0xc040b340);
  GG(c, d, a, b, m[11], 14, 0x265e5a51);
  GG(b, c, d, a, m[0], 20, 0xe9b6c7aa);
  GG(a, b, c, d, m[5], 5, 0xd62f105d);
  GG(d, a, b, c, m[10], 9, 0x02441453);
  GG(c, d, a, b, m[15], 14, 0xd8a1e681);
  GG(b, c, d, a, m[4], 20, 0xe7d3fbc8);
  GG(a, b, c, d, m[9], 5, 0x21e1cde6);
  GG(d, a, b, c, m[14], 9, 0xc33707d6);
  GG(c, d, a, b, m[3], 14, 0xf4d50d87);
  GG(b, c, d, a, m[8], 20, 0x455a14ed);
  GG(a, b, c, d, m[13], 5, 0xa9e3e905);
  GG(d, a, b, c, m[2], 9, 0xfcefa3f8);
  GG(c, d, a, b, m[7], 14, 0x676f02d9);
  GG(b, c, d, a, m[12], 20, 0x8d2a4c8a);

  HH(a, b, c, d, m[5], 4, 0xfffa3942);
  HH(d, a, b, c, m[8], 11, 0x8771f681);
  HH(c, d, a, b, m[11], 16, 0x6d9d6122);
  HH(b, c, d, a, m[14], 23, 0xfde5380c);
  HH(a, b, c, d, m[1], 4, 0xa4beea44);
  HH(d, a, b, c, m[4], 11, 0x4bdecfa9);
  HH(c, d, a, b, m[7], 16, 0xf6bb4b60);
  HH(b, c, d, a, m[10], 23, 0xbebfbc70);
  HH(a, b, c, d, m[13], 4, 0x289b7ec6);
  HH(d, a, b, c, m[0], 11, 0xeaa127fa);
  HH(c, d, a, b, m[3], 16, 0xd4ef3085);
  HH(b, c, d, a, m[6], 23, 0x04881d05);
  HH(a, b, c, d, m[9], 4, 0xd9d4d039);
  HH(d, a, b, c, m[12], 11, 0xe6db99e5);
  HH(c, d, a, b, m[15], 16, 0x1fa27cf8);
  HH(b, c, d, a, m[2], 23, 0xc4ac5665);

  II(a, b, c, d, m[0], 6, 0xf4292244);
  II(d, a, b, c, m[7], 10, 0x432aff97);
  II(c, d, a, b, m[14], 15, 0xab9423a7);
  II(b, c, d, a, m[5], 21, 0xfc93a039);
  II(a, b, c, d, m[12], 6, 0x655b59c3);
  II(d, a, b, c, m[3], 10, 0x8f0ccc92);
  II(c, d, a, b, m[10], 15, 0xffeff47d);
  II(b, c, d, a, m[1], 21, 0x85845dd1);
  II(a, b, c, d, m[8], 6, 0x6fa87e4f);
  II(d, a, b, c, m[15], 10, 0xfe2ce6e0);
  II(c, d, a, b, m[6], 15, 0xa3014314);
  II(b, c, d, a, m[13], 21, 0x4e0811a1);
  II(a, b, c, d, m[4], 6, 0xf7537e82);
  II(d, a, b, c, m[11], 10, 0xbd3af235);
  II(c, d, a, b, m[2], 15, 0x2ad7d2bb);
  II(b, c, d, a, m[9], 21, 0xeb86d391);

  state->state[0] += a;
  state->state[1] += b;
  state->state[2] += c;
  state->state[3] += d;
}

void md5_process_byte(EXCRYPT_MD5_STATE* state, uint8_t octet)
{
  uint32_t offset = state->count++ & 0x3F;
  state->buffer[offset] = octet;
  if ((state->count & 0x3F) == 0)
  {
    md5_process_block(state);
  }
}

void ExCryptMd5Init(EXCRYPT_MD5_STATE* state)
{
  state->count = 0;
  state->state[0] = 0x67452301;
  state->state[1] = 0xEFCDAB89;
  state->state[2] = 0x98BADCFE;
  state->state[3] = 0x10325476;
}

void ExCryptMd5Update(EXCRYPT_MD5_STATE* state, const uint8_t* input, uint32_t input_size)
{
  for (uint32_t i = 0; i < input_size; i++)
  {
    md5_process_byte(state, input[i]);
  }
}

void ExCryptMd5Final(EXCRYPT_MD5_STATE* state, uint8_t* output, uint32_t output_size)
{
  uint64_t bit_count = (uint64_t)state->count * 8;

  md5_process_byte(state, 0x80);
  if ((state->count & 0x3F) < 56)
  {
    while ((state->count & 0x3F) < 56)
    {
      md5_process_byte(state, 0);
    }
  }
  else if ((state->count & 0x3F) >= 56)
  {
    while ((state->count & 0x3F) != 0)
    {
      md5_process_byte(state, 0);
    }
    md5_process_block(state);
    memset(state->buffer, 0, 56);
  }

  state->buffer[56] = (uint8_t)(bit_count & 0xFF);
  state->buffer[57] = (uint8_t)((bit_count >> 8) & 0xFF);
  state->buffer[58] = (uint8_t)((bit_count >> 16) & 0xFF);
  state->buffer[59] = (uint8_t)((bit_count >> 24) & 0xFF);
  state->buffer[60] = (uint8_t)((bit_count >> 32) & 0xFF);
  state->buffer[61] = (uint8_t)((bit_count >> 40) & 0xFF);
  state->buffer[62] = (uint8_t)((bit_count >> 48) & 0xFF);
  state->buffer[63] = (uint8_t)((bit_count >> 56) & 0xFF);

  md5_process_block(state);

  memcpy(output, state->state, output_size);
}

void ExCryptMd5(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size)
{
  EXCRYPT_MD5_STATE sha;
  ExCryptMd5Init(&sha);

  if (input1)
  {
    ExCryptMd5Update(&sha, input1, input1_size);
  }
  if (input2)
  {
    ExCryptMd5Update(&sha, input2, input2_size);
  }
  if (input3)
  {
    ExCryptMd5Update(&sha, input3, input3_size);
  }

  ExCryptMd5Final(&sha, output, output_size);
}

void ExCryptRotSumMd5(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  uint8_t* output, uint32_t output_size)
{
  EXCRYPT_ROTSUM_STATE rotsum;
  memset(&rotsum, 0, sizeof(EXCRYPT_ROTSUM_STATE));

  ExCryptRotSum(&rotsum, (const uint64_t*)input1, input1_size / 8);
  ExCryptRotSum(&rotsum, (const uint64_t*)input2, input2_size / 8);

  EXCRYPT_MD5_STATE sha;
  ExCryptMd5Init(&sha);

  ExCryptMd5Update(&sha, (const uint8_t*)& rotsum, sizeof(EXCRYPT_ROTSUM_STATE));
  ExCryptMd5Update(&sha, (const uint8_t*)& rotsum, sizeof(EXCRYPT_ROTSUM_STATE));

  ExCryptMd5Update(&sha, input1, input1_size);
  ExCryptMd5Update(&sha, input2, input2_size);

  rotsum.data[0] = ~rotsum.data[0];
  rotsum.data[1] = ~rotsum.data[1];
  rotsum.data[2] = ~rotsum.data[2];
  rotsum.data[3] = ~rotsum.data[3];

  ExCryptMd5Update(&sha, (const uint8_t*)& rotsum, sizeof(EXCRYPT_ROTSUM_STATE));
  ExCryptMd5Update(&sha, (const uint8_t*)& rotsum, sizeof(EXCRYPT_ROTSUM_STATE));

  ExCryptMd5Final(&sha, output, output_size);
}

void ExCryptHmacMd5Init(EXCRYPT_HMACMD5_STATE* state, const uint8_t* key, uint32_t key_size)
{
  ExCryptMd5Init(&state->Md5State[0]);
  ExCryptMd5Init(&state->Md5State[1]);

  if (key_size > 64)
  {
    key_size = 64;
  }

  uint32_t buf1[0x10];
  uint32_t buf2[0x10];
  memset(buf1, 0, 0x10 * 4);
  memset(buf2, 0, 0x10 * 4);

  memcpy(buf1, key, key_size);
  memcpy(buf2, key, key_size);

  for (int i = 0; i < 16; i++)
  {
    buf1[i] ^= 0x36363636;
    buf2[i] ^= 0x5C5C5C5C;
  }

  ExCryptMd5Update(&state->Md5State[0], (const uint8_t*)buf1, 0x40);
  ExCryptMd5Update(&state->Md5State[1], (const uint8_t*)buf2, 0x40);
}

void ExCryptHmacMd5Update(EXCRYPT_HMACMD5_STATE* state, const uint8_t* input, uint32_t input_size)
{
  ExCryptMd5Update(&state->Md5State[0], input, input_size);
}

void ExCryptHmacMd5Final(EXCRYPT_HMACMD5_STATE* state, uint8_t* output, uint32_t output_size)
{
  ExCryptMd5Final(&state->Md5State[0], 0, 0);

  // updates second SHA1 state with result from first SHA1
  ExCryptMd5Update(&state->Md5State[1], (const uint8_t*)state->Md5State[0].state, 0x14);

  ExCryptMd5Final(&state->Md5State[1], output, output_size);
}

void ExCryptHmacMd5(const uint8_t* key, uint32_t key_size, const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size)
{
  EXCRYPT_HMACMD5_STATE hmacsha;
  ExCryptHmacMd5Init(&hmacsha, key, key_size);

  if (input1)
  {
    ExCryptHmacMd5Update(&hmacsha, input1, input1_size);
  }
  if (input2)
  {
    ExCryptHmacMd5Update(&hmacsha, input2, input2_size);
  }
  if (input3)
  {
    ExCryptHmacMd5Update(&hmacsha, input3, input3_size);
  }

  ExCryptHmacMd5Final(&hmacsha, output, output_size);
}

uint8_t ExCryptHmacMd5Verify(const uint8_t* key, uint32_t key_size, const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, const uint8_t* compare_buf, uint32_t compare_buf_size)
{
  uint8_t output[0x14];
  ExCryptHmacMd5(key, key_size, input1, input1_size, input2, input2_size, input3, input3_size, output, 0x14);

  return compare_buf_size <= 0x14 && !memcmp(output, compare_buf, compare_buf_size);
}
