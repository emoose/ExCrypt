#include <stdlib.h>
#include <string.h>

#include "excrypt.h"

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

// SHA1 code based on https://github.com/mohaps/TinySHA1

void sha1_process_block(EXCRYPT_SHA_STATE* state)
{
  uint32_t w[80];
  for (size_t i = 0; i < 16; i++) {
    w[i] = (state->buffer[i * 4 + 0] << 24);
    w[i] |= (state->buffer[i * 4 + 1] << 16);
    w[i] |= (state->buffer[i * 4 + 2] << 8);
    w[i] |= (state->buffer[i * 4 + 3]);
  }
  for (size_t i = 16; i < 80; i++) {
    w[i] = ROTL32((w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]), 1);
  }

  uint32_t a = state->state[0];
  uint32_t b = state->state[1];
  uint32_t c = state->state[2];
  uint32_t d = state->state[3];
  uint32_t e = state->state[4];

  for (int i = 0; i < 80; ++i) {
    uint32_t f = 0;
    uint32_t k = 0;

    if (i < 20) {
      f = (b & c) | (~b & d);
      k = 0x5A827999;
    }
    else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1;
    }
    else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDC;
    }
    else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6;
    }
    uint32_t temp = ROTL32(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = ROTL32(b, 30);
    b = a;
    a = temp;
  }

  state->state[0] += a;
  state->state[1] += b;
  state->state[2] += c;
  state->state[3] += d;
  state->state[4] += e;
}

void sha1_process_byte(EXCRYPT_SHA_STATE* state, uint8_t octet)
{
  uint32_t offset = state->count++ & 0x3F;
  state->buffer[offset] = octet;
  if ((state->count & 0x3F) == 0)
  {
    sha1_process_block(state);
  }
}

void ExCryptShaInit(EXCRYPT_SHA_STATE* state)
{
  state->count = 0;
  state->state[0] = 0x67452301;
  state->state[1] = 0xEFCDAB89;
  state->state[2] = 0x98BADCFE;
  state->state[3] = 0x10325476;
  state->state[4] = 0xC3D2E1F0;
}

void ExCryptShaUpdate(EXCRYPT_SHA_STATE* state, const uint8_t* input, uint32_t input_size)
{
  for (uint32_t i = 0; i < input_size; i++)
  {
    sha1_process_byte(state, input[i]);
  }
}

void ExCryptShaFinal(EXCRYPT_SHA_STATE* state, uint8_t* output, uint32_t output_size)
{
  uint64_t bit_count = (uint64_t)state->count * 8;

  sha1_process_byte(state, 0x80);

  if ((state->count & 0x3F) > 56)
  {
    while ((state->count & 0x3F) != 0)
    {
      sha1_process_byte(state, 0);
    }
    while ((state->count & 0x3F) < 56)
    {
      sha1_process_byte(state, 0);
    }
  }
  else
  {
    while ((state->count & 0x3F) < 56)
    {
      sha1_process_byte(state, 0);
    }
  }

  sha1_process_byte(state, 0);
  sha1_process_byte(state, 0);
  sha1_process_byte(state, 0);
  sha1_process_byte(state, 0);

  sha1_process_byte(state, (uint8_t)((bit_count >> 24) & 0xFF));
  sha1_process_byte(state, (uint8_t)((bit_count >> 16) & 0xFF));
  sha1_process_byte(state, (uint8_t)((bit_count >> 8) & 0xFF));
  sha1_process_byte(state, (uint8_t)((bit_count) & 0xFF));

  //sha1_process_block(state);
  uint32_t result[5];
  result[0] = _byteswap_ulong(state->state[0]);
  result[1] = _byteswap_ulong(state->state[1]);
  result[2] = _byteswap_ulong(state->state[2]);
  result[3] = _byteswap_ulong(state->state[3]);
  result[4] = _byteswap_ulong(state->state[4]);
  memcpy(output, result, min(output_size, 0x14));
}

void ExCryptSha(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size)
{
  EXCRYPT_SHA_STATE state[1];
  ExCryptShaInit(state);

  if (input1 && input1_size)
  {
    ExCryptShaUpdate(state, input1, input1_size);
  }
  if (input2 && input2_size)
  {
    ExCryptShaUpdate(state, input2, input2_size);
  }
  if (input3 && input3_size)
  {
    ExCryptShaUpdate(state, input3, input3_size);
  }

  ExCryptShaFinal(state, output, output_size);
}

void ExCryptHmacShaInit(EXCRYPT_HMACSHA_STATE* state, const uint8_t* key, uint32_t key_size)
{
  ExCryptShaInit(&state->ShaState[0]);
  ExCryptShaInit(&state->ShaState[1]);

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

  ExCryptShaUpdate(&state->ShaState[0], (const uint8_t*)buf1, 0x40);
  ExCryptShaUpdate(&state->ShaState[1], (const uint8_t*)buf2, 0x40);
}

void ExCryptHmacShaUpdate(EXCRYPT_HMACSHA_STATE* state, const uint8_t* input, uint32_t input_size)
{
  ExCryptShaUpdate(&state->ShaState[0], input, input_size);
}

void ExCryptHmacShaFinal(EXCRYPT_HMACSHA_STATE* state, uint8_t* output, uint32_t output_size)
{
  uint8_t hash[0x14];
  ExCryptShaFinal(&state->ShaState[0], hash, 0x14);

  // updates second SHA1 state with result from first SHA1
  ExCryptShaUpdate(&state->ShaState[1], hash, 0x14);

  ExCryptShaFinal(&state->ShaState[1], output, output_size);
}

void ExCryptHmacSha(const uint8_t* key, uint32_t key_size, const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size)
{
  EXCRYPT_HMACSHA_STATE hmacsha;
  ExCryptHmacShaInit(&hmacsha, key, key_size);

  if (input1)
  {
    ExCryptHmacShaUpdate(&hmacsha, input1, input1_size);
  }
  if (input2)
  {
    ExCryptHmacShaUpdate(&hmacsha, input2, input2_size);
  }
  if (input3)
  {
    ExCryptHmacShaUpdate(&hmacsha, input3, input3_size);
  }

  ExCryptHmacShaFinal(&hmacsha, output, output_size);
}

uint8_t ExCryptHmacShaVerify(const uint8_t* key, uint32_t key_size, const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, const uint8_t* compare_buf, uint32_t compare_buf_size)
{
  uint8_t output[0x14];
  ExCryptHmacSha(key, key_size, input1, input1_size, input2, input2_size, input3, input3_size, output, 0x14);

  return compare_buf_size <= 0x14 && !memcmp(output, compare_buf, compare_buf_size);
}
