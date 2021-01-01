#include <string.h>
#include <stdlib.h>

#include "excrypt.h"

#include "fp61.hpp" // CAT_MUL128

// Unfortunately this seems to be a XeCrypt custom function, OpenSSL etc doesn't seem to include it, so we have to implement it ourselves :/
// Many thanks to Just1n for posting a C# impl. of it at https://www.se7ensins.com/forums/threads/c-verify-rsa-signature.173155

void ExCryptBnQwNeModMul(const uint64_t* input_A, const uint64_t* input_B, uint64_t* output_C, uint64_t inverse, const uint64_t* modulus, uint32_t modulus_size)
{
  uint8_t buffer[0x210];
  memset(buffer, 0, 0x210);

  uint64_t r10 = inverse * input_A[0];
  uint64_t r11 = 0;
  uint64_t r12 = 0;
  uint64_t r14 = 0;
  uint64_t r15 = 0;
  uint64_t r16 = 0;
  uint64_t r17 = 0;
  uint64_t r18 = 0;
  uint64_t r19 = 0;
  uint64_t r20 = 0;

  uint64_t throwaway = 0;

  int index = 8; // "0x58" ??

  for (uint32_t a = 0; a < modulus_size; a++)
  {
    // reset index
    index = 8;
    r11 = input_B[a];
    r12 = r10 * r11;
    r16 = *(uint64_t*)(buffer + index);
    r17 = *(uint64_t*)(buffer + index + 0x108);
    r16 = r16 - r17;
    r16 = r16 * inverse;
    r12 = r12 + r16;

    r14 = 0;
    r15 = 0;

    for (uint32_t b = 0; b < modulus_size; b++)
    {
      r16 = input_A[b];
      CAT_MUL128(r17, throwaway, r11, r16);
      r18 = r11 * r16;
      r16 = *(uint64_t*)(buffer + index);
      r18 = r18 + r16;
      if (r18 < r16)
        r17++;

      r18 = r18 + r14;
      if (r18 < r14)
        r17++;

      r14 = r17;
      *(uint64_t*)(buffer + index - 8) = r18;
      r16 = modulus[b];
      CAT_MUL128(r17, throwaway, r12, r16);
      r18 = r12 * r16;
      r16 = *(uint64_t*)(buffer + index + 0x108);
      r18 = r18 + r16;
      if (r18 < r16)
        r17 = r17 + 0x01;

      r18 = r18 + r15;
      if (r18 < r15)
        r17 = r17 + 0x01;

      r15 = r17;
      *(uint64_t*)(buffer + index + 0x100) = r18;
      index += 8;
    }

    *(uint64_t*)(buffer + index - 8) = r14;
    *(uint64_t*)(buffer + index + 0x100) = r15;
  }

  r14 = 0;
  r15 = 0;

  // Loop that updates r16 & r17 for later use..
  uint64_t big_modulus_size = modulus_size;
  index = ROTL64(big_modulus_size, 3) & 0xFFFFFFFFFFFFFFF8;
  for (uint32_t c = 0; c < modulus_size; c++)
  {
    r16 = *(uint64_t*)(buffer + index);
    r17 = *(uint64_t*)(buffer + index + 0x108);
    if (r16 != r17)
      break;

    index -= 8;
  }

  index = 8;

  if (r16 > r17)
  {
    for (uint32_t c = 0; c < modulus_size; c++)
    {
      r16 = *(uint64_t*)(buffer + index);
      r17 = *(uint64_t*)(buffer + index + 0x108);
      r18 = r16 - r17;
      r18 = r18 - r14;
      output_C[c] = r18;

      r17 = r17 ^ r16;
      r18 = r18 ^ r16;
      r18 = r18 | r17;
      r16 = r16 ^ r18;
      r14 = ((r16 >> 63) & 1);

      index += 8;
    }
  }
  else
  {
    for (uint32_t c = 0; c < modulus_size; c++)
    {
      r16 = *(uint64_t*)(buffer + index);
      r17 = *(uint64_t*)(buffer + index + 0x108);
      r18 = modulus[c];
      r19 = r16 + r18;
      r19 = r19 + r14;
      r20 = r19 - r17;
      r20 = r20 - r15;
      output_C[c] = r20;

      r18 = r18 ^ r19;
      r16 = r16 ^ r19;
      r16 = r16 | r18;
      r16 = r16 ^ r19;
      r14 = ((r16 >> 63) & 1);
      r20 = r20 ^ r19;
      r17 = r17 ^ r19;
      r17 = r17 | r20;
      r17 = r17 ^ r19;
      r15 = ((r17 >> 63) & 1);

      index += 8;
    }
  }
}

uint64_t ExCryptBnQwNeModInv(uint64_t input)
{
  // Compute the 2-adic of qw such that: val = -1 + input^2
  uint64_t val = (input * 3) ^ 2;
  input = 1 - (val * input);

  // Raise it to another 32 such that: val = -1 + input^64
  for (uint32_t i = 5; i < 32; i <<= 1)
  {
    val = val * (input + 1);
    input = input * input;
  }

  // Done
  val = val * (input + 1);
  return val;
}
