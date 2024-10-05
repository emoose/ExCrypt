#include <stdlib.h>

#include "excrypt.h"

void ExCryptRotSum(EXCRYPT_ROTSUM_STATE* result, const uint64_t* input, uint32_t input_qwords)
{
  result->data[0] = _byteswap_uint64(result->data[0]);
  result->data[1] = _byteswap_uint64(result->data[1]);
  result->data[2] = _byteswap_uint64(result->data[2]);
  result->data[3] = _byteswap_uint64(result->data[3]);

  for (uint32_t i = 0; i < input_qwords; i++)
  {
    uint64_t data = _byteswap_uint64(*input);
    input++;

    result->data[1] += data;
    result->data[3] -= data;

    if (result->data[1] < data) {
      result->data[0]++; // adding must have overflowed, increment counter
    }
    if (result->data[3] > data) {
      result->data[2]--; // subtracting must have underflowed, decrement counter
    }

    result->data[1] = ROTL64(result->data[1], 29);
    result->data[3] = ROTL64(result->data[3], 31);
  }

  result->data[0] = _byteswap_uint64(result->data[0]);
  result->data[1] = _byteswap_uint64(result->data[1]);
  result->data[2] = _byteswap_uint64(result->data[2]);
  result->data[3] = _byteswap_uint64(result->data[3]);
}

void ExCryptRotSum4(EXCRYPT_ROTSUM4_STATE* result, uint32_t* input, uint32_t input_dwords)
{
  result->data[0] = _byteswap_uint64(result->data[0]);
  result->data[1] = _byteswap_uint64(result->data[1]);

  for (uint32_t i = 0; i < input_dwords; i++)
  {
    uint32_t data = _byteswap_ulong(*input);
    input++;

    result->data[0] += data;
    result->data[1] -= data;

    result->data[0] = ROTL64(result->data[0], 29);
    result->data[1] = ROTL64(result->data[1], 31);
  }

  result->data[0] = _byteswap_uint64(result->data[0]);
  result->data[1] = _byteswap_uint64(result->data[1]);
}

void ExCryptRotSumSha(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  uint8_t* output, uint32_t output_size)
{
  EXCRYPT_ROTSUM_STATE rotsum;
  memset(&rotsum, 0, sizeof(EXCRYPT_ROTSUM_STATE));

  ExCryptRotSum(&rotsum, (const uint64_t*)input1, input1_size / 8);
  ExCryptRotSum(&rotsum, (const uint64_t*)input2, input2_size / 8);

  EXCRYPT_SHA_STATE sha;
  ExCryptShaInit(&sha);

  ExCryptShaUpdate(&sha, (const uint8_t*)&rotsum, sizeof(EXCRYPT_ROTSUM_STATE));
  ExCryptShaUpdate(&sha, (const uint8_t*)&rotsum, sizeof(EXCRYPT_ROTSUM_STATE));

  ExCryptShaUpdate(&sha, input1, input1_size);
  ExCryptShaUpdate(&sha, input2, input2_size);

  rotsum.data[0] = ~rotsum.data[0];
  rotsum.data[1] = ~rotsum.data[1];
  rotsum.data[2] = ~rotsum.data[2];
  rotsum.data[3] = ~rotsum.data[3];

  ExCryptShaUpdate(&sha, (const uint8_t*)&rotsum, sizeof(EXCRYPT_ROTSUM_STATE));
  ExCryptShaUpdate(&sha, (const uint8_t*)&rotsum, sizeof(EXCRYPT_ROTSUM_STATE));

  ExCryptShaFinal(&sha, output, output_size);
}
