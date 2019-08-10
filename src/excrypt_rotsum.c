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
