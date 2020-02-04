#include <string.h>
#include <stdlib.h>

#include "excrypt.h"

void ExCryptBn_BeToLeKey(EXCRYPT_RSA* key, const uint8_t* input, uint32_t input_size)
{
  key->num_digits = _byteswap_ulong(*(uint32_t*)input);
  input += 4;

  int input_size_mul = key->num_digits / 0x10;

  key->pub_exponent = _byteswap_ulong(*(uint32_t*)input);
  input += 4;

  key->reserved = _byteswap_uint64(*(uint64_t*)input);
  input += 8;

  if (input_size <= 0x10)
    return;

  EXCRYPT_RSAPUB_1024* key_pub = (EXCRYPT_RSAPUB_1024*)key;
  ExCryptBnQw_SwapDwQwLeBe((uint64_t*)input, key_pub->modulus, key->num_digits);

  int modulus_size = input_size_mul * 0x80;
  input += modulus_size;

  if (input_size <= (modulus_size + 0x10))
    return;

  auto* key_prv = ((uint8_t*)key_pub) + 0x10 + modulus_size;
  int prv_size = input_size_mul * 0x40;

  // P
  ExCryptBnQw_SwapDwQwLeBe((uint64_t*)input, (uint64_t*)key_prv, prv_size / 8);
  input += prv_size;
  key_prv += prv_size;

  // Q
  ExCryptBnQw_SwapDwQwLeBe((uint64_t*)input, (uint64_t*)key_prv, prv_size / 8);
  input += prv_size;
  key_prv += prv_size;

  // DP
  ExCryptBnQw_SwapDwQwLeBe((uint64_t*)input, (uint64_t*)key_prv, prv_size / 8);
  input += prv_size;
  key_prv += prv_size;

  // DQ
  ExCryptBnQw_SwapDwQwLeBe((uint64_t*)input, (uint64_t*)key_prv, prv_size / 8);
  input += prv_size;
  key_prv += prv_size;

  // CR
  ExCryptBnQw_SwapDwQwLeBe((uint64_t*)input, (uint64_t*)key_prv, prv_size / 8);
  input += prv_size;
  key_prv += prv_size;
}
