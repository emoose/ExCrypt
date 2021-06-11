#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <algorithm>
#include <memory>

#include "excrypt.h"

uint64_t kPkcs1Format0_0 = 0xE03021A05000414;
uint64_t kPkcs1Format0_1 = 0x3021300906052B;

uint64_t kPkcs1Format1_0 = 0x052B0E03021A0414;
uint32_t kPkcs1Format1_1 = 0x1F300706;
uint16_t kPkcs1Format1_2 = 0x30;

extern "C" {

void ExCryptBnDwLePkcs1Format(const uint8_t* hash, uint32_t format, uint8_t* output_sig, uint32_t output_sig_size)
{
  std::memset(output_sig, 0xFF, output_sig_size);

  if (output_sig_size - 39 > 473)
    return;

  output_sig[output_sig_size - 1] = 0;
  output_sig[output_sig_size - 2] = 1;

  // Copy reversed-hash into signature
  std::reverse_copy(hash, hash + 0x14, output_sig);

  // Append different bytes depending on format
  switch (format)
  {
  case 0:
    *(uint64_t*)(output_sig + 0x14) = kPkcs1Format0_0;
    *(uint64_t*)(output_sig + 0x1C) = kPkcs1Format0_1;
    break;
  case 1:
    *(uint64_t*)(output_sig + 0x14) = kPkcs1Format1_0;
    *(uint32_t*)(output_sig + 0x1C) = kPkcs1Format1_1;
    *(uint16_t*)(output_sig + 0x20) = kPkcs1Format1_2;
    break;
  case 2:
    output_sig[0x14] = 0;
  }
}

BOOL ExCryptBnDwLePkcs1Verify(const uint8_t* hash, const uint8_t* input_sig, uint32_t input_sig_size)
{
  if (input_sig_size - 39 > 473)
    return false;

  // format = 0 if 0x16 == 0
  // format = 1 if 0x16 == 0x1A
  // format = 2 if 0x16 != 0x1A
  uint32_t format = 0;
  if (input_sig[0x16] != 0)
    format = (input_sig[0x16] != 0x1A) ? 2 : 1;

  auto test_sig = std::make_unique<uint8_t[]>(input_sig_size);
  ExCryptBnDwLePkcs1Format(hash, format, test_sig.get(), input_sig_size);

  return std::memcmp(test_sig.get(), input_sig, input_sig_size) == 0;
}

};
