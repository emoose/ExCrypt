#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tests.h"
#include "excrypt.h"

int test_rc4(void)
{
  static const uint8_t key[] = "Key";
  static const uint8_t plaintext[] = "Plaintext";
  static const uint8_t expected[] = { 0xbb, 0xf3, 0x16, 0xe8, 0xd9, 0x40, 0xaf, 0x0a, 0xd3 };
  
  uint8_t output[sizeof(plaintext) - 1];

  EXCRYPT_RC4_STATE state;
  int failures = 0;

  memcpy(output, plaintext, sizeof(output));
  ExCryptRc4(key, sizeof(key) - 1, output, sizeof(output));
  
  failures += expect_bytes("RC4 one-shot", output, expected, sizeof(output));

  memcpy(output, plaintext, sizeof(output));
  ExCryptRc4Key(&state, key, sizeof(key) - 1);
  ExCryptRc4Ecb(&state, output, 4);
  ExCryptRc4Ecb(&state, output + 4, sizeof(output) - 4);

  failures += expect_bytes("RC4 streaming", output, expected, sizeof(output));

  return failures;
}