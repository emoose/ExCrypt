#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tests.h"
#include "excrypt.h"

int test_sha(void)
{
  static const uint8_t expected[20] = {
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25,
    0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
  };

  EXCRYPT_SHA_STATE state;
  uint8_t output[20];
  int failures;

  ExCryptSha((const uint8_t*)"a", 1, (const uint8_t*)"b", 1, (const uint8_t*)"c", 1, output, sizeof(output));
  failures = expect_bytes("SHA-1 one-shot", output, expected, sizeof(output));

  ExCryptShaInit(&state);
  ExCryptShaUpdate(&state, (const uint8_t*)"a", 1);
  ExCryptShaUpdate(&state, (const uint8_t*)"bc", 2);
  ExCryptShaFinal(&state, output, sizeof(output));
  
  failures += expect_bytes("SHA-1 streaming", output, expected, sizeof(output));
  return failures;
}
