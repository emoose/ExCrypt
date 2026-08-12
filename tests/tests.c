#include "tests.h"
#include <stdio.h>

int main(void)
{
  int failures = test_aes() + test_sha() + test_rc4();
  if (failures != 0)
  {
    return 1;
  }

  printf("AES, SHA-1, and RC4 tests passed\n");
  return 0;
}