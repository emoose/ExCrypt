#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tests.h"

int expect_bytes(const char* name, const uint8_t* actual, const uint8_t* expected, size_t size)
{
  if (memcmp(actual, expected, size) == 0)
  {
    return 0;
  }

  fprintf(stderr, "%s failed\n", name);
  fprintf(stderr, "  actual:   ");

  for (size_t index = 0; index < size; index++)
  {
    fprintf(stderr, "%02x", actual[index]);
  }

  fprintf(stderr, "\n  expected: ");

  for (size_t index = 0; index < size; index++)
  {
    fprintf(stderr, "%02x", expected[index]);
  }

  fprintf(stderr, "\n");
  
  return 1;
}