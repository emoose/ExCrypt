#include <algorithm>

#include "excrypt.h"

int32_t ExCryptMemDiff(uint8_t* buf1, uint8_t* buf2, uint32_t size)
{
  uint8_t difference = 0;
  if (!size)
    return difference;

  do
  {
    difference |= *buf2++ ^ *buf1++;
    size--;
  } while (size > 0);

  return difference;
}

void ExCryptMemReverseBytes(uint8_t* data, uint32_t length)
{
  std::reverse(data, data + length);
}
