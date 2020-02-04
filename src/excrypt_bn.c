#include <string.h>
#include <stdlib.h>

#include "excrypt.h"

void ExCryptBnDw_Zero(uint32_t* data, uint32_t data_dwords)
{
  memset(data, 0, sizeof(uint32_t) * data_dwords);
}

void ExCryptBnDw_Copy(const uint32_t* source, uint32_t* dest, uint32_t num_dwords)
{
  if (source != dest)
    memcpy(dest, source, sizeof(uint32_t) * num_dwords);
}

// Endian-swaps DWORDs
void ExCryptBnDw_SwapLeBe(const uint32_t* source, uint32_t* dest, uint32_t num_dwords)
{
  for (uint32_t i = 0; i < num_dwords; i++)
  {
    *dest = _byteswap_ulong(*source);
    dest++;
    source++;
  }
}

void ExCryptBnQw_Zero(uint64_t* data, uint32_t num_qwords)
{
  memset(data, 0, sizeof(uint64_t) * num_qwords);
}

void ExCryptBnQw_Copy(const uint64_t* source, uint64_t* dest, uint32_t num_qwords)
{
  if (source != dest)
    memcpy(dest, source, sizeof(uint64_t) * num_qwords);
}

// Endian-swaps QWORDs - seems to swap the two DWORDs inside it seperately?
// Maybe XeCryptBnQw_SwapDwQw is used afterward
void ExCryptBnQw_SwapLeBe(const uint64_t* source, uint64_t* dest, uint32_t num_qwords)
{
  ExCryptBnDw_SwapLeBe((const uint32_t*)source, (uint32_t*)dest, num_qwords * 2);
}

// Swaps around the two DWORDs inside a QWORD
void ExCryptBnQw_SwapDwQw(const uint64_t* source, uint64_t* dest, uint32_t num_qwords)
{
  const uint32_t* source_dw = (const uint32_t*)source;
  uint32_t* dest_dw = (uint32_t*)dest;
  for (uint32_t i = 0; i < num_qwords; i++)
  {
    uint32_t first = source_dw[0];
    uint32_t second = source_dw[1];
    dest_dw[0] = second;
    dest_dw[1] = first;
    source_dw += 2;
    dest_dw += 2;
  }
}

// Endian-swaps & swaps around the two DWORDs inside a QWORD
void ExCryptBnQw_SwapDwQwLeBe(const uint64_t* source, uint64_t* dest, uint32_t num_qwords)
{
  const uint32_t* source_dw = (const uint32_t*)source;
  uint32_t* dest_dw = (uint32_t*)dest;
  for (uint32_t i = 0; i < num_qwords; i++)
  {
    uint32_t first = _byteswap_ulong(source_dw[0]);
    uint32_t second = _byteswap_ulong(source_dw[1]);
    dest_dw[0] = second;
    dest_dw[1] = first;
    source_dw += 2;
    dest_dw += 2;
  }
}
