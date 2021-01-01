#include "excrypt.h"

uint32_t curves[15] = {
  0x80000000,
  0x80000001,
  0x80000002,
  0x80000003,
  0x80000004,
  0x80000005,
  0x80000006,
  0x80000007,
  0x80000008,
  0x80000009,
  0x8000000A,
  0x8000000B,
  0x8000000C,
  0x8000000D,
  0x8000000E
};

uint32_t ExCryptEccGetCurveParameters(uint32_t curve_num, uint32_t** curve_param)
{
  if (!curve_param)
    return 1;

  if (curve_num <= 0 || curve_num >= 15)
  {
    *curve_param = 0;
    return 0;
  }

  *curve_param = &curves[curve_num];
  return 4;
}
