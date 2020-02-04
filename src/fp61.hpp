#pragma once

// Code to extract high part of 64 bit integer multiplication
// from: https://github.com/catid/fp61/blob/master/fp61.h

//------------------------------------------------------------------------------
// Portability Macros

// Compiler-specific force inline keyword
#ifdef _MSC_VER
# define FP61_FORCE_INLINE inline __forceinline
#else
# define FP61_FORCE_INLINE inline __attribute__((always_inline))
#endif


//------------------------------------------------------------------------------
// Portable 64x64->128 Multiply
// CAT_MUL128: r{hi,lo} = x * y

// Returns low part of product, and high part is set in r_hi
FP61_FORCE_INLINE uint64_t Emulate64x64to128(uint64_t& r_hi, const uint64_t x, const uint64_t y)
{
  // Form temporary 32-bit words
  const uint32_t x0 = static_cast<uint32_t>(x);
  const uint32_t x1 = static_cast<uint32_t>(x >> 32);
  const uint32_t y0 = static_cast<uint32_t>(y);
  const uint32_t y1 = static_cast<uint32_t>(y >> 32);

  // Calculate 32x32->64 bit products
  const uint64_t p11 = static_cast<uint64_t>(x1)* y1;
  const uint64_t p01 = static_cast<uint64_t>(x0)* y1;
  const uint64_t p10 = static_cast<uint64_t>(x1)* y0;
  const uint64_t p00 = static_cast<uint64_t>(x0)* y0;

  /*
      This is implementing schoolbook multiplication:
              x1 x0
      X       y1 y0
      -------------
                 00  LOW PART
      -------------
              00
           10 10     MIDDLE PART
      +       01
      -------------
           01
      + 11 11        HIGH PART
      -------------
  */

  // 64-bit product + two 32-bit values
  const uint64_t middle = p10
    + static_cast<uint32_t>(p00 >> 32)
    + static_cast<uint32_t>(p01);

  /*
      Proof that 64-bit products can accumulate two more 32-bit values
      without overflowing:
      Max 32-bit value is 2^32 - 1.
      PSum = (2^32-1) * (2^32-1) + (2^32-1) + (2^32-1)
           = 2^64 - 2^32 - 2^32 + 1 + 2^32 - 1 + 2^32 - 1
           = 2^64 - 1
      Therefore it cannot overflow regardless of input.
  */

  // 64-bit product + two 32-bit values
  r_hi = p11
    + static_cast<uint32_t>(middle >> 32)
    + static_cast<uint32_t>(p01 >> 32);

  // Add LOW PART and lower half of MIDDLE PART
  return (middle << 32) | static_cast<uint32_t>(p00);
}

#if defined(_MSC_VER) && defined(_WIN64)
// Visual Studio 64-bit

# include <intrin.h>
# pragma intrinsic(_umul128)
# define CAT_MUL128(r_hi, r_lo, x, y) \
    r_lo = _umul128(x, y, &(r_hi));

#elif defined(__SIZEOF_INT128__)
// Compiler supporting 128-bit values (GCC/Clang)

# define CAT_MUL128(r_hi, r_lo, x, y)                   \
    {                                                   \
        unsigned __int128 w = (unsigned __int128)x * y; \
        r_lo = (uint64_t)w;                             \
        r_hi = (uint64_t)(w >> 64);                     \
    }

#else
// Emulate 64x64->128-bit multiply with 64x64->64 operations

# define CAT_MUL128(r_hi, r_lo, x, y) \
    r_lo = Emulate64x64to128(r_hi, x, y);

#endif // End CAT_MUL128
