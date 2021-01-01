/*
---------------------------------------------------------------------------
Copyright (c) 1998-2010, Brian Gladman, Worcester, UK. All rights reserved.

The redistribution and use of this software (with or without changes)
is allowed without the payment of fees or royalties provided that:

source code distributions include the above copyright notice, this
list of conditions and the following disclaimer;

binary distributions include the above copyright notice, this list
of conditions and the following disclaimer in their documentation.

This software is provided 'as is' with no explicit or implied warranties
in respect of its operation, including, but not limited to, correctness
and fitness for purpose.
---------------------------------------------------------------------------
Issue Date: 20/12/2007

This code implements sha256, sha384 and sha512 but the latter two
functions rely on efficient 64-bit integer operations that may not be
very efficient on 32-bit machines

The sha256 functions use a type 'sha256_ctx' to hold details of the
current hash state and uses the following three calls:

    void sha256_begin( sha256_ctx ctx[1] )
    void sha256_hash( const unsigned char data[],
                          unsigned long len, sha256_ctx ctx[1] )
    void sha_end1( unsigned char hval[], sha256_ctx ctx[1] )

The first subroutine initialises a hash computation by setting up the
context in the sha256_ctx context. The second subroutine hashes 8-bit
bytes from array data[] into the hash state withinh sha256_ctx context,
the number of bytes to be hashed being given by the the unsigned long
integer len.  The third subroutine completes the hash calculation and
places the resulting digest value in the array of 8-bit bytes hval[].

The sha384 and sha512 functions are similar and use the interfaces:

    void sha384_begin( sha384_ctx ctx[1] );
    void sha384_hash( const unsigned char data[],
                          unsigned long len, sha384_ctx ctx[1] );
    void sha384_end( unsigned char hval[], sha384_ctx ctx[1] );

    void sha512_begin( sha512_ctx ctx[1] );
    void sha512_hash( const unsigned char data[],
                          unsigned long len, sha512_ctx ctx[1] );
    void sha512_end( unsigned char hval[], sha512_ctx ctx[1] );

In addition there is a function sha2 that can be used to call all these
functions using a call with a hash length parameter as follows:

    int sha2_begin( unsigned long len, sha2_ctx ctx[1] );
    void sha2_hash( const unsigned char data[],
                          unsigned long len, sha2_ctx ctx[1] );
    void sha2_end( unsigned char hval[], sha2_ctx ctx[1] );

The data block length in any one call to any of these hash functions must
be no more than 2^32 - 1 bits or 2^29 - 1 bytes.

My thanks to Erik Andersen <andersen@codepoet.org> for testing this code
on big-endian systems and for his assistance with corrections
*/

#if 1
#define UNROLL_SHA2         /* for SHA2 loop unroll     */
#endif

#include <string.h>         /* for memcpy() etc.        */
#include "excrypt.h"

#if defined( _MSC_VER ) && ( _MSC_VER > 800 )
#pragma intrinsic(memcpy)
#pragma intrinsic(memset)
#endif

#if 0 && defined(_MSC_VER)
#define rotl32 _lrotl
#define rotr32 _lrotr
#else
#define rotl32(x,n)   (((x) << n) | ((x) >> (32 - n)))
#define rotr32(x,n)   (((x) >> n) | ((x) << (32 - n)))
#endif

#if !defined(bswap_32)
#define bswap_32(x) ((rotr32((x), 24) & 0x00ff00ff) | (rotr32((x), 8) & 0xff00ff00))
#endif

#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#define SWAP_BYTES
#else
#undef  SWAP_BYTES
#endif

#if 0

#define ch(x,y,z)       (((x) & (y)) ^ (~(x) & (z)))
#define maj(x,y,z)      (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#else   /* Thanks to Rich Schroeppel and Colin Plumb for the following      */

#define ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define maj(x,y,z)      (((x) & (y)) | ((z) & ((x) ^ (y))))

#endif

/* round transforms for SHA256 and SHA512 compression functions */

#define vf(n,i) v[(n - i) & 7]

#define hf(i) (p[i & 15] += \
  g_1(p[(i + 14) & 15]) + p[(i + 9) & 15] + g_0(p[(i + 1) & 15]))

#define v_cycle(i,j)                                \
  vf(7,i) += (j ? hf(i) : p[i]) + k_0[i+j]        \
  + s_1(vf(4,i)) + ch(vf(4,i),vf(5,i),vf(6,i));   \
  vf(3,i) += vf(7,i);                             \
  vf(7,i) += s_0(vf(0,i))+ maj(vf(0,i),vf(1,i),vf(2,i))

#define SHA256_MASK (SHA256_BLOCK_SIZE - 1)

#if defined(SWAP_BYTES)
#define bsw_32(p,n) \
  { int _i = (n); while(_i--) ((uint32_t*)p)[_i] = bswap_32(((uint32_t*)p)[_i]); }
#else
#define bsw_32(p,n)
#endif

#define s_0(x)  (rotr32((x),  2) ^ rotr32((x), 13) ^ rotr32((x), 22))
#define s_1(x)  (rotr32((x),  6) ^ rotr32((x), 11) ^ rotr32((x), 25))
#define g_0(x)  (rotr32((x),  7) ^ rotr32((x), 18) ^ ((x) >>  3))
#define g_1(x)  (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))
#define k_0     k256

/* rotated SHA256 round definition. Rather than swapping variables as in    */
/* FIPS-180, different variables are 'rotated' on each round, returning     */
/* to their starting positions every eight rounds                           */

#define q(n)  v##n

#define one_cycle(a,b,c,d,e,f,g,h,k,w)  \
  q(h) += s_1(q(e)) + ch(q(e), q(f), q(g)) + k + w; \
  q(d) += q(h); q(h) += s_0(q(a)) + maj(q(a), q(b), q(c))

/* SHA256 mixing data   */

const uint32_t k256[64] =
{ 0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul,
    0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
    0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul,
    0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
    0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul,
    0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
    0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul,
    0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
    0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul,
    0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
    0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul,
    0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
    0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul,
    0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
    0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul,
    0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul,
};

/* Compile 64 bytes of hash data into SHA256 digest value   */
/* NOTE: this routine assumes that the byte order in the    */
/* ctx->wbuf[] at this point is such that low address bytes */
/* in the ORIGINAL byte stream will go into the high end of */
/* words on BOTH big and little endian systems              */

void sha256_compile(EXCRYPT_SHA256_STATE ctx[1])
{
#if !defined(UNROLL_SHA2)

  uint32_t j, * p = ctx->wbuf, v[8];

  memcpy(v, ctx->hash, sizeof(ctx->hash));

  for (j = 0; j < 64; j += 16)
  {
    v_cycle(0, j); v_cycle(1, j);
    v_cycle(2, j); v_cycle(3, j);
    v_cycle(4, j); v_cycle(5, j);
    v_cycle(6, j); v_cycle(7, j);
    v_cycle(8, j); v_cycle(9, j);
    v_cycle(10, j); v_cycle(11, j);
    v_cycle(12, j); v_cycle(13, j);
    v_cycle(14, j); v_cycle(15, j);
  }

  ctx->hash[0] += v[0]; ctx->hash[1] += v[1];
  ctx->hash[2] += v[2]; ctx->hash[3] += v[3];
  ctx->hash[4] += v[4]; ctx->hash[5] += v[5];
  ctx->hash[6] += v[6]; ctx->hash[7] += v[7];

#else

  uint32_t* p = ctx->wbuf, v0, v1, v2, v3, v4, v5, v6, v7;

  v0 = ctx->hash[0]; v1 = ctx->hash[1];
  v2 = ctx->hash[2]; v3 = ctx->hash[3];
  v4 = ctx->hash[4]; v5 = ctx->hash[5];
  v6 = ctx->hash[6]; v7 = ctx->hash[7];

  one_cycle(0, 1, 2, 3, 4, 5, 6, 7, k256[0], p[0]);
  one_cycle(7, 0, 1, 2, 3, 4, 5, 6, k256[1], p[1]);
  one_cycle(6, 7, 0, 1, 2, 3, 4, 5, k256[2], p[2]);
  one_cycle(5, 6, 7, 0, 1, 2, 3, 4, k256[3], p[3]);
  one_cycle(4, 5, 6, 7, 0, 1, 2, 3, k256[4], p[4]);
  one_cycle(3, 4, 5, 6, 7, 0, 1, 2, k256[5], p[5]);
  one_cycle(2, 3, 4, 5, 6, 7, 0, 1, k256[6], p[6]);
  one_cycle(1, 2, 3, 4, 5, 6, 7, 0, k256[7], p[7]);
  one_cycle(0, 1, 2, 3, 4, 5, 6, 7, k256[8], p[8]);
  one_cycle(7, 0, 1, 2, 3, 4, 5, 6, k256[9], p[9]);
  one_cycle(6, 7, 0, 1, 2, 3, 4, 5, k256[10], p[10]);
  one_cycle(5, 6, 7, 0, 1, 2, 3, 4, k256[11], p[11]);
  one_cycle(4, 5, 6, 7, 0, 1, 2, 3, k256[12], p[12]);
  one_cycle(3, 4, 5, 6, 7, 0, 1, 2, k256[13], p[13]);
  one_cycle(2, 3, 4, 5, 6, 7, 0, 1, k256[14], p[14]);
  one_cycle(1, 2, 3, 4, 5, 6, 7, 0, k256[15], p[15]);

  one_cycle(0, 1, 2, 3, 4, 5, 6, 7, k256[16], hf(0));
  one_cycle(7, 0, 1, 2, 3, 4, 5, 6, k256[17], hf(1));
  one_cycle(6, 7, 0, 1, 2, 3, 4, 5, k256[18], hf(2));
  one_cycle(5, 6, 7, 0, 1, 2, 3, 4, k256[19], hf(3));
  one_cycle(4, 5, 6, 7, 0, 1, 2, 3, k256[20], hf(4));
  one_cycle(3, 4, 5, 6, 7, 0, 1, 2, k256[21], hf(5));
  one_cycle(2, 3, 4, 5, 6, 7, 0, 1, k256[22], hf(6));
  one_cycle(1, 2, 3, 4, 5, 6, 7, 0, k256[23], hf(7));
  one_cycle(0, 1, 2, 3, 4, 5, 6, 7, k256[24], hf(8));
  one_cycle(7, 0, 1, 2, 3, 4, 5, 6, k256[25], hf(9));
  one_cycle(6, 7, 0, 1, 2, 3, 4, 5, k256[26], hf(10));
  one_cycle(5, 6, 7, 0, 1, 2, 3, 4, k256[27], hf(11));
  one_cycle(4, 5, 6, 7, 0, 1, 2, 3, k256[28], hf(12));
  one_cycle(3, 4, 5, 6, 7, 0, 1, 2, k256[29], hf(13));
  one_cycle(2, 3, 4, 5, 6, 7, 0, 1, k256[30], hf(14));
  one_cycle(1, 2, 3, 4, 5, 6, 7, 0, k256[31], hf(15));

  one_cycle(0, 1, 2, 3, 4, 5, 6, 7, k256[32], hf(0));
  one_cycle(7, 0, 1, 2, 3, 4, 5, 6, k256[33], hf(1));
  one_cycle(6, 7, 0, 1, 2, 3, 4, 5, k256[34], hf(2));
  one_cycle(5, 6, 7, 0, 1, 2, 3, 4, k256[35], hf(3));
  one_cycle(4, 5, 6, 7, 0, 1, 2, 3, k256[36], hf(4));
  one_cycle(3, 4, 5, 6, 7, 0, 1, 2, k256[37], hf(5));
  one_cycle(2, 3, 4, 5, 6, 7, 0, 1, k256[38], hf(6));
  one_cycle(1, 2, 3, 4, 5, 6, 7, 0, k256[39], hf(7));
  one_cycle(0, 1, 2, 3, 4, 5, 6, 7, k256[40], hf(8));
  one_cycle(7, 0, 1, 2, 3, 4, 5, 6, k256[41], hf(9));
  one_cycle(6, 7, 0, 1, 2, 3, 4, 5, k256[42], hf(10));
  one_cycle(5, 6, 7, 0, 1, 2, 3, 4, k256[43], hf(11));
  one_cycle(4, 5, 6, 7, 0, 1, 2, 3, k256[44], hf(12));
  one_cycle(3, 4, 5, 6, 7, 0, 1, 2, k256[45], hf(13));
  one_cycle(2, 3, 4, 5, 6, 7, 0, 1, k256[46], hf(14));
  one_cycle(1, 2, 3, 4, 5, 6, 7, 0, k256[47], hf(15));

  one_cycle(0, 1, 2, 3, 4, 5, 6, 7, k256[48], hf(0));
  one_cycle(7, 0, 1, 2, 3, 4, 5, 6, k256[49], hf(1));
  one_cycle(6, 7, 0, 1, 2, 3, 4, 5, k256[50], hf(2));
  one_cycle(5, 6, 7, 0, 1, 2, 3, 4, k256[51], hf(3));
  one_cycle(4, 5, 6, 7, 0, 1, 2, 3, k256[52], hf(4));
  one_cycle(3, 4, 5, 6, 7, 0, 1, 2, k256[53], hf(5));
  one_cycle(2, 3, 4, 5, 6, 7, 0, 1, k256[54], hf(6));
  one_cycle(1, 2, 3, 4, 5, 6, 7, 0, k256[55], hf(7));
  one_cycle(0, 1, 2, 3, 4, 5, 6, 7, k256[56], hf(8));
  one_cycle(7, 0, 1, 2, 3, 4, 5, 6, k256[57], hf(9));
  one_cycle(6, 7, 0, 1, 2, 3, 4, 5, k256[58], hf(10));
  one_cycle(5, 6, 7, 0, 1, 2, 3, 4, k256[59], hf(11));
  one_cycle(4, 5, 6, 7, 0, 1, 2, 3, k256[60], hf(12));
  one_cycle(3, 4, 5, 6, 7, 0, 1, 2, k256[61], hf(13));
  one_cycle(2, 3, 4, 5, 6, 7, 0, 1, k256[62], hf(14));
  one_cycle(1, 2, 3, 4, 5, 6, 7, 0, k256[63], hf(15));

  ctx->hash[0] += v0; ctx->hash[1] += v1;
  ctx->hash[2] += v2; ctx->hash[3] += v3;
  ctx->hash[4] += v4; ctx->hash[5] += v5;
  ctx->hash[6] += v6; ctx->hash[7] += v7;
#endif
}

/* SHA256 hash data in an array of bytes into hash buffer   */
/* and call the hash_compile function as required.          */

void ExCryptSha256Update(EXCRYPT_SHA256_STATE* state, const uint8_t* input, uint32_t input_size)
{
  uint32_t pos = (uint32_t)((state->count >> 3) & SHA256_MASK);
  const unsigned char* sp = input;
  unsigned char* w = (unsigned char*)state->wbuf;
#if SHA2_BITS == 1
  uint32_t ofs = (state->count & 7);
#else
  input_size <<= 3;
#endif

  state->count += input_size;

#if SHA2_BITS == 1
  if (ofs)                 /* if not on a byte boundary    */
  {
    if (ofs + input_size < 8)   /* if no added bytes are needed */
    {
      w[pos] |= (*sp >> ofs);
    }
    else                /* otherwise and add bytes      */
    {
      unsigned char part = w[pos];

      while ((int)(ofs + (input_size -= 8)) >= 0)
      {
        w[pos++] = part | (*sp >> ofs);
        part = *sp++ << (8 - ofs);
        if (pos == SHA256_BLOCK_SIZE)
        {
          bsw_32(w, SHA256_BLOCK_SIZE >> 2);
          sha256_compile(state); pos = 0;
        }
      }

      w[pos] = part;
    }
  }
  else    /* data is byte aligned */
#endif
  {
    uint32_t space = SHA256_BLOCK_SIZE - pos;

    while (input_size >= (space << 3))
    {
      memcpy(w + pos, sp, space);
      bsw_32(w, SHA256_BLOCK_SIZE >> 2);
      sha256_compile(state);
      sp += space; input_size -= (space << 3);
      space = SHA256_BLOCK_SIZE; pos = 0;
    }
    memcpy(w + pos, sp, (input_size + 7 * SHA2_BITS) >> 3);
  }
}

const uint32_t i256[8] =
{
    0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,
    0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul
};

void ExCryptSha256Init(EXCRYPT_SHA256_STATE* state)
{
  memset(state, 0, sizeof(EXCRYPT_SHA256_STATE));
  memcpy(state->hash, i256, sizeof(state->hash));
}

/* SHA256 Final padding and digest calculation  */
void ExCryptSha256Final(EXCRYPT_SHA256_STATE* state, uint8_t* output, uint32_t output_size)
{
  uint32_t    i = (uint32_t)((state->count >> 3) & SHA256_MASK), m1;

  /* put bytes in the buffer in an order in which references to   */
  /* 32-bit words will put bytes with lower addresses into the    */
  /* top of 32 bit words on BOTH big and little endian machines   */
  bsw_32(state->wbuf, (i + 3 + SHA2_BITS) >> 2)

    /* we now need to mask valid bytes and add the padding which is */
    /* a single 1 bit and as many zero bits as necessary. Note that */
    /* we can always add the first padding byte here because the    */
    /* buffer always has at least one empty slot                    */
    m1 = (unsigned char)0x80 >> (state->count & 7);
  state->wbuf[i >> 2] &= ((0xffffff00 | (~m1 + 1)) << 8 * (~i & 3));
  state->wbuf[i >> 2] |= (m1 << 8 * (~i & 3));

  /* we need 9 or more empty positions, one for the padding byte  */
  /* (above) and eight for the length count.  If there is not     */
  /* enough space pad and empty the buffer                        */
  if (i > SHA256_BLOCK_SIZE - 9)
  {
    if (i < 60) state->wbuf[15] = 0;
    sha256_compile(state);
    i = 0;
  }
  else    /* compute a word index for the empty buffer positions  */
    i = (i >> 2) + 1;

  while (i < 15) /* and zero pad all but last two positions        */
    state->wbuf[i++] = 0;

  /* the following 32-bit length fields are assembled in the      */
  /* wrong byte order on little endian machines but this is       */
  /* corrected later since they are only ever used as 32-bit      */
  /* word values.                                                 */
  state->wbuf[15] = state->count;
  sha256_compile(state);

  /* extract the hash value as bytes in case the hash buffer is   */
  /* misaligned for 32-bit words                                  */
  for (i = 0; i < output_size; ++i)
    output[i] = ((state->hash[i >> 2] >> (8 * (~i & 3))) & 0xff);
}

void ExCryptSha256(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size)
{
  EXCRYPT_SHA256_STATE  state[1];

  ExCryptSha256Init(state);
  if (input1 && input1_size) {
    ExCryptSha256Update(state, input1, input1_size);
  }
  if (input2 && input2_size) {
    ExCryptSha256Update(state, input2, input2_size);
  }
  if (input3 && input3_size) {
    ExCryptSha256Update(state, input3, input3_size);
  }
  ExCryptSha256Final(state, output, output_size);
}

#define SHA512_MASK (SHA512_BLOCK_SIZE - 1)

#define rotr64(x,n)   (((x) >> n) | ((x) << (64 - n)))

#if !defined(bswap_64)
#define bswap_64(x) (((uint64_t)(bswap_32((uint32_t)(x)))) << 32 | bswap_32((uint32_t)((x) >> 32)))
#endif

#if defined(SWAP_BYTES)
#define bsw_64(p,n) \
  { int _i = (n); while(_i--) ((uint64_t*)p)[_i] = bswap_64(((uint64_t*)p)[_i]); }
#else
#define bsw_64(p,n)
#endif

/* SHA512 mixing function definitions   */

#ifdef   s_0
# undef  s_0
# undef  s_1
# undef  g_0
# undef  g_1
# undef  k_0
#endif

#define s_0(x)  (rotr64((x), 28) ^ rotr64((x), 34) ^ rotr64((x), 39))
#define s_1(x)  (rotr64((x), 14) ^ rotr64((x), 18) ^ rotr64((x), 41))
#define g_0(x)  (rotr64((x),  1) ^ rotr64((x),  8) ^ ((x) >>  7))
#define g_1(x)  (rotr64((x), 19) ^ rotr64((x), 61) ^ ((x) >>  6))
#define k_0     k512

/* SHA384/SHA512 mixing data    */

const uint64_t  k512[80] =
{
    0x428a2f98d728ae22, 0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
    0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210,
    0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910,
    0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60,
    0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9,
    0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

/* Compile 128 bytes of hash data into SHA384/512 digest    */
/* NOTE: this routine assumes that the byte order in the    */
/* ctx->wbuf[] at this point is such that low address bytes */
/* in the ORIGINAL byte stream will go into the high end of */
/* words on BOTH big and little endian systems              */

void sha512_compile(EXCRYPT_SHA512_STATE ctx[1])
{
  uint64_t    v[8], * p = ctx->wbuf;
  uint32_t    j;

  memcpy(v, ctx->hash, sizeof(ctx->hash));

  for (j = 0; j < 80; j += 16)
  {
    v_cycle(0, j); v_cycle(1, j);
    v_cycle(2, j); v_cycle(3, j);
    v_cycle(4, j); v_cycle(5, j);
    v_cycle(6, j); v_cycle(7, j);
    v_cycle(8, j); v_cycle(9, j);
    v_cycle(10, j); v_cycle(11, j);
    v_cycle(12, j); v_cycle(13, j);
    v_cycle(14, j); v_cycle(15, j);
  }

  ctx->hash[0] += v[0]; ctx->hash[1] += v[1];
  ctx->hash[2] += v[2]; ctx->hash[3] += v[3];
  ctx->hash[4] += v[4]; ctx->hash[5] += v[5];
  ctx->hash[6] += v[6]; ctx->hash[7] += v[7];
}

/* Compile 128 bytes of hash data into SHA256 digest value  */
/* NOTE: this routine assumes that the byte order in the    */
/* ctx->wbuf[] at this point is in such an order that low   */
/* address bytes in the ORIGINAL byte stream placed in this */
/* buffer will now go to the high end of words on BOTH big  */
/* and little endian systems                                */

void ExCryptSha512Update(EXCRYPT_SHA512_STATE* state, const uint8_t* input, uint32_t input_size)
{
  uint32_t pos = (uint32_t)(state->count >> 3) & SHA512_MASK;
  const unsigned char* sp = input;
  unsigned char* w = (unsigned char*)state->wbuf;
#if SHA2_BITS == 1
  uint32_t ofs = (state->count & 7);
#else
  input_size <<= 3;
#endif

  state->count += input_size;

#if SHA2_BITS == 1
  if (ofs)                 /* if not on a byte boundary    */
  {
    if (ofs + input_size < 8)   /* if no added bytes are needed */
    {
      w[pos] |= (*sp >> ofs);
    }
    else                /* otherwise and add bytes      */
    {
      unsigned char part = w[pos];

      while ((int)(ofs + (input_size -= 8)) >= 0)
      {
        w[pos++] = part | (*sp >> ofs);
        part = *sp++ << (8 - ofs);
        if (pos == SHA512_BLOCK_SIZE)
        {
          bsw_64(w, SHA512_BLOCK_SIZE >> 3);
          sha512_compile(state); pos = 0;
        }
      }

      w[pos] = part;
    }
  }
  else    /* data is byte aligned */
#endif
  {
    uint32_t space = SHA512_BLOCK_SIZE - pos;

    while (input_size >= (space << 3))
    {
      memcpy(w + pos, sp, space);
      bsw_64(w, SHA512_BLOCK_SIZE >> 3);
      sha512_compile(state);
      sp += space; input_size -= (space << 3);
      space = SHA512_BLOCK_SIZE; pos = 0;
    }
    memcpy(w + pos, sp, (input_size + 7 * SHA2_BITS) >> 3);
  }
}

void ExCryptSha384Update(EXCRYPT_SHA384_STATE* state, const uint8_t* input, uint32_t input_size)
{
  ExCryptSha512Update(state, input, input_size);
}

/* SHA384 initialisation data   */

const uint64_t  i384[80] =
{
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507,
    0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511,
    0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

void ExCryptSha384Init(EXCRYPT_SHA384_STATE* state)
{
  memset(state, 0, sizeof(EXCRYPT_SHA384_STATE));
  memcpy(state->hash, i384, sizeof(state->hash));
}

void ExCryptSha384Final(EXCRYPT_SHA384_STATE* state, uint8_t* output, uint32_t output_size)
{
  ExCryptSha512Final(state, output, output_size);
}

void ExCryptSha384(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size)
{
  EXCRYPT_SHA384_STATE  state[1];

  ExCryptSha384Init(state);
  if (input1 && input1_size) {
    ExCryptSha384Update(state, input1, input1_size);
  }
  if (input2 && input2_size) {
    ExCryptSha384Update(state, input2, input2_size);
  }
  if (input3 && input3_size) {
    ExCryptSha384Update(state, input3, input3_size);
  }
  ExCryptSha512Final(state, output, output_size);
}

/* SHA512 initialisation data   */

static const uint64_t i512[SHA512_DIGEST_SIZE >> 3] =
{
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

void ExCryptSha512Init(EXCRYPT_SHA512_STATE* state)
{
  memset(state, 0, sizeof(EXCRYPT_SHA512_STATE));
  memcpy(state->hash, i512, sizeof(state->hash));
}

void ExCryptSha512Final(EXCRYPT_SHA512_STATE* state, uint8_t* output, uint32_t output_size)
{
  uint32_t     i = (uint32_t)((state->count >> 3) & SHA512_MASK);
  uint64_t     m1;

  /* put bytes in the buffer in an order in which references to   */
  /* 32-bit words will put bytes with lower addresses into the    */
  /* top of 32 bit words on BOTH big and little endian machines   */
  bsw_64(state->wbuf, (i + 7 + SHA2_BITS) >> 3);

  /* we now need to mask valid bytes and add the padding which is */
  /* a single 1 bit and as many zero bits as necessary. Note that */
  /* we can always add the first padding byte here because the    */
  /* buffer always has at least one empty slot                    */
  m1 = (unsigned char)0x80 >> (state->count & 7);
  state->wbuf[i >> 3] &= ((0xffffffffffffff00 | (~m1 + 1)) << 8 * (~i & 7));
  state->wbuf[i >> 3] |= (m1 << 8 * (~i & 7));

  /* we need 17 or more empty byte positions, one for the padding */
  /* byte (above) and sixteen for the length count.  If there is  */
  /* not enough space pad and empty the buffer                    */
  if (i > SHA512_BLOCK_SIZE - 17)
  {
    if (i < 120) state->wbuf[15] = 0;
    sha512_compile(state);
    i = 0;
  }
  else
    i = (i >> 3) + 1;

  while (i < 15)
    state->wbuf[i++] = 0;

  /* the following 64-bit length fields are assembled in the      */
  /* wrong byte order on little endian machines but this is       */
  /* corrected later since they are only ever used as 64-bit      */
  /* word values.                                                 */
  state->wbuf[15] = state->count;
  sha512_compile(state);

  /* extract the hash value as bytes in case the hash buffer is   */
  /* misaligned for 32-bit words                                  */
  for (i = 0; i < output_size; ++i)
    output[i] = ((state->hash[i >> 3] >> (8 * (~i & 7))) & 0xff);
}

void ExCryptSha512(const uint8_t* input1, uint32_t input1_size, const uint8_t* input2, uint32_t input2_size,
  const uint8_t* input3, uint32_t input3_size, uint8_t* output, uint32_t output_size)
{
  EXCRYPT_SHA512_STATE  state[1];

  ExCryptSha512Init(state);
  if (input1 && input1_size) {
    ExCryptSha512Update(state, input1, input1_size);
  }
  if (input2 && input2_size) {
    ExCryptSha512Update(state, input2, input2_size);
  }
  if (input3 && input3_size) {
    ExCryptSha512Update(state, input3, input3_size);
  }
  ExCryptSha512Final(state, output, output_size);
}

const uint32_t i224[8] =
{
    0xc1059ed8ul, 0x367cd507ul, 0x3070dd17ul, 0xf70e5939ul,
    0xffc00b31ul, 0x68581511ul, 0x64f98fa7ul, 0xbefa4fa4ul
};

void ExCryptSha224Init(EXCRYPT_SHA256_STATE* state)
{
  memset(state, 0, sizeof(EXCRYPT_SHA256_STATE));
  memcpy(state->hash, i224, sizeof(state->hash));
}
