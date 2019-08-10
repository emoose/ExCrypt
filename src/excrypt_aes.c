#include <string.h>
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include <intrin.h> // cpuid

#include "excrypt.h"

// reference rijndael implementation, from http://www.efgh.com/software/rijndael.htm
#include "rijndael.h"

// function signature shared between reference impl. and our AESNI versions
typedef void(*rijndaelCrypt_fn)(const unsigned long*, int, const unsigned char*, unsigned char*);

rijndaelCrypt_fn AesEnc = rijndaelEncrypt;
rijndaelCrypt_fn AesDec = rijndaelDecrypt;

/* AESNI code based on https://gist.github.com/acapola/d5b940da024080dfaf5f */
void rijndaelEncrypt_AESNI(const unsigned long* rk, int nrounds, const unsigned char* plaintext, unsigned char* ciphertext)
{
  __m128i block = _mm_loadu_si128((const __m128i*)plaintext);
  __m128i* enc_table = (__m128i*)rk;

  block = _mm_xor_si128(block, enc_table[0]);
  block = _mm_aesenc_si128(block, enc_table[1]);
  block = _mm_aesenc_si128(block, enc_table[2]);
  block = _mm_aesenc_si128(block, enc_table[3]);
  block = _mm_aesenc_si128(block, enc_table[4]);
  block = _mm_aesenc_si128(block, enc_table[5]);
  block = _mm_aesenc_si128(block, enc_table[6]);
  block = _mm_aesenc_si128(block, enc_table[7]);
  block = _mm_aesenc_si128(block, enc_table[8]);
  block = _mm_aesenc_si128(block, enc_table[9]);
  block = _mm_aesenclast_si128(block, enc_table[10]);

  _mm_storeu_si128((__m128i*)ciphertext, block);
}

void rijndaelDecrypt_AESNI(const unsigned long* rk, int nrounds, const unsigned char* ciphertext, unsigned char* plaintext)
{
  __m128i block = _mm_loadu_si128((const __m128i*)ciphertext);
  __m128i* dec_table = (__m128i*)rk;

  block = _mm_xor_si128(block, dec_table[0]);
  block = _mm_aesdec_si128(block, dec_table[1]);
  block = _mm_aesdec_si128(block, dec_table[2]);
  block = _mm_aesdec_si128(block, dec_table[3]);
  block = _mm_aesdec_si128(block, dec_table[4]);
  block = _mm_aesdec_si128(block, dec_table[5]);
  block = _mm_aesdec_si128(block, dec_table[6]);
  block = _mm_aesdec_si128(block, dec_table[7]);
  block = _mm_aesdec_si128(block, dec_table[8]);
  block = _mm_aesdec_si128(block, dec_table[9]);
  block = _mm_aesdeclast_si128(block, dec_table[10]);

  _mm_storeu_si128((__m128i*)plaintext, block);
}

#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

static __m128i aes_128_key_expansion(__m128i key, __m128i keygened) {
  keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3, 3, 3, 3));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
  return _mm_xor_si128(key, keygened);
}

static int aesni_supported = 0;
int aesni_get_supported()
{
#ifndef _M_AMD64
  return 0; // AES-NI only works properly in x64?
#endif
  int regs[4];
  __cpuid(regs, 1);
  aesni_supported = (regs[2] >> 25) & 1;

  if (aesni_supported)
  {
    AesEnc = rijndaelEncrypt_AESNI;
    AesDec = rijndaelDecrypt_AESNI;
  }
  return aesni_supported;
}

void ExCryptAesKey(EXCRYPT_AES_STATE* state, const uint8_t* key)
{
  if (aesni_supported || aesni_get_supported())
  {
    __m128i* enc_table = (__m128i*)state->keytabenc;
    enc_table[0] = _mm_loadu_si128((const __m128i*)key);
    enc_table[1] = AES_128_key_exp(enc_table[0], 0x01);
    enc_table[2] = AES_128_key_exp(enc_table[1], 0x02);
    enc_table[3] = AES_128_key_exp(enc_table[2], 0x04);
    enc_table[4] = AES_128_key_exp(enc_table[3], 0x08);
    enc_table[5] = AES_128_key_exp(enc_table[4], 0x10);
    enc_table[6] = AES_128_key_exp(enc_table[5], 0x20);
    enc_table[7] = AES_128_key_exp(enc_table[6], 0x40);
    enc_table[8] = AES_128_key_exp(enc_table[7], 0x80);
    enc_table[9] = AES_128_key_exp(enc_table[8], 0x1B);
    enc_table[10] = AES_128_key_exp(enc_table[9], 0x36);

    // generate decryption keys in reverse order.
    // For some implementation reasons, decryption key schedule is NOT the encryption key schedule in reverse order
    __m128i* dec_table = (__m128i*) & state->keytabdec;
    dec_table[0] = enc_table[10];
    dec_table[1] = _mm_aesimc_si128(enc_table[9]);
    dec_table[2] = _mm_aesimc_si128(enc_table[8]);
    dec_table[3] = _mm_aesimc_si128(enc_table[7]);
    dec_table[4] = _mm_aesimc_si128(enc_table[6]);
    dec_table[5] = _mm_aesimc_si128(enc_table[5]);
    dec_table[6] = _mm_aesimc_si128(enc_table[4]);
    dec_table[7] = _mm_aesimc_si128(enc_table[3]);
    dec_table[8] = _mm_aesimc_si128(enc_table[2]);
    dec_table[9] = _mm_aesimc_si128(enc_table[1]);
    dec_table[10] = _mm_loadu_si128((const __m128i*)key);
  }
  else
  {
    rijndaelSetupEncrypt((unsigned long*)state->keytabenc, key, 128);
    memcpy(state->keytabdec, state->keytabenc, sizeof(state->keytabdec));
    rijndaelSetupDecrypt((unsigned long*)state->keytabdec, key, 128);
  }
}

void ExCryptAesEcb(const EXCRYPT_AES_STATE* state, const uint8_t* input, uint8_t* output, uint8_t encrypt)
{
  if (encrypt)
  {
    AesEnc((unsigned long*)state->keytabenc, 10, input, output);
  }
  else
  {
    AesDec((unsigned long*)state->keytabdec, 10, input, output);
  }
}

inline void xorWithIv(const uint8_t* input, uint8_t* output, const uint8_t* iv)
{
  for (uint32_t i = 0; i < AES_BLOCKLEN; i++)
  {
    output[i] = input[i] ^ iv[i];
  }
}

void rijndaelCbcEncrypt(const unsigned long* rk, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  uint8_t* iv = feed;
  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    xorWithIv(input, output, iv);
    AesEnc(rk, 10, output, output);
    iv = output;
    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }
  // store IV in feed param for next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void rijndaelCbcDecrypt(const unsigned long* rk, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed)
{
  const uint8_t* iv = feed;
  for (uint32_t i = 0; i < input_size; i += AES_BLOCKLEN)
  {
    AesDec(rk, 10, input, output);
    xorWithIv(output, output, iv);
    iv = input;
    output += AES_BLOCKLEN;
    input += AES_BLOCKLEN;
  }
  // store IV in feed param for next call
  memcpy(feed, iv, AES_BLOCKLEN);
}

void ExCryptAesCbc(const EXCRYPT_AES_STATE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed, uint8_t encrypt)
{
  if (encrypt)
  {
    rijndaelCbcEncrypt((unsigned long*)state->keytabenc, input, input_size, output, feed);
  }
  else
  {
    rijndaelCbcDecrypt((unsigned long*)state->keytabdec, input, input_size, output, feed);
  }
}
