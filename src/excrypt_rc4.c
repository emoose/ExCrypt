#include "excrypt.h"

void ExCryptRc4Key(EXCRYPT_RC4_STATE* state, const uint8_t* key, uint32_t key_size)
{
  // Setup RC4 state
  state->i = state->j = 0;
  for (uint32_t x = 0; x < 0x100; x++) {
    state->S[x] = (uint8_t)x;
  }

  uint32_t idx = 0;
  for (uint32_t x = 0; x < 0x100; x++) {
    idx = (idx + state->S[x] + key[x % 0x10]) % 0x100;
    uint8_t temp = state->S[idx];
    state->S[idx] = state->S[x];
    state->S[x] = temp;
  }
}

void ExCryptRc4Ecb(EXCRYPT_RC4_STATE* state, uint8_t* buf, uint32_t buf_size)
{
  // Crypt data
  for (uint32_t idx = 0; idx < buf_size; idx++) {
    state->i = (state->i + 1) % 0x100;
    state->j = (state->j + state->S[state->i]) % 0x100;
    uint8_t temp = state->S[state->i];
    state->S[state->i] = state->S[state->j];
    state->S[state->j] = temp;

    uint8_t a = buf[idx];
    uint8_t b =
      state->S[(state->S[state->i] + state->S[state->j]) % 0x100];
    buf[idx] = (uint8_t)(a ^ b);
  }
}

void ExCryptRc4(const uint8_t* key, uint32_t key_size, uint8_t* buf, uint32_t buf_size)
{
  EXCRYPT_RC4_STATE state;
  ExCryptRc4Key(&state, key, key_size);
  ExCryptRc4Ecb(&state, buf, buf_size);
}
