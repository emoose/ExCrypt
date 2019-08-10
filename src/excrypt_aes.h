#pragma once

typedef struct _EXCRYPT_AES_STATE
{
  uint8_t keytabenc[11][4][4];
  uint8_t keytabdec[11][4][4];
} EXCRYPT_AES_STATE;
static_assert(sizeof(EXCRYPT_AES_STATE) == 0x160, "sizeof(EXCRYPT_AES_STATE) != 0x160");

#define AES_BLOCKLEN 16

void ExCryptAesKey(EXCRYPT_AES_STATE * state, const uint8_t * key);
void ExCryptAesEcb(const EXCRYPT_AES_STATE* state, const uint8_t* input, uint8_t* output, uint8_t encrypt);
void ExCryptAesCbc(const EXCRYPT_AES_STATE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed, uint8_t encrypt);

//void ExCryptAesCtr(const EXCRYPT_AES_STATE* pAesState, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* counter);
//void ExCryptAesCbcMac(const uint8_t* key, const uint8_t* input, uint32_t input_size, uint8_t* output);
//void ExCryptAesDmMac(const uint8_t* key, const uint8_t* input, uint32_t input_size, uint8_t* output);
