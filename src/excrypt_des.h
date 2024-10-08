#pragma once
// DES & 3DES functions

typedef struct _EXCRYPT_DES_STATE
{
  uint64_t keytab[16];
} EXCRYPT_DES_STATE;
#ifdef __cplusplus
static_assert(sizeof(EXCRYPT_DES_STATE) == 0x80, "sizeof(EXCRYPT_DES_STATE) != 0x80");
#endif

void ExCryptDesParity(const uint8_t* input, uint32_t input_size, uint8_t* output);

void ExCryptDesKey(EXCRYPT_DES_STATE* state, const uint8_t* key);
void ExCryptDesEcb(const EXCRYPT_DES_STATE* state, const uint8_t* input, uint8_t* output, uint8_t encrypt);
void ExCryptDesCbc(const EXCRYPT_DES_STATE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed, uint8_t encrypt);

typedef struct _EXCRYPT_DES3_STATE
{
  EXCRYPT_DES_STATE des_state[3];
} EXCRYPT_DES3_STATE;
#ifdef __cplusplus
static_assert(sizeof(EXCRYPT_DES3_STATE) == 0x180, "sizeof(EXCRYPT_DES3_STATE) != 0x180");
#endif

void ExCryptDes3Key(EXCRYPT_DES3_STATE* state, const uint64_t* keys);
void ExCryptDes3Ecb(const EXCRYPT_DES3_STATE* state, const uint8_t* input, uint8_t* output, uint8_t encrypt);
void ExCryptDes3Cbc(const EXCRYPT_DES3_STATE* state, const uint8_t* input, uint32_t input_size, uint8_t* output, uint8_t* feed, uint8_t encrypt);
