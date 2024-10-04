#pragma once
// BigNum functions, used as part of public-key crypto

void ExCryptBnDw_Zero(uint32_t* data, uint32_t data_dwords);
void ExCryptBnDw_Copy(const uint32_t* source, uint32_t* dest, uint32_t num_dwords);
void ExCryptBnDw_SwapLeBe(const uint32_t* source, uint32_t* dest, uint32_t num_dwords);

void ExCryptBnQw_Zero(uint64_t* data, uint32_t num_qwords);
void ExCryptBnQw_Copy(const uint64_t* source, uint64_t* dest, uint32_t num_qwords);
void ExCryptBnQw_SwapLeBe(const uint64_t* source, uint64_t* dest, uint32_t num_qwords);
void ExCryptBnQw_SwapDwQw(const uint64_t* source, uint64_t* dest, uint32_t num_qwords);
void ExCryptBnQw_SwapDwQwLeBe(const uint64_t* source, uint64_t* dest, uint32_t num_qwords);

int32_t ExCryptBnQwNeCompare(const uint64_t* input1, const uint64_t* input2, uint32_t num_qwords);

// excrypt_bn_mod.cpp
void ExCryptBnQwNeModMul(const uint64_t* input_A, const uint64_t* input_B, uint64_t* output_C, uint64_t inverse, const uint64_t* modulus, uint32_t modulus_size);
uint64_t ExCryptBnQwNeModInv(uint64_t input);

// Structure of RSA & RC4-decrypted signature
// (Signature is RC4-encrypted using hash field as key, and then RSA privkey-encrypted)
typedef struct _EXCRYPT_SIG
{
  uint64_t padding[28]; // zeroed
  uint8_t one; // 0x01
  uint8_t salt[10];
  uint8_t hash[20]; // SHA1(sig[0:8] | salt | data-hash)
  uint8_t end; // 0xBC
} EXCRYPT_SIG;
#ifdef __cplusplus
static_assert(sizeof(EXCRYPT_SIG) == 0x100, "sizeof(EXCRYPT_SIG) != 0x100");
#endif

// Base struct of all ExCrypt RSA keys
typedef struct _EXCRYPT_RSA
{
  uint32_t num_digits;
  uint32_t pub_exponent;
  uint64_t reserved;
} EXCRYPT_RSA;
#ifdef __cplusplus
static_assert(sizeof(EXCRYPT_RSA) == 0x10, "sizeof(EXCRYPT_RSA) != 0x100");
#endif

typedef struct _EXCRYPT_RSAPUB_1024
{
  EXCRYPT_RSA rsa;
  uint64_t modulus[16];
} EXCRYPT_RSAPUB_1024;
#ifdef __cplusplus
static_assert(sizeof(EXCRYPT_RSAPUB_1024) == 0x90, "sizeof(EXCRYPT_RSAPUB_1024) != 0x90");
#endif

typedef struct _EXCRYPT_RSAPUB_2048
{
  EXCRYPT_RSA rsa;
  uint64_t modulus[32];
} EXCRYPT_RSAPUB_2048;
#ifdef __cplusplus
static_assert(sizeof(EXCRYPT_RSAPUB_2048) == 0x110, "sizeof(EXCRYPT_RSAPUB_2048) != 0x110");
#endif

typedef struct _EXCRYPT_RSAPRV_1024
{
  EXCRYPT_RSA rsa;
  uint64_t modulus[16];
  uint64_t prime1[8];
  uint64_t prime2[8];
  uint64_t exponent1[8];
  uint64_t exponent2[8];
  uint64_t coefficient[8];
  uint64_t priv_exponent[16];
} EXCRYPT_RSAPRV_1024;

// excrypt_bn_sig.c
void ExCryptBnQwBeSigFormat(EXCRYPT_SIG* sig, const uint8_t* hash, const uint8_t* salt);
//BOOL ExCryptBnQwBeSigCreate(EXCRYPT_SIG* sig, const uint8_t* hash, const uint8_t* salt, const EXCRYPT_RSA* privkey);
BOOL ExCryptBnQwBeSigVerify(EXCRYPT_SIG* sig, const uint8_t* hash, const uint8_t* salt, const EXCRYPT_RSA* pubkey);
int32_t ExCryptBnQwBeSigDifference(EXCRYPT_SIG* sig, const uint8_t* hash, const uint8_t* salt, const EXCRYPT_RSA* pubkey);

// excrypt_bn_key.cpp

// (not from XeCrypt)
// Swaps an EXCRYPT_RSA key from Xbox360 format to a format usable with PC ExCrypt functions.
// TODO: remove this - our funcs should be handling conversions automatically!
void ExCryptBn_BeToLeKey(EXCRYPT_RSA* key, const uint8_t* input, uint32_t input_size);

// excrypt_bn_rsa.cpp
// TODO: investigate PrivExp/'D' constant, XeCrypt struct doesn't provide it, but pretty much all RSA codebases need it
// We only have one for 1024-bit numbers atm, should be some way to use ModInv to calculate it though...
BOOL ExCryptBnQwNeRsaPrvCrypt(const uint64_t* input, uint64_t* output, const EXCRYPT_RSA* key);
BOOL ExCryptBnQwNeRsaPubCrypt(const uint64_t* input, uint64_t* output, const EXCRYPT_RSA* key);

// excrypt_bn_pkcs1.cpp
void ExCryptBnDwLePkcs1Format(const uint8_t* hash, uint32_t format, uint8_t* output_sig, uint32_t output_sig_size);
BOOL ExCryptBnDwLePkcs1Verify(const uint8_t* hash, const uint8_t* input_sig, uint32_t input_sig_size);

//BOOL ExCryptBnQwNeRsaKeyGen(uint32_t num_bits, uint32_t public_exponent, EXCRYPT_RSA* pub_key, EXCRYPT_RSA* priv_key);
