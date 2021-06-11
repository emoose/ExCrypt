#include "excrypt.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>
#endif

#include <algorithm>
#include <memory>

extern "C" {

uint8_t kStaticPrivateExponent1024[] = {
  0x51, 0xEC, 0x1F, 0x9D, 0x56, 0x26, 0xC2, 0xFC, 0x10, 0xA6, 0x67, 0x64, 0xCB, 0x3A, 0x6D, 0x4D,
  0xA1, 0xE7, 0x4E, 0xA8, 0x42, 0xF0, 0xF4, 0xFD, 0xFA, 0x66, 0xEF, 0xC7, 0x8E, 0x10, 0x2F, 0xE4,
  0x1C, 0xA3, 0x1D, 0xD0, 0xCE, 0x39, 0x2E, 0xC3, 0x19, 0x2D, 0xD0, 0x58, 0x74, 0x79, 0xAC, 0x08,
  0xE7, 0x90, 0xC1, 0xAC, 0x2D, 0xC6, 0xEB, 0x47, 0xE8, 0x3D, 0xCF, 0x4C, 0x6D, 0xFF, 0x51, 0x65,
  0xD4, 0x6E, 0xBD, 0x0F, 0x15, 0x79, 0x37, 0x95, 0xC4, 0xAF, 0x90, 0x9E, 0x2B, 0x50, 0x8A, 0x0A,
  0x22, 0x4A, 0xB3, 0x41, 0xE5, 0x89, 0x80, 0x73, 0xCD, 0xFA, 0x21, 0x02, 0xF5, 0xDD, 0x30, 0xDD,
  0x07, 0x2A, 0x6F, 0x34, 0x07, 0x81, 0x97, 0x7E, 0xB2, 0xFB, 0x72, 0xE9, 0xEA, 0xC1, 0x88, 0x39,
  0xAC, 0x48, 0x2B, 0xA8, 0x4D, 0xFC, 0xD7, 0xED, 0x9B, 0xF9, 0xDE, 0xC2, 0x45, 0x93, 0x4C, 0x4C 
};

BOOL ExCryptBnQwNeRsaPrvCrypt(const uint64_t* input, uint64_t* output, const EXCRYPT_RSA* key)
{
#ifndef _WIN32
  return false;
#else
  if (!input || !output || !key)
    return false;

  uint32_t key_digits = _byteswap_ulong(key->num_digits);
  if (key_digits <= 0 || key_digits > 0x40)
    return false;

  // TODO: currently only works with 1024-bit/16-digit keys, due to kStaticPrivateExponent1024 above
  // Need to replace that with some way of calculating it from the rest of the privkey instead
  if (key_digits != 16)
    return false;

  // TODO: check this
  //if (ExCryptBnQwNeCompare(input, xecrypt_modulus, key_digits) >= 0)
  //  return false;

  uint32_t modulus_size = key_digits * 8; // = 16
  uint32_t prime_count = key_digits / 2;
  uint32_t prime_size = prime_count * 8;

  // Convert XECRYPT blob into BCrypt format
  ULONG key_size = sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(uint32_t) +  // exponent
    modulus_size +                                   // modulus
    prime_size +                                     // prime1
    prime_size +                                     // prime2
    prime_size +                                     // exponent1
    prime_size +                                     // exponent2
    prime_size +                                     // coefficient
    modulus_size;                              // private exponent
  auto key_buf = std::make_unique<uint8_t[]>(key_size);
  auto* key_header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(key_buf.get());

  key_header->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
  key_header->BitLength = modulus_size * 8;
  key_header->cbPublicExp = sizeof(uint32_t);
  key_header->cbModulus = modulus_size;
  key_header->cbPrime1 = key_header->cbPrime2 = prime_size;

  // Copy in exponent/modulus, luckily these are BE inside BCrypt blob
  uint32_t* key_exponent = reinterpret_cast<uint32_t*>(&key_header[1]);
  *key_exponent = key->pub_exponent;

  // ...except other fields need to be reversed in 64-bit chunks for BCrypt to
  // make use of them properly for some reason
  uint64_t* key_modulus = reinterpret_cast<uint64_t*>(&key_exponent[1]);
  auto* xecrypt_modulus = reinterpret_cast<const uint64_t*>(&key[1]);
  std::reverse_copy(xecrypt_modulus, xecrypt_modulus + key_digits, key_modulus);

  uint64_t* key_prime1 = reinterpret_cast<uint64_t*>(&key_modulus[key_digits]);
  auto* xecrypt_prime1 =
    reinterpret_cast<const uint64_t*>(&xecrypt_modulus[key_digits]);

  std::reverse_copy(xecrypt_prime1, xecrypt_prime1 + (prime_count), key_prime1);

  uint64_t* key_prime2 = reinterpret_cast<uint64_t*>(&key_prime1[prime_count]);
  auto* xecrypt_prime2 =
    reinterpret_cast<const uint64_t*>(&xecrypt_prime1[prime_count]);

  std::reverse_copy(xecrypt_prime2, xecrypt_prime2 + prime_count, key_prime2);

  uint64_t* key_exponent1 =
    reinterpret_cast<uint64_t*>(&key_prime2[prime_count]);
  auto* xecrypt_exponent1 =
    reinterpret_cast<const uint64_t*>(&xecrypt_prime2[prime_count]);

  std::reverse_copy(xecrypt_exponent1, xecrypt_exponent1 + prime_count,
    key_exponent1);

  uint64_t* key_exponent2 =
    reinterpret_cast<uint64_t*>(&key_exponent1[prime_count]);
  auto* xecrypt_exponent2 =
    reinterpret_cast<const uint64_t*>(&xecrypt_exponent1[prime_count]);

  std::reverse_copy(xecrypt_exponent2, xecrypt_exponent2 + prime_count,
    key_exponent2);

  uint64_t* key_coefficient =
    reinterpret_cast<uint64_t*>(&key_exponent2[prime_count]);
  auto* xecrypt_coefficient =
    reinterpret_cast<const uint64_t*>(&xecrypt_exponent2[prime_count]);

  std::reverse_copy(xecrypt_coefficient, xecrypt_coefficient + prime_count,
    key_coefficient);

  uint64_t* key_privexponent =
    reinterpret_cast<uint64_t*>(&key_coefficient[prime_count]);

  // X360 uses a static private exponent / "D" value
  std::memcpy(key_privexponent, kStaticPrivateExponent1024, 0x80);

  BCRYPT_ALG_HANDLE hAlgorithm = NULL;
  NTSTATUS status = BCryptOpenAlgorithmProvider(
    &hAlgorithm, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);

  if (!BCRYPT_SUCCESS(status))
    return false;

  auto* buf = key_buf.get();
  BCRYPT_KEY_HANDLE hKey = NULL;
  status = BCryptImportKeyPair(hAlgorithm, NULL, BCRYPT_RSAFULLPRIVATE_BLOB, &hKey,
    buf, key_size, 0);

  if (!BCRYPT_SUCCESS(status))
  {
    if (hAlgorithm)
      BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return false;
  }

  // Byteswap & reverse the input into output, as BCrypt wants MSB first
  uint8_t* output_bytes = reinterpret_cast<uint8_t*>(output);
  ExCryptBnQw_SwapDwQwLeBe(input, output, key_digits);
  std::reverse(output_bytes, output_bytes + modulus_size);

  // BCryptDecrypt only works with private keys, fortunately BCryptEncrypt
  // performs the right actions needed for us to decrypt the input
  ULONG result_size = 0;

  status = BCryptDecrypt(hKey, output_bytes, modulus_size, nullptr, nullptr, 0,
    output_bytes, modulus_size, &result_size, BCRYPT_PAD_NONE);

  //assert(result_size == modulus_size);

  if (BCRYPT_SUCCESS(status)) {
    // Reverse data & byteswap again so data is as game expects
    std::reverse(output_bytes, output_bytes + modulus_size);
    ExCryptBnQw_SwapDwQwLeBe(output, output, key_digits);
  }

  if (hKey)
    BCryptDestroyKey(hKey);

  if (hAlgorithm)
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

  return BCRYPT_SUCCESS(status);
#endif
}

BOOL ExCryptBnQwNeRsaPubCrypt(const uint64_t* input, uint64_t* output, const EXCRYPT_RSA* key)
{
#ifndef _WIN32
  return false;
#else
  if (!input || !output || !key)
    return false;

  uint32_t key_digits = _byteswap_ulong(key->num_digits);
  if (key_digits <= 0 || key_digits > 0x40)
    return false;

  auto* xecrypt_modulus = reinterpret_cast<const uint64_t*>(&key[1]);

  // TODO: check this
  //if (ExCryptBnQwNeCompare(input, xecrypt_modulus, key_digits) >= 0)
  //  return false;

  uint32_t modulus_size = key_digits * 8;

  // Convert XECRYPT blob into BCrypt format
  ULONG key_size = sizeof(BCRYPT_RSAKEY_BLOB) + sizeof(uint32_t) + modulus_size;
  auto key_buf = std::make_unique<uint8_t[]>(key_size);

  auto* key_header = reinterpret_cast<BCRYPT_RSAKEY_BLOB*>(key_buf.get());
  key_header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
  key_header->BitLength = modulus_size * 8;
  key_header->cbPublicExp = sizeof(uint32_t);
  key_header->cbModulus = modulus_size;
  key_header->cbPrime1 = key_header->cbPrime2 = 0;

  // Copy in exponent/modulus, luckily these are BE inside BCrypt blob
  uint32_t* key_exponent = reinterpret_cast<uint32_t*>(&key_header[1]);
  *key_exponent = key->pub_exponent;

  // ...except modulus needs to be reversed in 64-bit chunks for BCrypt to make
  // use of it properly for some reason
  auto* key_modulus = reinterpret_cast<uint64_t*>(&key_exponent[1]);
  std::reverse_copy(xecrypt_modulus, xecrypt_modulus + key_digits, key_modulus);

  BCRYPT_ALG_HANDLE hAlgorithm = NULL;
  NTSTATUS status = BCryptOpenAlgorithmProvider(
    &hAlgorithm, BCRYPT_RSA_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);

  if (!BCRYPT_SUCCESS(status))
    return false;

  BCRYPT_KEY_HANDLE hKey = NULL;
  status = BCryptImportKeyPair(hAlgorithm, NULL, BCRYPT_RSAPUBLIC_BLOB, &hKey,
    key_buf.get(), key_size, 0);

  if (!BCRYPT_SUCCESS(status))
  {
    if (hAlgorithm)
      BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return false;
  }

  // Byteswap & reverse the input into output, as BCrypt wants MSB first
  uint8_t* output_bytes = reinterpret_cast<uint8_t*>(output);
  ExCryptBnQw_SwapDwQwLeBe(input, output, key_digits);
  std::reverse(output_bytes, output_bytes + modulus_size);

  // BCryptDecrypt only works with private keys, fortunately BCryptEncrypt
  // performs the right actions needed for us to decrypt the input
  ULONG result_size = 0;
  status = BCryptEncrypt(hKey, output_bytes, modulus_size, nullptr, nullptr, 0,
      output_bytes, modulus_size, &result_size, BCRYPT_PAD_NONE);

  //assert(result_size == modulus_size);

  if (BCRYPT_SUCCESS(status)) {
    // Reverse data & byteswap again so data is as game expects
    std::reverse(output_bytes, output_bytes + modulus_size);
    ExCryptBnQw_SwapDwQwLeBe(output, output, key_digits);
  }

  if (hKey)
    BCryptDestroyKey(hKey);

  if (hAlgorithm)
    BCryptCloseAlgorithmProvider(hAlgorithm, 0);

  return BCRYPT_SUCCESS(status);
#endif
}

};
