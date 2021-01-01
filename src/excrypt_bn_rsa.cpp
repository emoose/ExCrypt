#include "excrypt.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <bcrypt.h>
#endif

#include <algorithm>
#include <memory>

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
