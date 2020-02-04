#include <string.h>
#include <stdlib.h>

#include "excrypt.h"

// BnQwBeSig seems to be a custom XeCrypt signature format, so we have to implement code for it ourselves :(
// AFAIK console-signing (eg. thru XeKeysConsolePrivateKeySign) use PKCS1 instead, so hopefully we can use some existing codebase for those.

void ExCryptBnQwBeSigFormat(EXCRYPT_SIG* sig, const uint8_t* hash, const uint8_t* salt)
{
  EXCRYPT_SIG output;

  memset(output.padding, 0, 28 * sizeof(uint64_t));
  output.one = 1;
  memcpy(output.salt, salt, 10);
  output.end = 0xBC;

  // Create hash value inside signature
  ExCryptSha((uint8_t*)&output, 8, hash, 20, salt, 10, output.hash, 20);

  // RC4 encrypt signature contents
  ExCryptRc4(output.hash, 20, (uint8_t*)&output, 0xEB);

  // Clear high bit of signature
  *(uint8_t*)&output = (*(uint8_t*)&output) & 0x7F;

  // Swap signature, every 8 bytes
  uint64_t* in64 = (uint64_t*)&output;
  uint64_t* out64 = (uint64_t*)sig;
  for (int c = 0; c < 0x20; c++)
    out64[0x1F - c] = in64[c];
}

BOOL ExCryptBnQwBeSigVerify(EXCRYPT_SIG* sig, const uint8_t* hash, const uint8_t* salt, const EXCRYPT_RSA* pubkey)
{
  return ExCryptBnQwBeSigDifference(sig, hash, salt, pubkey) == 0;
}

int32_t ExCryptBnQwBeSigDifference(EXCRYPT_SIG* sig, const uint8_t* hash, const uint8_t* salt, const EXCRYPT_RSA* pubkey)
{
  if (pubkey->num_digits != 0x20 || (pubkey->pub_exponent != 3 && pubkey->pub_exponent != 0x10001))
    return -1;

  uint64_t* qwSig = (uint64_t*)sig;
  EXCRYPT_RSAPUB_2048* key = (EXCRYPT_RSAPUB_2048*)pubkey;

  uint64_t inverse = ExCryptBnQwNeModInv(key->modulus[0]);

  uint64_t sig_copy[0x20];
  ExCryptBnQw_SwapDwQwLeBe(qwSig, qwSig, 32);
  ExCryptBnQw_Copy(qwSig, sig_copy, 32);

  uint32_t exp = pubkey->pub_exponent;
  while (1)
  {
    exp >>= 1;
    if (!exp)
      break;
    ExCryptBnQwNeModMul(sig_copy, sig_copy, sig_copy, inverse, key->modulus, 32);
    exp = exp;
  }
  ExCryptBnQwNeModMul(sig_copy, qwSig, qwSig, inverse, key->modulus, 32);
  ExCryptBnQw_SwapDwQwLeBe(qwSig, qwSig, 32);

  ExCryptBnQwBeSigFormat((EXCRYPT_SIG*)&sig_copy, hash, salt);

  return ExCryptMemDiff((uint8_t*)qwSig, (uint8_t*)&sig_copy, 256);
}
