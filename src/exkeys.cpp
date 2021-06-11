#include <memory>
#include <map>
#include <vector>

#include "excrypt.h"

std::map<uint32_t, std::tuple<uint32_t, uint32_t>> kExKeyProperties = {
	{ 0x00, { 0x8, 0x1 } },
	{ 0x01, { 0x9, 0x1 } },
	{ 0x02, { 0xA, 0x1 } },
	{ 0x03, { 0xB, 0x1 } },
	{ 0x04, { 0xC, 0x2 } },
	{ 0x05, { 0xE, 0x2 } },
	{ 0x06, { 0x10, 0x4 } },
	{ 0x07, { 0x14, 0x4 } },
	{ 0x08, { 0x18, 0x4 } },
	{ 0x09, { 0x1C, 0x4 } },
	{ 0x0A, { 0x20, 0x8 } },
	{ 0x0B, { 0x28, 0x8 } },
	{ 0x0C, { 0x30, 0x8 } },
	{ 0x0D, { 0x38, 0x8 } },
	{ 0x0E, { 0x40, 0x10 } },
	{ 0x0F, { 0x50, 0x10 } },
	{ 0x10, { 0x60, 0x10 } },
	{ 0x11, { 0x70, 0x10 } },
	{ 0x12, { 0x80, 0x10 } },
	{ 0x13, { 0x90, 0x10 } },
	{ 0x14, { 0xA0, 0xC } },
	{ 0x15, { 0xAC, 0xC } },
	{ 0x16, { 0xB8, 0x2 } },
	// 6 bytes padding
	{ 0x17, { 0xC0, 0x10 } },
	{ 0x18, { 0xD0, 0x10 } },
	{ 0x19, { 0xE0, 0x10 } },
	{ 0x1A, { 0xF0, 0x10 } },
	{ 0x1B, { 0x100, 0x18 } },
	{ 0x1C, { 0x118, 0x10 } },
	{ 0x1D, { 0x128, 0x10 } },
	{ 0x1E, { 0x138, 0x10 } },
	{ 0x1F, { 0x148, 0x10 } },
	{ 0x20, { 0x158, 0x10 } },
	{ 0x21, { 0x168, 0x10 } },
	{ 0x22, { 0x178, 0x10 } },
	{ 0x23, { 0x188, 0x10 } },
	{ 0x24, { 0x198, 0x10 } },
	{ 0x25, { 0x1A8, 0x10 } },
	{ 0x26, { 0x1B8, 0x10 } },
	{ 0x27, { 0x1C8, 0x10 } },
	{ 0x28, { 0x1D8, 0x10 } },
	{ 0x29, { 0x1E8, 0x10 } },
	{ 0x2A, { 0x1F8, 0x10 } },
	{ 0x2B, { 0x208, 0x10 } },
	{ 0x2C, { 0x218, 0x10 } },
	{ 0x2D, { 0x228, 0x10 } },
	{ 0x2E, { 0x238, 0x10 } },
	{ 0x2F, { 0x248, 0x10 } },
	{ 0x30, { 0x258, 0x10 } },
	{ 0x31, { 0x268, 0x10 } },
	{ 0x32, { 0x278, 0x10 } },
	{ 0x33, { 0x288, 0x1D0 } },
	{ 0x34, { 0x458, 0x390 } },
	{ 0x35, { 0x7E8, 0x1D0 } },
	{ 0x36, { 0x9B8, 0x1A8 } },
	{ 0x37, { 0xB60, 0x1288 } },
	{ 0x44, { 0x1DF8, 0x100 } },
	{ 0x38, { 0x1EE8, 0x2108 } },
};

uint8_t kRoamableObfuscationKey_Retail[0x10] = 
{ 
	0xE1, 0xBC, 0x15, 0x9C, 0x73, 0xB1, 0xEA, 0xE9, 0xAB, 0x31, 0x70, 0xF3, 0xAD, 0x47, 0xEB, 0xF3
};
uint8_t kRoamableObfuscationKey_Devkit[0x10] = 
{
	0xDA, 0xB6, 0x9A, 0xD9, 0x8E, 0x28, 0x76, 0x4F, 0x97, 0x7E, 0xE2, 0x48, 0x7E, 0x4F, 0x3F, 0x68
};

std::vector<uint8_t> ExKeyVault;

extern "C"
{

BOOL ExKeysLoadKeyVault(const char* filepath)
{
	FILE* file;
	if (fopen_s(&file, filepath, "rb") != 0)
		return false;

	fseek(file, 0, SEEK_END);
	auto filesize = ftell(file);
	fseek(file, 0, SEEK_SET);

	if (filesize >= 0x4000)
	{
		// skip over digest
		fseek(file, 0x10, SEEK_SET);
		filesize -= 0x10;
	}

	ExKeyVault.resize(filesize);

	fread(ExKeyVault.data(), 1, filesize, file);
	fclose(file);

	// ROAMABLE_OBFUSCATION_KEY doesn't seem to be stored in the keyvault, is generated at runtime/stored in HV?
	auto* roamable_key = ExKeysGetKeyPtr(XEKEY_ROAMABLE_OBFUSCATION_KEY);
	if (ExKeysGetConsoleType() == 2)
		std::memcpy(roamable_key, kRoamableObfuscationKey_Retail, 0x10);
	else
		std::memcpy(roamable_key, kRoamableObfuscationKey_Devkit, 0x10);

	return true;
}

BOOL ExKeysIsKeySupported(uint32_t key_idx)
{
	return kExKeyProperties.count(key_idx) > 0;
}

BOOL ExKeysGetKey(uint32_t key_idx, uint8_t* output, uint32_t* output_size)
{
	if (output_size)
		*output_size = 0;

	if (!ExKeysIsKeySupported(key_idx))
		return false;

	if (ExKeyVault.empty())
		return false;

	auto& key_info = kExKeyProperties.at(key_idx);
	auto& key_offset = std::get<0>(key_info);
	auto& key_size = std::get<1>(key_info);

	if (output_size)
		*output_size = key_size;

	if (!output)
		return true;

	std::memcpy(output, ExKeyVault.data() + key_offset, key_size);

	return true;
}

uint8_t* ExKeysGetKeyPtr(uint32_t key_idx)
{
	if (!ExKeysIsKeySupported(key_idx))
		return nullptr;

	auto& key_info = kExKeyProperties.at(key_idx);
	auto& key_offset = std::get<0>(key_info);

	return ExKeyVault.data() + key_offset;
}

// Returns size of given key, and IIRC can also return flags?
uint32_t ExKeysGetKeyProperties(uint32_t key_idx)
{
	if (!ExKeysIsKeySupported(key_idx))
		return 0;

	auto& key_info = kExKeyProperties.at(key_idx);
	auto& key_size = std::get<1>(key_info);
	return key_size;
}

uint32_t ExKeysGetConsoleCertificate(uint8_t* output)
{
	uint32_t length = 0;
	ExKeysGetKey(XEKEY_CONSOLE_CERTIFICATE, output, &length);
	return 0;
}

uint32_t ExKeysGetConsoleId(uint8_t* raw_bytes, char* hex_string)
{
	uint8_t* console_cert = ExKeysGetKeyPtr(XEKEY_CONSOLE_CERTIFICATE);

	if (raw_bytes) {
		std::memcpy(raw_bytes, console_cert + 2, 5);
	}
	if (hex_string) {
		// TODO
	}
	return 0;
}

uint32_t ExKeysGetConsoleType()
{
	uint8_t* console_cert = ExKeysGetKeyPtr(XEKEY_CONSOLE_CERTIFICATE);

	return *(uint32_t*)(console_cert + 0x18);
}

uint32_t ExKeysGetConsolePrivateKey(EXCRYPT_RSAPRV_1024* output)
{
	uint32_t length = 0;
	ExKeysGetKey(XEKEY_CONSOLE_PRIVATE_KEY, (uint8_t*)output, &length);
	return 0;
}

BOOL ExKeysQwNeRsaPrvCrypt(uint32_t key_idx, const uint64_t* input, uint64_t* output)
{
	if (key_idx != XEKEY_CONSOLE_PRIVATE_KEY &&
		key_idx != XEKEY_XEIKA_PRIVATE_KEY &&
		key_idx != XEKEY_CARDEA_PRIVATE_KEY)
		return false;

	// Xeika key is larger than the others, and likely needs a different D/PrivExp value for it (see kStaticPrivateExponent1024), so disallow it for now
	if (key_idx == XEKEY_XEIKA_PRIVATE_KEY)
		return false;

	auto* key_ptr = ExKeysGetKeyPtr(key_idx);

	return ExCryptBnQwNeRsaPrvCrypt(input, output, (EXCRYPT_RSA*)key_ptr);
}

BOOL ExKeysConsolePrivateKeySign(const uint8_t* hash, uint8_t* output_cert_sig)
{
	uint64_t sig_buf[0x10];

	ExCryptBnDwLePkcs1Format(hash, 0, (uint8_t*)sig_buf, 0x10 * 8);
	ExCryptBnQw_SwapDwQwLeBe(sig_buf, sig_buf, 0x10);

	if (!ExKeysQwNeRsaPrvCrypt(XEKEY_CONSOLE_PRIVATE_KEY, sig_buf, sig_buf))
		return false;

	ExCryptBnQw_SwapDwQwLeBe(sig_buf, (uint64_t*)(output_cert_sig + 0x1A8), 0x10);
	ExKeysGetConsoleCertificate(output_cert_sig);
	return true;
}

BOOL ExKeysPkcs1Verify(const uint8_t* hash, const uint8_t* input_sig, EXCRYPT_RSA* key)
{
	uint64_t temp_sig[0x10];

	uint32_t key_digits = _byteswap_ulong(key->num_digits);
	uint32_t modulus_size = key_digits * 8;
	if (modulus_size > 0x200)
		return false;

	ExCryptBnQw_SwapDwQwLeBe((uint64_t*)input_sig, temp_sig, 0x10);
	if (!ExCryptBnQwNeRsaPubCrypt(temp_sig, temp_sig, key))
		return false;

	ExCryptBnQw_SwapDwQwLeBe(temp_sig, temp_sig, 0x10);
	return ExCryptBnDwLePkcs1Verify(hash, (uint8_t*)temp_sig, 0x10 * 8);
}

uint32_t ExKeysObscureKey(const uint8_t* input, uint8_t* output)
{
	EXCRYPT_AES_STATE aes;
	ExCryptAesKey(&aes, ExKeysGetKeyPtr(XEKEY_KEY_OBFUSCATION_KEY));
	ExCryptAesEcb(&aes, input, output, 1);

	return 0; // TODO: X_STATUS_SUCCESS
}

uint32_t ExKeysHmacShaUsingKey(const uint8_t* obscured_key,
	const uint8_t* input1, uint32_t input1_size,
	const uint8_t* input2, uint32_t input2_size,
	const uint8_t* input3, uint32_t input3_size,
	uint8_t* output, uint32_t output_size)
{
	if (!obscured_key)
		return 1; // TODO: X_STATUS_INVALID_PARAMETER

	uint8_t key[0x10];

	// Deobscure key
	EXCRYPT_AES_STATE aes;
	ExCryptAesKey(&aes, ExKeysGetKeyPtr(XEKEY_KEY_OBFUSCATION_KEY));
	ExCryptAesEcb(&aes, obscured_key, key, 0);

	ExCryptHmacSha(key, 0x10, input1, input1_size, input2, input2_size, input3, input3_size, output, output_size);

	return 0; // TODO: X_STATUS_SUCCESS
}

uint32_t ExKeysHmacSha(uint32_t key_idx,
	const uint8_t* input1, uint32_t input1_size,
	const uint8_t* input2, uint32_t input2_size,
	const uint8_t* input3, uint32_t input3_size,
	uint8_t* output, uint32_t output_size)
{
	auto* key = ExKeysGetKeyPtr(key_idx);
	if (!key)
		return 1; // TODO: X_STATUS_INVALID_PARAMETER

	auto size = ExKeysGetKeyProperties(key_idx);

	ExCryptHmacSha(key, size, input1, input1_size, input2, input2_size, input3, input3_size, output, output_size);

	return 0; // TODO: X_STATUS_SUCCESS
}

uint32_t ExKeysObfuscate(bool roaming, const uint8_t* input, uint32_t input_size, uint8_t* output, uint32_t* output_size)
{
	std::memcpy(output + 0x18, input, input_size);
	*output_size = input_size + 0x18;

	//TODO: set random nonce
	//ExCryptRandom(output + 0x10, 8);
	std::memset(output + 0x10, 0xBB, 8);

	uint32_t key_idx = roaming ? XEKEY_ROAMABLE_OBFUSCATION_KEY : XEKEY_CONSOLE_OBFUSCATION_KEY;

	auto result = ExKeysHmacSha(key_idx, output + 0x10, *output_size - 0x10, nullptr, 0, nullptr, 0, output, 0x10);
	if (result < 0)
		return result;

	uint8_t key[0x10];
	ExKeysHmacSha(key_idx, output, 0x10, 0, 0, 0, 0, key, 0x10);

	ExCryptRc4(key, 0x10, output + 0x10, *output_size - 0x10);

	return result; // TODO: X_STATUS_SUCCESS
}

BOOL ExKeysUnobfuscate(bool roaming, const uint8_t* input, uint32_t input_size, uint8_t* output, uint32_t* output_size)
{
	if (input_size < 0x18)
		return false;

	uint8_t buf1[0x20];
	std::memcpy(buf1, input, 0x18);

	*output_size = input_size - 0x18;
	std::memcpy(output, input + 0x18, *output_size);

	uint32_t key_idx = roaming ? XEKEY_ROAMABLE_OBFUSCATION_KEY : XEKEY_CONSOLE_OBFUSCATION_KEY;

	uint8_t key[0x10];
	auto result = ExKeysHmacSha(key_idx, buf1, 0x10, nullptr, 0, nullptr, 0, key, 0x10);
	if (result < 0)
		return false;

	EXCRYPT_RC4_STATE rc4;
	ExCryptRc4Key(&rc4, key, 0x10);
	ExCryptRc4Ecb(&rc4, buf1 + 0x10, 8);
	ExCryptRc4Ecb(&rc4, output, *output_size);

	uint8_t hash[0x10];
	ExKeysHmacSha(key_idx, buf1 + 0x10, 8, output, *output_size, nullptr, 0, hash, 0x10);

	return std::memcmp(hash, buf1, 0x10) == 0;
}

};
