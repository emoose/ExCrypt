#include <memory>
#include <map>
#include <vector>

#include "excrypt.h"

std::map<uint32_t, std::tuple<uint32_t, uint32_t>> kExKeyProperties = {
	{ XEKEY_MANUFACTURING_MODE, { 0x8, 0x1 } },
	{ XEKEY_ALTERNATE_KEY_VAULT, { 0x9, 0x1 } },
	{ XEKEY_RESTRICTED_PRIVILEGES_FLAGS, { 0xA, 0x1 } },
	{ XEKEY_RESERVED_BYTE3, { 0xB, 0x1 } },
	{ XEKEY_ODD_FEATURES, { 0xC, 0x2 } },
	{ XEKEY_ODD_AUTHTYPE, { 0xE, 0x2 } },
	{ XEKEY_RESTRICTED_HVEXT_LOADER, { 0x10, 0x4 } },
	{ XEKEY_POLICY_FLASH_SIZE, { 0x14, 0x4 } },
	{ XEKEY_POLICY_BUILTIN_USBMU_SIZE, { 0x18, 0x4 } },
	{ XEKEY_RESERVED_DWORD4, { 0x1C, 0x4 } },
	{ XEKEY_RESTRICTED_PRIVILEGES, { 0x20, 0x8 } },
	{ XEKEY_RESERVED_QWORD2, { 0x28, 0x8 } },
	{ XEKEY_RESERVED_QWORD3, { 0x30, 0x8 } },
	{ XEKEY_RESERVED_QWORD4, { 0x38, 0x8 } },
	{ XEKEY_RESERVED_KEY1, { 0x40, 0x10 } },
	{ XEKEY_RESERVED_KEY2, { 0x50, 0x10 } },
	{ XEKEY_RESERVED_KEY3, { 0x60, 0x10 } },
	{ XEKEY_RESERVED_KEY4, { 0x70, 0x10 } },
	{ XEKEY_RESERVED_RANDOM_KEY1, { 0x80, 0x10 } },
	{ XEKEY_RESERVED_RANDOM_KEY2, { 0x90, 0x10 } },
	{ XEKEY_CONSOLE_SERIAL_NUMBER, { 0xA0, 0xC } },
	{ XEKEY_MOBO_SERIAL_NUMBER, { 0xAC, 0xC } },
	{ XEKEY_GAME_REGION, { 0xB8, 0x2 } },
	// 6 bytes padding
	{ XEKEY_CONSOLE_OBFUSCATION_KEY, { 0xC0, 0x10 } },
	{ XEKEY_KEY_OBFUSCATION_KEY, { 0xD0, 0x10 } },
	{ XEKEY_ROAMABLE_OBFUSCATION_KEY, { 0xE0, 0x10 } },
	{ XEKEY_DVD_KEY, { 0xF0, 0x10 } },
	{ XEKEY_PRIMARY_ACTIVATION_KEY, { 0x100, 0x18 } },
	{ XEKEY_SECONDARY_ACTIVATION_KEY, { 0x118, 0x10 } },
	{ XEKEY_GLOBAL_DEVICE_2DES_KEY1, { 0x128, 0x10 } },
	{ XEKEY_GLOBAL_DEVICE_2DES_KEY2, { 0x138, 0x10 } },
	{ XEKEY_WIRELESS_CONTROLLER_MS_2DES_KEY1, { 0x148, 0x10 } },
	{ XEKEY_WIRELESS_CONTROLLER_MS_2DES_KEY2, { 0x158, 0x10 } },
	{ XEKEY_WIRED_WEBCAM_MS_2DES_KEY1, { 0x168, 0x10 } },
	{ XEKEY_WIRED_WEBCAM_MS_2DES_KEY2, { 0x178, 0x10 } },
	{ XEKEY_WIRED_CONTROLLER_MS_2DES_KEY1, { 0x188, 0x10 } },
	{ XEKEY_WIRED_CONTROLLER_MS_2DES_KEY2, { 0x198, 0x10 } },
	{ XEKEY_MEMORY_UNIT_MS_2DES_KEY1, { 0x1A8, 0x10 } },
	{ XEKEY_MEMORY_UNIT_MS_2DES_KEY2, { 0x1B8, 0x10 } },
	{ XEKEY_OTHER_XSM3_DEVICE_MS_2DES_KEY1, { 0x1C8, 0x10 } },
	{ XEKEY_OTHER_XSM3_DEVICE_MS_2DES_KEY2, { 0x1D8, 0x10 } },
	{ XEKEY_WIRELESS_CONTROLLER_3P_2DES_KEY1, { 0x1E8, 0x10 } },
	{ XEKEY_WIRELESS_CONTROLLER_3P_2DES_KEY2, { 0x1F8, 0x10 } },
	{ XEKEY_WIRED_WEBCAM_3P_2DES_KEY1, { 0x208, 0x10 } },
	{ XEKEY_WIRED_WEBCAM_3P_2DES_KEY2, { 0x218, 0x10 } },
	{ XEKEY_WIRED_CONTROLLER_3P_2DES_KEY1, { 0x228, 0x10 } },
	{ XEKEY_WIRED_CONTROLLER_3P_2DES_KEY2, { 0x238, 0x10 } },
	{ XEKEY_MEMORY_UNIT_3P_2DES_KEY1, { 0x248, 0x10 } },
	{ XEKEY_MEMORY_UNIT_3P_2DES_KEY2, { 0x258, 0x10 } },
	{ XEKEY_OTHER_XSM3_DEVICE_3P_2DES_KEY1, { 0x268, 0x10 } },
	{ XEKEY_OTHER_XSM3_DEVICE_3P_2DES_KEY2, { 0x278, 0x10 } },
	{ XEKEY_CONSOLE_PRIVATE_KEY, { 0x288, 0x1D0 } },
	{ XEKEY_XEIKA_PRIVATE_KEY, { 0x458, 0x390 } },
	{ XEKEY_CARDEA_PRIVATE_KEY, { 0x7E8, 0x1D0 } },
	{ XEKEY_CONSOLE_CERTIFICATE, { 0x9B8, 0x1A8 } },
	{ XEKEY_XEIKA_CERTIFICATE, { 0xB60, 0x1288 } },
	{ XEKEY_SPECIAL_KEY_VAULT_SIGNATURE, { 0x1DF8, 0x100 } },
	{ XEKEY_CARDEA_CERTIFICATE, { 0x1EE8, 0x2108 } },
};

std::map<uint32_t, std::vector<uint8_t>> ExImportedKeys;

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

BOOL ExKeysKeyVaultLoaded()
{
	return !ExKeyVault.empty();
}

void ExKeysKeyVaultSetup()
{
	// ROAMABLE_OBFUSCATION_KEY doesn't seem to be stored in the keyvault, is generated at runtime/stored in HV?
	auto* roamable_key = ExKeysGetKeyPtr(XEKEY_ROAMABLE_OBFUSCATION_KEY);
	if (ExKeysGetConsoleType() == 2)
		std::copy_n(kRoamableObfuscationKey_Retail, 0x10, roamable_key);
	else
		std::copy_n(kRoamableObfuscationKey_Devkit, 0x10, roamable_key);
}

BOOL ExKeysLoadKeyVault(const uint8_t* decrypted_kv, uint32_t length)
{
	if (length < 0x3FF0)
		return false;

	uint32_t offset = 0;
	if (length >= 0x4000)
		offset = 0x10; // skip over digest

	ExKeyVault.resize(length - offset);

	std::copy_n(decrypted_kv + offset, length - offset, ExKeyVault.data());

	ExKeysKeyVaultSetup();

	return true;
}

BOOL ExKeysLoadKeyVaultFromPath(const char* filepath)
{
	FILE* file;
	if (fopen_s(&file, filepath, "rb") != 0)
		return false;

	fseek(file, 0, SEEK_END);
	auto filesize = ftell(file);
	fseek(file, 0, SEEK_SET);

	if (filesize < 0x3FF0)
	{
		fclose(file);
		return false;
	}

	if (filesize >= 0x4000)
	{
		// skip over digest
		fseek(file, 0x10, SEEK_SET);
		filesize -= 0x10;
	}

	ExKeyVault.resize(filesize);

	fread(ExKeyVault.data(), 1, filesize, file);
	fclose(file);

	ExKeysKeyVaultSetup();

	return true;
}

BOOL ExKeysImportKey(uint32_t key_idx, uint8_t* input, uint32_t size) {
	std::vector<uint8_t> key_vector;
	key_vector.resize(size);
	memcpy(key_vector.data(), input, size);
	ExImportedKeys.insert({ key_idx, key_vector });
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

	std::copy_n(ExKeyVault.data() + key_offset, key_size, output);

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

uint32_t ExKeysGetConsoleID(uint8_t* raw_bytes, char* hex_string)
{
	uint8_t* console_cert = ExKeysGetKeyPtr(XEKEY_CONSOLE_CERTIFICATE);

	if (raw_bytes) {
		std::copy_n(console_cert + 2, 5, raw_bytes);
	}
	if (hex_string) {
		// TODO
	}
	return 0;
}

uint32_t ExKeysGetConsoleType()
{
	uint8_t* console_cert = ExKeysGetKeyPtr(XEKEY_CONSOLE_CERTIFICATE);

	return _byteswap_ulong(*(uint32_t*)(console_cert + 0x18));
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

// Signs the given hash with the loaded keyvaults private-key, and writes out console cert + signature to output_cert_sig
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
	uint64_t temp_sig[0x20];

	uint32_t key_digits = _byteswap_ulong(key->num_digits);
	uint32_t modulus_size = key_digits * 8;
	if (modulus_size > 0x200)
		return false;

	ExCryptBnQw_SwapDwQwLeBe((uint64_t*)input_sig, temp_sig, key_digits);
	if (!ExCryptBnQwNeRsaPubCrypt(temp_sig, temp_sig, key))
		return false;

	ExCryptBnQw_SwapDwQwLeBe(temp_sig, temp_sig, key_digits);
	return ExCryptBnDwLePkcs1Verify(hash, (uint8_t*)temp_sig, modulus_size);
}

// Verifies that the given hash was signed by the given console certificate, and that the console certificate was signed by the master key.
BOOL ExKeysConsoleSignatureVerification(const uint8_t* hash, uint8_t* input_signature, int32_t *compare_result)
{
	uint32_t master_key_size = 0x110;
	uint8_t our_console_cert[0x1A8];
	uint8_t master_key[0x110];
	EXCRYPT_RSAPUB_1024 console_public_key;

	ExKeysGetConsoleCertificate(our_console_cert);

	int32_t diff = ExCryptMemDiff(our_console_cert, input_signature, 0x1A8);
	if (compare_result != NULL)
		*compare_result = diff;

	//ExKeysGetKey(XEKEY_CONSTANT_MASTER_KEY, master_key, &master_key_size);
	if (ExImportedKeys.count(XEKEY_CONSTANT_MASTER_KEY) > 0)
		memcpy(master_key, ExImportedKeys.at(XEKEY_CONSTANT_MASTER_KEY).data(), master_key_size);
	else
		memset(master_key, 0, 0x110);

	if (master_key_size == 0x110 && _byteswap_ulong(*(uint32_t*)master_key) == 0x20) {
		// Validate the input console certificate against the master public key.
		uint8_t cert_checksum[0x14];
		ExCryptSha(input_signature, 0xA8, NULL, 0, NULL, 0, cert_checksum, 0x14);
		if (ExKeysPkcs1Verify(cert_checksum, input_signature + 0xA8, (EXCRYPT_RSA*)master_key)) {
			// The certificate doesn't have the public key size - the real function does this stuff, too.
			console_public_key.rsa.num_digits = _byteswap_ulong(0x10);
			console_public_key.rsa.pub_exponent = *(uint32_t*)(input_signature + 0x24);
			memcpy(console_public_key.modulus, input_signature + 0x28, sizeof(console_public_key.modulus));
			// Validate the input hash against the provided signatuer.
			if (ExKeysPkcs1Verify(hash, input_signature + 0x1A8, &console_public_key.rsa))
				return true;
		}
	}

	return false;
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

uint32_t ExKeysObfuscate(BOOL roaming, const uint8_t* input, uint32_t input_size, uint8_t* output, uint32_t* output_size)
{
	std::copy_n(input, input_size, output + 0x18);
	*output_size = input_size + 0x18;

	//TODO: set random nonce/confounder
	//ExCryptRandom(output + 0x10, 8);
	std::memset(output + 0x10, 0xBB, 8);

	uint32_t key_idx = roaming ? uint32_t(XEKEY_ROAMABLE_OBFUSCATION_KEY) : uint32_t(XEKEY_CONSOLE_OBFUSCATION_KEY);

	auto result = ExKeysHmacSha(key_idx, output + 0x10, *output_size - 0x10, nullptr, 0, nullptr, 0, output, 0x10);
	if (result < 0)
		return result;

	uint8_t key[0x10];
	ExKeysHmacSha(key_idx, output, 0x10, 0, 0, 0, 0, key, 0x10);

	ExCryptRc4(key, 0x10, output + 0x10, *output_size - 0x10);

	return result; // TODO: X_STATUS_SUCCESS
}

BOOL ExKeysUnObfuscate(BOOL roaming, const uint8_t* input, uint32_t input_size, uint8_t* output, uint32_t* output_size)
{
	if (input_size < 0x18)
		return false;

	uint8_t buf1[0x18];
	std::copy_n(input, 0x18, buf1);

	*output_size = input_size - 0x18;
	std::copy_n(input + 0x18, *output_size, output);

	uint32_t key_idx = roaming ? uint32_t(XEKEY_ROAMABLE_OBFUSCATION_KEY) : uint32_t(XEKEY_CONSOLE_OBFUSCATION_KEY);

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
