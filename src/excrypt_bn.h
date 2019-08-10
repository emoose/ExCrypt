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

uint64_t ExCryptBnQwNeModInv(uint64_t input);
