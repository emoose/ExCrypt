#pragma once

#include <stdint.h>
#include <stddef.h>

int expect_bytes(const char* name, const uint8_t* actual, const uint8_t* expected, size_t size);
int test_aes(void);
int test_sha(void);
int test_rc4(void);