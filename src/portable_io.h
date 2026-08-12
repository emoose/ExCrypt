#pragma once

#include <stdint.h>
#include <stdio.h>

#ifndef fopen_s
int fopen_s(FILE** pFile, const char* filename, const char* mode);
#endif