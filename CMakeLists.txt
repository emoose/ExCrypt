cmake_minimum_required(VERSION 3.16)

project(ExCrypt LANGUAGES C CXX)

include(CTest)

add_library(ExCrypt STATIC
        src/excrypt.h
        src/excrypt_aes.c
        src/excrypt_aes.h
        src/excrypt_bn.c
        src/excrypt_bn.h
        src/excrypt_bn_key.cpp
        src/excrypt_bn_mod.cpp
        src/excrypt_bn_pkcs1.cpp
        src/excrypt_bn_rsa.cpp
        src/excrypt_bn_sig.c
        src/excrypt_des.c
        src/excrypt_des.h
        src/excrypt_des_data.h
        src/excrypt_ecc.c
        src/excrypt_ecc.h
        src/excrypt_md5.c
        src/excrypt_md5.h
        src/excrypt_mem.cpp
        src/excrypt_mem.h
        src/excrypt_parve.c
        src/excrypt_parve.h
        src/excrypt_rc4.c
        src/excrypt_rc4.h
        src/excrypt_rotsum.c
        src/excrypt_rotsum.h
        src/excrypt_sha.c
        src/excrypt_sha.h
        src/excrypt_sha2.c
        src/excrypt_sha2.h
        src/exkeys.cpp
        src/exkeys.h
        src/fp61.hpp
        src/rijndael.c
        src/rijndael.h)

target_include_directories(ExCrypt PUBLIC src)

target_compile_features(ExCrypt PUBLIC c_std_11 cxx_std_17)

set_target_properties(ExCrypt PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Enable AES-NI and SSE4.1 flags for excrypt_aes.c
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64|i[3-6]86"))
    set_source_files_properties(src/excrypt_aes.c PROPERTIES COMPILE_OPTIONS "-maes;-msse4.1")
endif()

if(WIN32)
    target_link_libraries(ExCrypt PUBLIC bcrypt)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
