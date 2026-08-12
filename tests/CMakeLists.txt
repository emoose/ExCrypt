cmake_minimum_required(VERSION 3.16)


add_executable(ExCryptTests
            common.c
            tests.c
            test_aes.c
            test_sha.c
            test_rc4.c
            tests.h)

target_link_libraries(ExCryptTests PRIVATE ExCrypt)
add_test(NAME ExCryptTests COMMAND ExCryptTests)