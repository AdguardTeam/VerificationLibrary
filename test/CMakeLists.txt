cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 98)

link_libraries(certificate_verifier gtest_main ${OPENSSL_LIBRARIES})
include_directories(${OPENSSL_INCLUDE_DIR})

add_library(crl_set_blob STATIC "${CMAKE_CURRENT_BINARY_DIR}/crl-set.o")
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/crl-set.o" PROPERTIES EXTERNAL_OBJECT true GENERATED true)
set_target_properties(crl_set_blob PROPERTIES LINKER_LANGUAGE C)
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/crl-set.o"
        PRE_BUILD
        COMMAND wget -nv -O crl-set.bin "http://clients2.google.com/service/update2/crx?response=redirect\\&x=id%3Dhfnkpimlhhgieaddgfemjhofmfblmnib%26v=%26uc"
        COMMAND ld -r -b binary -o crl-set.o crl-set.bin
        COMMAND objcopy --rename-section .data=.rodata,alloc,load,readonly,data,contents crl-set.o crl-set.o
        WORKING_DIRECTORY ${CURRENT_CURRENT_BINARY_DIR})

add_executable(test_verifier AGCertificateVerifierTest.cpp)

target_link_libraries(test_verifier crl_set_blob)
add_test(test_verifier test_verifier)
