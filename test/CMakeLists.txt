cmake_minimum_required(VERSION 3.1)

set(CMAKE_CXX_STANDARD 98)

link_libraries(certificate_verifier gtest_main ${OPENSSL_LIBRARIES})
include_directories(${OPENSSL_INCLUDE_DIR})

add_executable(test_verifier AGCertificateVerifierTest.cpp)
if(UNIX AND NOT APPLE)
set(CRL_SET_OBJ "AGCertificateVerifierTestCrlSet.o")
set(CRL_SET_BIN "AGCertificateVerifierTestCrlSet.bin")
add_library(test_verifier_crl_set_blob STATIC "${CMAKE_CURRENT_BINARY_DIR}/${CRL_SET_OBJ}")
set_source_files_properties("${CMAKE_CURRENT_BINARY_DIR}/${CRL_SET_OBJ}" PROPERTIES EXTERNAL_OBJECT true GENERATED true)
set_target_properties(test_verifier_crl_set_blob PROPERTIES LINKER_LANGUAGE C)
add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${CRL_SET_OBJ}"
        PRE_BUILD
        COMMAND wget -nv -O "${CRL_SET_BIN}" "http://clients2.google.com/service/update2/crx?response=redirect\\&x=id%3Dhfnkpimlhhgieaddgfemjhofmfblmnib%26v=%26uc"
        COMMAND ld -r -b binary -o "${CRL_SET_OBJ}" "${CRL_SET_BIN}"
        COMMAND objcopy --rename-section .data=.rodata,alloc,load,readonly,data,contents "${CRL_SET_OBJ}" "${CRL_SET_OBJ}"
        WORKING_DIRECTORY ${CURRENT_CURRENT_BINARY_DIR})
target_link_libraries(test_verifier test_verifier_crl_set_blob)
endif()
add_test(test_verifier test_verifier)
