cmake_minimum_required(VERSION 3.1)
project(certificate_verifier)

set(CMAKE_CXX_STANDARD 98)

# Require OpenSSL 1.0.2 or higher
find_package(OpenSSL REQUIRED)
if(${OPENSSL_VERSION} VERSION_LESS "1.0.2")
message(FATAL_ERROR "OpenSSL 1.0.2 or higher is required")
endif()

# Third party libraries
set(JSMN_DIR third-party/jsmn-c772a0e)
set(MINIZ_DIR third-party/miniz-2.0.5)
set(THIRD_PARTY_FILES
        ${JSMN_DIR}/jsmn.h
        ${JSMN_DIR}/jsmn.c
        ${MINIZ_DIR}/miniz.h
        ${MINIZ_DIR}/miniz.c)

set(SOURCE_FILES
        src/AGCertificateVerifier.h
        src/AGCertificateVerifier.cpp
        src/AGCertificateVerifierStaticData.cpp
        src/AGHPKPInfo.h
        src/AGHPKPInfo.cpp
        src/AGStringUtils.h
        src/AGJsonUtils.h
        src/AGX509StoreUtils.h
        src/AGDataStorage.h
        src/AGDataStorage.cpp)

add_library(certificate_verifier STATIC ${THIRD_PARTY_FILES} ${SOURCE_FILES})
if(UNIX)
    set_source_files_properties(${THIRD_PARTY_FILES} COMPILE_FLAGS "-fvisibility=hidden")
endif(UNIX)
target_include_directories(certificate_verifier PRIVATE ${OPENSSL_INCLUDE_DIR})
target_include_directories(certificate_verifier PRIVATE ${JSMN_DIR})
target_include_directories(certificate_verifier PRIVATE ${MINIZ_DIR})
target_link_libraries(certificate_verifier ${OPENSSL_LIBRARIES})

add_subdirectory(third-party/googletest-1.8.0)

enable_testing()
add_subdirectory(test)
