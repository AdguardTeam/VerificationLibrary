/*
 * This file is part of Adguard certificate verification library
 * (http://github.com/AdguardTeam/VerificationLibrary)
 *
 * Copyright 2017 Performix LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include "../src/AGCertificateVerifier.h"

extern "C" {
extern char _binary_AGCertificateVerifierTestCrlSet_bin_start;
extern char _binary_AGCertificateVerifierTestCrlSet_bin_size;
extern char _binary_AGCertificateVerifierTestCrlSet_bin_end;
}

struct TestParam {
    std::string hostName;
    AGVerifyResult result;
};

TestParam tests[] = {
        {"www.google.com", AGVerifyResult::OK},
        {"badssl.com", AGVerifyResult::OK},
        {"expired.badssl.com", AGVerifyResult::EXPIRED},
        {"wrong.host.badssl.com", AGVerifyResult::HOST_NAME_MISMATCH},
        {"self-signed.badssl.com", AGVerifyResult::SELF_SIGNED},
        {"untrusted-root.badssl.com", AGVerifyResult::INVALID_CHAIN},
        {"revoked.badssl.com", AGVerifyResult::REVOKED},
        {"sha1-intermediate.badssl.com", AGVerifyResult::WEAK_HASH},
        {"pinning-test.badssl.com", AGVerifyResult::PINNING_ERROR},
};

class AGCertificateVerifierTestForHost : public ::testing::TestWithParam<TestParam> {

protected:
    virtual void SetUp() {
        storage = new AGSimpleDirectoryStorage("/tmp");
    }

    virtual void TearDown() {
        delete storage;
    }

    AGDataStorage *storage;
};

TEST_P(AGCertificateVerifierTestForHost, testHost) {
    const TestParam &test = GetParam();
    std::cout << "Testing host " << test.hostName << std::endl;

    long res;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;

    SSL_library_init();

    const SSL_METHOD* method = SSLv23_method();
    ASSERT_TRUE(NULL != method);

    ctx = SSL_CTX_new(method);
    ASSERT_TRUE(ctx != NULL);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL_CTX_set_verify_depth(ctx, 4);

    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);

    res = SSL_CTX_set_default_verify_paths(ctx);
    ASSERT_TRUE(res == 1);

    web = BIO_new_ssl_connect(ctx);
    ASSERT_TRUE(web != NULL);

    res = BIO_set_conn_hostname(web, (test.hostName + ":443").c_str());
    ASSERT_TRUE(res == 1);

    BIO_get_ssl(web, &ssl);
    ASSERT_TRUE(ssl != NULL);

    const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    ASSERT_TRUE(res == 1);

    res = SSL_set_tlsext_host_name(ssl, test.hostName.c_str());
    ASSERT_TRUE(res == 1);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    ASSERT_TRUE(NULL != out);

    res = BIO_do_connect(web);
    ASSERT_TRUE(res == 1);

    res = BIO_do_handshake(web);
    ASSERT_TRUE(res == 1);

    X509* cert = SSL_get_peer_certificate(ssl);
    ASSERT_FALSE(NULL == cert);

    char buf[1024] = {0};
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, buf, sizeof(buf));
    std::cout << "Peer cert: " << buf << std::endl;
    if (cert) {
        X509_free(cert);
    }

    AGCertificateVerifier verifier(storage);
    verifier.updateCRLSets(&_binary_AGCertificateVerifierTestCrlSet_bin_start,
                           &_binary_AGCertificateVerifierTestCrlSet_bin_end - &_binary_AGCertificateVerifierTestCrlSet_bin_start);
    AGVerifyResult result = verifier.verify(test.hostName, SSL_get_peer_cert_chain(ssl));
    std::cout << "Result: " << result << std::endl;
    ASSERT_TRUE(result == test.result);

    if(out)
        BIO_free(out);

    if(web != NULL)
        BIO_free_all(web);

    if(NULL != ctx)
        SSL_CTX_free(ctx);
}

INSTANTIATE_TEST_CASE_P(MainTests, AGCertificateVerifierTestForHost, ::testing::ValuesIn(tests));

int get_ocsp_response(SSL *ssl, void *arg) {
    const unsigned char *ocsp_response;
    long len = SSL_get_tlsext_status_ocsp_resp(ssl, &ocsp_response);
    if (len >= 0) {
        d2i_OCSP_RESPONSE((OCSP_RESPONSE **) arg, &ocsp_response, len);
    } else {
        *(OCSP_RESPONSE **)arg = NULL;
    }
    return 1;
}

TestParam ocspReqTests[] = {
        {"www.yahoo.com", AGVerifyResult::OK},
        {"revoked.grc.com", AGVerifyResult::REVOKED},
};

class AGCertificateVerifierTestOcspForHost : public ::testing::TestWithParam<TestParam> {

protected:
    virtual void SetUp() {
        storage = new AGSimpleDirectoryStorage("/tmp");
    }

    virtual void TearDown() {
        delete storage;
    }

    AGDataStorage *storage;
};

TEST_P(AGCertificateVerifierTestOcspForHost, testOCSPRequest) {
    const TestParam &test = GetParam();
    std::cout << "Testing host " << test.hostName << std::endl;

    long res;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;

    SSL_library_init();

    const SSL_METHOD* method = SSLv23_method();
    ASSERT_TRUE(NULL != method);

    ctx = SSL_CTX_new(method);
    ASSERT_TRUE(ctx != NULL);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    SSL_CTX_set_verify_depth(ctx, 4);

    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);

    res = SSL_CTX_set_default_verify_paths(ctx);
    ASSERT_TRUE(res == 1);

    web = BIO_new_ssl_connect(ctx);
    ASSERT_TRUE(web != NULL);

    res = BIO_set_conn_hostname(web, (test.hostName + ":443").c_str());
    ASSERT_TRUE(res == 1);

    BIO_get_ssl(web, &ssl);
    ASSERT_TRUE(ssl != NULL);

    const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    ASSERT_TRUE(res == 1);

    res = SSL_set_tlsext_host_name(ssl, test.hostName.c_str());
    ASSERT_TRUE(res == 1);

    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    ASSERT_TRUE(NULL != out);

    OCSP_RESPONSE *ocsp_response = NULL;
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ctx, get_ocsp_response);
    SSL_CTX_set_tlsext_status_arg(ctx, &ocsp_response);

    res = BIO_do_connect(web);
    ASSERT_TRUE(res == 1);

    res = BIO_do_handshake(web);
    ASSERT_TRUE(res == 1);

    X509* cert = SSL_get_peer_certificate(ssl);
    ASSERT_FALSE(NULL == cert);

    char buf[1024] = {0};
    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, buf, sizeof(buf));
    std::cout << "Peer cert: " << buf << std::endl;
    if (cert) {
        X509_free(cert);
    }

    AGCertificateVerifier verifier(storage);
    {
        ASSERT_TRUE(ocsp_response != NULL);
        AGVerifyResult result = verifier.verifyOCSPResponse(test.hostName, SSL_get_peer_cert_chain(ssl), ocsp_response);
        OCSP_RESPONSE_free(ocsp_response);
        std::cout << "OCSP stapled response check result: " << result << std::endl;
        ASSERT_TRUE(result == test.result);
    }
    {
        AGVerifyResult result = verifier.verifyOCSP(test.hostName, SSL_get_peer_cert_chain(ssl));
        std::cout << "OCSP request result: " << result << std::endl;
        ASSERT_TRUE(result == test.result);
    }

    if(out)
        BIO_free(out);

    if(web != NULL)
        BIO_free_all(web);

    if(NULL != ctx)
        SSL_CTX_free(ctx);
}

INSTANTIATE_TEST_CASE_P(OCSP, AGCertificateVerifierTestOcspForHost, ::testing::ValuesIn(ocspReqTests));
