/*
 * This file is part of Adguard certificate verification library
 * (http://github.com/AdguardTeam/VerificationLibrary)
 *
 * Copyright 2017 Adguard Software Ltd.
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
#include "../src/AGStringUtils.h"

#if __linux__
extern "C" {
extern char _binary_AGCertificateVerifierTestCrlSet_bin_start;
extern char _binary_AGCertificateVerifierTestCrlSet_bin_size;
extern char _binary_AGCertificateVerifierTestCrlSet_bin_end;
}
#endif

struct TestParam {
    std::string hostName;
    AGVerifyResult result;
};

TestParam tests[] = {
        {"www.google.com", AGVerifyResult::OK},
        {"badssl.com", AGVerifyResult::OK},
        {"twitter.com", AGVerifyResult::OK},
        {"expired.badssl.com", AGVerifyResult::EXPIRED},
        {"wrong.host.badssl.com", AGVerifyResult::HOST_NAME_MISMATCH},
        {"self-signed.badssl.com", AGVerifyResult::SELF_SIGNED},
        {"untrusted-root.badssl.com", AGVerifyResult::INVALID_CHAIN},
#if __linux__
        {"revoked.badssl.com", AGVerifyResult::REVOKED_CRLSETS},
#endif
        {"sha1-intermediate.badssl.com", AGVerifyResult::SIGNED_WITH_SHA1},
        {"pinning-test.badssl.com", AGVerifyResult::PINNING_ERROR},
};

class AGCertificateVerifierTestForHost : public ::testing::TestWithParam<TestParam> {

protected:
    virtual void SetUp() {
        char dirNameTemp[256] = "/tmp/verifier-test.XXXXXX";
        dirName = mktemp(dirNameTemp);
        mkdir(dirName.c_str(), 0755);
        storage = new AGSimpleDirectoryStorage(dirName);
    }

    virtual void TearDown() {
        delete storage;
        unlink((dirName + "/crl-set.bin").c_str());
        unlink((dirName + "/hpkp-info.bin").c_str());
        rmdir(dirName.c_str());
    }

    std::string dirName;
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
#if __linux__
    verifier.updateCRLSets(&_binary_AGCertificateVerifierTestCrlSet_bin_start,
                           &_binary_AGCertificateVerifierTestCrlSet_bin_end - &_binary_AGCertificateVerifierTestCrlSet_bin_start);
#endif
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
        {"revoked.grc.com", AGVerifyResult::REVOKED_OCSP},
};

class AGCertificateVerifierTestOcspForHost : public ::testing::TestWithParam<TestParam> {

protected:
    virtual void SetUp() {
        char dirNameTemp[256] = "/tmp/verifier-test.XXXXXX";
        dirName = mktemp(dirNameTemp);
        mkdir(dirName.c_str(), 0755);
        storage = new AGSimpleDirectoryStorage(dirName);
    }

    virtual void TearDown() {
        delete storage;
        unlink((dirName + "/crl-set.bin").c_str());
        unlink((dirName + "/hpkp-info.bin").c_str());
        rmdir(dirName.c_str());
    }

    std::string dirName;
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

class AGHPKPTest : public testing::Test {

protected:
    virtual void SetUp() {
        char dirNameTemp[256] = "/tmp/verifier-test.XXXXXX";
        dirName = mktemp(dirNameTemp);
        mkdir(dirName.c_str(), 0755);
        storage = new AGSimpleDirectoryStorage(dirName);
    }

    virtual void TearDown() {
        delete storage;
        unlink((dirName + "/crl-set.bin").c_str());
        unlink((dirName + "/hpkp-info.bin").c_str());
        rmdir(dirName.c_str());
    }

    std::string dirName;
    AGDataStorage *storage;
};

TEST_F(AGHPKPTest, TestHPKPPin) {

    std::string hostName1 = "projects.dm.id.lv";
    std::string hostName2 = "pkptest.projects.dm.id.lv";

    SSL_library_init();

    SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
    ASSERT_TRUE(ctx != NULL);

    SSL_CTX_set_default_verify_paths(ctx);

    BIO *web = BIO_new_ssl_connect(ctx);
    ASSERT_TRUE(web != NULL);

    long res = BIO_set_conn_hostname(web, (hostName1 + ":443").c_str());
    ASSERT_TRUE(res == 1);

    SSL *ssl;
    BIO_get_ssl(web, &ssl);
    ASSERT_TRUE(ssl != NULL);

    res = SSL_set_tlsext_host_name(ssl, hostName1.c_str());
    ASSERT_TRUE(res == 1);

    res = BIO_do_handshake(web);
    ASSERT_TRUE(res == 1);

    AGCertificateVerifier verifier = AGCertificateVerifier(storage);

    std::string request = "GET / HTTP/1.1\r\nHost: " + hostName1 + "\r\n\r\n";
    res = BIO_write(web, request.c_str(), (int) request.size());
    ASSERT_TRUE(res == request.size());

    char response[1024];
    int r = BIO_read(web, response, sizeof(response));
    std::string responseData(response, r);
    std::vector<std::string> responseStrings = AGStringUtils::split(responseData, "\r\n");
    for (std::vector<std::string>::const_iterator i = responseStrings.begin(); i != responseStrings.end(); i++) {
        const std::string &responseString = *i;
        if (AGStringUtils::toLower(responseString).find("public-key-pins") != std::string::npos) {
            unsigned long pos = responseString.find(":");
            if (pos == std::string::npos) {
                continue;
            }
            std::string header = responseString.substr(0, pos - 1);
            std::string value = responseString.substr(pos + 1);
            verifier.updateHPKPInfo(hostName1, SSL_get_peer_cert_chain(ssl), header, value);
        }
    }


    BIO_free_all(web);

    web = BIO_new_ssl_connect(ctx);
    ASSERT_TRUE(web != NULL);

    res = BIO_set_conn_hostname(web, (hostName2 + ":443").c_str());
    ASSERT_TRUE(res == 1);

    BIO_get_ssl(web, &ssl);
    ASSERT_TRUE(ssl != NULL);

    res = SSL_set_tlsext_host_name(ssl, hostName2.c_str());
    ASSERT_TRUE(res == 1);

    res = BIO_do_handshake(web);
    ASSERT_TRUE(res == 1);

    AGVerifyResult result = verifier.verify(hostName2, SSL_get_peer_cert_chain(ssl));
    std::cout << "Result: " << result << std::endl;
    ASSERT_TRUE(result.result == AGVerifyResult::PINNING_ERROR);

    if(web != NULL)
        BIO_free_all(web);

    if(NULL != ctx)
        SSL_CTX_free(ctx);
}
