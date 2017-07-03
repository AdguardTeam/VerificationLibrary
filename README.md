# Certificate Verification Library

[![Build Status](https://travis-ci.org/AdguardTeam/VerificationLibrary.svg?branch=master)](https://travis-ci.org/AdguardTeam/VerificationLibrary)

This repository contains verification library with support of CRLSets, HPKP, OCSP and SHA1 deprecation checks.

## Using library

### Build library and run tests
```bash
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ..
cmake --build .
# Run googletest
test/test_verifier
```

### Library interface

#### Example of usage
```c++
#include <AGCertificateVerifier.h>

void f() {
    AGStorage *storage = AGSimpleDirectoryStorage("./data");
    AGCertificateVerifier verifier(storage);
    ...
    // Connect to TLS server here
    ...
    STACK_OF(X509) *certChain = SSL_get_peer_cert_chain();
    AGVerifierResult result = verifier.verify("google.com", certChain);
    if (result != OK) {
        std::clog << result << std::endl;
        abort();
    }
}
```

#### Initialization
Verifier is initialized by the following constructor:
```c++
AGCertificateVerifier::AGCertificateVerifier(AGDataStorage *storage);
```
It is strongly recommended to implement your own AGDataStorage. However, there is AGSimpleDirectoryStorage - a simple, readable by everyone, directory-based implementation for testing purposes.

After verifier is open, CA store must be set by one of the following methods.
If OpenSSL can read CA certificates from default paths, this step is unneeded.
```c++
void AGCertificateVerifier::setCAStore(STACK_OF(X509) *certList);
void AGCertificateVerifier::setCAStore(X509_STORE *store);
```

#### Update CRL sets file
From time to time, CRL sets must be downloaded and updated. You can get download URL in documentation for this method.
```c++
void AGCertificateVerifier::updateCRLSets(const char *crlSetCrx, size_t crlSetCrxLen);
```

#### Update HPKP info
The following method is called when HTTP response is received. It updates internal HPKP info cache.
```c++
void AGCertificateVerifier::updateHPKPInfo(
        const std::string &dnsName, STACK_OF(X509) *certChain, 
        const std::string &httpHeaderName, const std::string &httpHeaderValue);
```

#### Verification methods
Finally, there are three methods for certificate verification:

```c++
AGVerifyResult AGCertificateVerifier::verify(const std::string &dnsName, STACK_OF(X509) *certChain);
```
This method performs all checks on certification chain except OCSP check.

```c++
AGVerifyResult AGCertificateVerifier::verifyOCSP(
        const std::string &dnsName, STACK_OF(X509) *certChain);
```
This method performs OCSP request.
```c++
AGVerifyResult AGCertificateVerifier::verifyOCSPResponse(
        const std::string &dnsName, STACK_OF(X509) *certChain, OCSP_RESPONSE *ocspResponse);
```
This method performs OCSP stapled response check.

Example for getting OCSP stapled response in OpenSSL code:
```c++
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

void codeThatConnectsToSslServer() {
...
    OCSP_RESPONSE *ocspResponse = NULL;
    SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);
    SSL_CTX_set_tlsext_status_cb(ctx, get_ocsp_response);
    SSL_CTX_set_tlsext_status_arg(ctx, &ocspResponse);
...
    BIO_do_handshake();
...
    if (ocspResponse != NULL) {
        AGVerifyResult res = verifier.verifyOCSPResponse(hostName, certChain, ocspResponse);
        ...
    }
}
```
