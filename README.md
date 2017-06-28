# Certificate Verification Library

This repository contains verification library with support of CRLSets, HPKP, OCSP and SHA1 deprecation checks.

## Library interface

#### Initialization

```c++
AGCertificateVerifier::AGCertificateVerifier(AGDataStorage *storage);
```
It is strongly recommended to implement your own AGDataStorage. However, there is AGSimpleDirectoryStorage - a simple, readable by everyone, directory-based implementation for testing purposes.

```c++
void AGCertificateVerifier::setLocalCAStore(STACK_OF(X509) *certList);
void AGCertificateVerifier::setLocalCAStore(X509_STORE *store);
```

#### Update CRL sets file

```c++
void AGCertificateVerifier::updateCRLSets(const char *crlSetCrx, size_t crlSetCrxLen);
```

#### Update HPKP info

```c++
void AGCertificateVerifier::updateHPKPInfo(
        const std::string &dnsName, STACK_OF(X509) *certChain, 
        const std::string &httpHeaderName, const std::string &httpHeaderValue);
```

#### Verification methods

```c++
AGVerifyResult AGCertificateVerifier::verify(const std::string &dnsName, STACK_OF(X509) *certChain);
```

```c++
AGVerifyResult AGCertificateVerifier::verifyOCSP(
        const std::string &dnsName, STACK_OF(X509) *certChain);
```

```c++
AGVerifyResult AGCertificateVerifier::verifyOCSPResponse(
        const std::string &dnsName, STACK_OF(X509) *certChain, OCSP_RESPONSE *ocspResponse);
```
