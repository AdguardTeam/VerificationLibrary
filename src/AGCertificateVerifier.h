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

#ifndef AGCERTIFICATEVERIFIER_H
#define AGCERTIFICATEVERIFIER_H

#include <string>
#include <set>
#include <map>
#include <openssl/x509v3.h>
#include <openssl/ocsp.h>
#include "AGHPKPInfo.h"
#include "AGDataStorage.h"

struct AGVerifyResult {

    enum AGVerifyResultType {
        /**
         * Cerification check is passed
         */
        OK = 0,
        /**
         * Verifier was not properly initialized
         */
        VERIFIER_NOT_INITIALIZED = 1,
        /**
         * Out of memory error
         */
        OUT_OF_MEMORY = 2,
        /**
         * Host name does not match hostname is certificate
         */
        HOST_NAME_MISMATCH = 3,
        /**
         * Certificate is not yet valid
         */
        NOT_YET_VALID = 4,
        /**
         * Certificate is expired
         */
        EXPIRED = 5,
        /**
         * Certificate is self-signed
         */
        SELF_SIGNED = 6,
        /**
         * Provided chain is invalid
         */
        INVALID_CHAIN = 7,
        /**
         * Certificate is revoked (found in CRLSets)
         */
        REVOKED_CRLSETS = 8,
        /**
         * Certificate is revoked (by info from issuer's OCSP server)
         */
        REVOKED_OCSP = 9,
        /**
         * Certificate uses SHA1 signature
         */
        SIGNED_WITH_SHA1 = 10,
        /**
         * Certificate chain contains one of CAs that is no longer trusted by major web browsers
         */
        BLACKLISTED_ROOT = 11,
        /**
         * HTTP public key pin exists for this site but provided chain does not contain any of pinned public keys.
         */
        PINNING_ERROR = 12,
        /**
         * OCSP request failed
         */
        OCSP_INVALID_RESPONSE = 13,
        /**
         * OCSP request failed
         */
        OCSP_REQUEST_FAILED = 14,
    };

    AGVerifyResultType result;
    std::string errorString;

    AGVerifyResult(AGVerifyResultType _result, const std::string &_errorString)
        : result(_result), errorString(_errorString) {}
    AGVerifyResult(AGVerifyResultType _result) : result(_result) {}
    AGVerifyResult() : result(OK) {}

    bool isOk() {
        return result == OK;
    }

    inline bool operator==(const AGVerifyResult &other) const {
        return other.result == result;
    }

    friend std::ostream& operator<<(std::ostream& stream, const AGVerifyResult& result) {
        switch (result.result) {
            case OK:
                return stream << std::string("OK");
            case VERIFIER_NOT_INITIALIZED:
                return stream << std::string("VERIFIER_NOT_INITIALIZED: ") << result.errorString;
            case OUT_OF_MEMORY:
                return stream << std::string("OUT_OF_MEMORY: ") << result.errorString;
            case HOST_NAME_MISMATCH:
                return stream << std::string("HOST_NAME_MISMATCH: ") << result.errorString;
            case NOT_YET_VALID:
                return stream << std::string("NOT_YET_VALID: ") << result.errorString;
            case EXPIRED:
                return stream << std::string("EXPIRED: ") << result.errorString;
            case REVOKED_CRLSETS:
                return stream << std::string("REVOKED_CRLSETS: ") << result.errorString;
            case REVOKED_OCSP:
                return stream << std::string("REVOKED_OCSP: ") << result.errorString;
            case SELF_SIGNED:
                return stream << std::string("SELF_SIGNED: ") << result.errorString;
            case INVALID_CHAIN:
                return stream << std::string("INVALID_CHAIN: ") << result.errorString;
            case SIGNED_WITH_SHA1:
                return stream << std::string("SIGNED_WITH_SHA1: ") << result.errorString;
            case BLACKLISTED_ROOT:
                return stream << std::string("BLACKLISTED_ROOT: ") << result.errorString;
            case PINNING_ERROR:
                return stream << std::string("PINNING_ERROR: ") << result.errorString;
            case OCSP_INVALID_RESPONSE:
                return stream << std::string("OCSP_INVALID_RESPONSE: ") << result.errorString;
            case OCSP_REQUEST_FAILED:
                return stream << std::string("OCSP_REQUEST_FAILED: ") << result.errorString;
        }
        return stream;
    }
};

/**
 * Adguard certificate verifier for HTTPS interception.
 */
class AGCertificateVerifier {
public:

    /**
     * Create Adguard certificate verifier
     * @param storage Verifier storage implementation
     */
    AGCertificateVerifier(AGDataStorage *storage);

    virtual ~AGCertificateVerifier();

    /**
     * Verify specified certificate chain
     * @param dnsName Host name
     * @param certChain Certificate chain
     * @return Verify result
     */
    AGVerifyResult verify(const std::string &dnsName, STACK_OF(X509) *certChain);

    /**
     * Set CA store of verifier to specified certificate list
     * @param certList Certificate list
     */
    void setCAStore(STACK_OF(X509) *certList);

    /**
     * Set CA store of verifier to specified certificate store
     * @param certStore Certificate store
     */
    void setCAStore(X509_STORE *store);

    // Persistent storage operations

    /**
     * Save CRLSets CRX file to verifier storage.
     *
     * CRLSets are used for certificate revocation checks.
     *
     * CRLSets CRX file is CRX (Chromium extension) containing file named "crl-set".
     * CRX file format: https://developer.chrome.com/extensions/crx
     * CRLSets file format: https://chromium.googlesource.com/experimental/chromium/src/+/master/net/cert/crl_set_storage.cc
     *
     * You may get CRLSets generated by Google Inc.:
     * - CRLSets CRX extension id: hfnkpimlhhgieaddgfemjhofmfblmnib
     * - CRLSets CRX download URL: http://clients2.google.com/service/update2/crx?response=redirect&x=id%3Dhfnkpimlhhgieaddgfemjhofmfblmnib%26v=%26uc
     * or use your own set (properly encoded).
     *
     * @param crlSetCrxContent CRLSets CRX file content
     * @param crlSetCrxLen CRLSets CRX file length
     */
    void updateCRLSets(const char *crlSetCrxContent, size_t crlSetCrxLen);

    /**
     * Add HTTP public key pinning info (HPKP) from HTTP header.
     *
     * This method should be called by HTTP client while processing HTTP response, when
     * there is an HTTP header "Public-Key-Pins" or "Public-Key-Pins-Report-Only".
     *
     * This information may after be used by verify() method to perform key pinning checks.
     *
     * Links with info about how HPKP works:
     * https://en.wikipedia.org/wiki/HTTP_Public_Key_Pinning
     * https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning
     *
     * @param dnsName Host name
     * @param certChain Certificate chain
     * @param httpHeaderName HTTP header name
     * @param httpHeaderValue HTTP header value
     */
    void updateHPKPInfo(const std::string &dnsName, STACK_OF(X509) *certChain, const std::string &httpHeaderName, const std::string &httpHeaderValue);

    // OCSP checks

    /**
     * Verify OCSP response for leaf certificate OCSP check (OpenSSL OCSP_RESPONSE structure).
     *
     * This method may be used to verify stapled OCSP response.
     *
     * Full certificate chain is needed to check OCSP response signature.
     *
     * @param dnsName Host name
     * @param certChain Certificate chain
     * @param response
     * @return
     */
    AGVerifyResult verifyOCSPResponse(const std::string &dnsName, STACK_OF(X509) *certChain, OCSP_RESPONSE *response);

    /**
     * Perform an OCSP request for leaf certificate and verify its result.
     *
     * Full certificate chain is needed to check OCSP response signature.
     */
    AGVerifyResult verifyOCSP(const std::string &dnsName, STACK_OF(X509) *certChain);
private:
    // System CA store
    X509_STORE *caStore;
    // Mozilla CA store (used for disabling HPKP checks if there is local (user-added) root certificate in chain)
    X509_STORE *mozillaCaStore;
    // Mozilla Untrusted CAs store (used to check against CAs that no longer trusted by major web browsers)
    X509_STORE *mozillaUntrustedCaStore;
    // CRLSet digest list
    std::set<std::string> revokedSHADigests;
    // CRLSet map of CRLs
    std::map<std::string, std::set<std::string> > issuerSHADigestToCRL;
    // Data storage
    AGDataStorage *storage;
    // Dynamic HPKP info
    std::map<std::string, AGHPKPInfo> dynamicHPKPInfo;
    // Static HPKP info
    std::map<std::string, AGHPKPInfo> staticHPKPInfo;

    void load();

    void loadStaticHPKPInfo();

    void loadDynamicHPKPInfo();

    void loadCRLSets();

    void loadMozillaCAStore();

    void clearCAStore();

    AGVerifyResult verifyDNSName(const std::string &dnsName, STACK_OF(X509) *certChain);

    AGVerifyResult verifyChain(X509_STORE *store, STACK_OF(X509) *certChain,
                               const std::string &dnsName, bool basicCheckOnly);

    AGVerifyResult verifyHttpPublicKeyPins(const std::string &dnsName, X509_STORE_CTX *ctx);

    AGVerifyResult verifyCrlSetsStatus(STACK_OF(X509) *certChain);

    AGVerifyResult verifyUntrustedAuthority(STACK_OF(X509) *certChain);

    AGVerifyResult verifyDeprecatedSha1Signature(X509_STORE_CTX *ctx);

    void saveDynamicHPKPInfo();

    AGVerifyResult doOCSPRequest(char *url, const std::string &dnsName, STACK_OF(X509) *certChain);
};

#endif // AGCERTIFICATEVERIFIER_H
