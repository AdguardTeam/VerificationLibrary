/*
 * This file is part of Adguard certificate verification library
 * (http://github.com/AdguardTeam/Verification)
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
        OK = 0,
        INVALID_CONFIGURATION,
        HOST_NAME_MISMATCH,
        NOT_YET_VALID,
        EXPIRED,
        REVOKED,
        SELF_SIGNED,
        INVALID_CHAIN,
        WEAK_HASH,
        BLACKLISTED_ROOT,
        PINNING_ERROR,
        OCSP_FAIL,
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
            case INVALID_CONFIGURATION:
                return stream << std::string("INVALID_CONFIGURATION: ") << result.errorString;
            case HOST_NAME_MISMATCH:
                return stream << std::string("HOST_NAME_MISMATCH: ") << result.errorString;
            case NOT_YET_VALID:
                return stream << std::string("NOT_YET_VALID: ") << result.errorString;
            case EXPIRED:
                return stream << std::string("EXPIRED: ") << result.errorString;
            case REVOKED:
                return stream << std::string("REVOKED: ") << result.errorString;
            case SELF_SIGNED:
                return stream << std::string("SELF_SIGNED: ") << result.errorString;
            case INVALID_CHAIN:
                return stream << std::string("INVALID_CHAIN: ") << result.errorString;
            case WEAK_HASH:
                return stream << std::string("WEAK_HASH: ") << result.errorString;
            case BLACKLISTED_ROOT:
                return stream << std::string("BLACKLISTED_ROOT: ") << result.errorString;
            case PINNING_ERROR:
                return stream << std::string("PINNING_ERROR: ") << result.errorString;
            case OCSP_FAIL:
                return stream << std::string("OCSP_FAIL: ") << result.errorString;
        }
    }
};

/**
 * Adguard certificate verifier for HTTPS interception.
 */
class AGCertificateVerifier {
public:

    /**
     * Create certificate verifier with given storage path
     * @param storage Data storage
     */
    AGCertificateVerifier(AGDataStorage *storage);
    virtual ~AGCertificateVerifier();

    /**
     * Verify specified certificate chain
     * @param dnsName Host name
     * @param certChain Certificate chain
     * @return True if verified, false otherwise
     */
    AGVerifyResult verify(const std::string &dnsName, STACK_OF(X509) *certChain);

    /**
     * Set local CA store of verifier to specified certificate list
     * @param certList Certificate list
     */
    void setLocalCAStore(STACK_OF(X509) *certList);

    /**
     * Set local CA store of verifier to specified certificate store
     * @param certStore Certificate store
     */
    void setLocalCAStore(X509_STORE *store);

    // Persistent storage operations

    /**
     * Fetch current CA store currently used in SSL clients
     */
    void updateCurrentCAStore(){}

    /**
     * Fetch updated CRLSets Chromium extension file.
     */
    void updateCRLSets(const char *crlSetCrx, size_t crlSetCrxLen);

    /**
     * Fetch updated HPKP pins.
     */
    void updateStaticHPKPInfo(){}

    /**
     * Add HPKP info from HPKP HTTP header
     * @param dnsName Host name
     * @param certChain Certificate chain
     * @param header HTTP header name
     * @param value HTTP header value
     */
    void updateHPKPInfo(const std::string &dnsName, STACK_OF(X509) *certChain, const std::string &header, const std::string &value);

    AGVerifyResult verifyOCSPResponse(const std::string &dnsName, STACK_OF(X509) *certChain, OCSP_RESPONSE *response);

    AGVerifyResult verifyOCSP(const std::string &dnsName, STACK_OF(X509) *certChain);
private:
    // System CA store
    X509_STORE *caStore;
    // Mozilla CA store
    X509_STORE *mozillaCaStore;
    // Mozilla Untrusted CAs store
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

    STACK_OF(X509) *sortedCertificateChain(STACK_OF(X509) *certChain);

    AGVerifyResult verifyDNSName(const std::string &dnsName, STACK_OF(X509) *certChain);

    AGVerifyResult verifyBasic(X509_STORE *store, STACK_OF(X509) *certChain);

    AGVerifyResult verifyPins(const std::string &dnsName, STACK_OF(X509) *certChain);

    AGVerifyResult verifyRevocations(STACK_OF(X509) *certChain);

    AGVerifyResult verifyUntrustedAuthority(STACK_OF(X509) *certChain);

    AGVerifyResult verifyWeakHashAlgorithm(STACK_OF(X509) *certChain);

    void saveDynamicHPKPInfo();

    AGVerifyResult doOCSPRequest(char *url, const std::string &dnsName, STACK_OF(X509) *certChain);
};

#endif // AGCERTIFICATEVERIFIER_H
