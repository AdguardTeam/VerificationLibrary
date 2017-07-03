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

#ifndef CERTIFICATE_VERIFIER_AGHPKPINFO_H
#define CERTIFICATE_VERIFIER_AGHPKPINFO_H

#include <set>
#include <string>
#include <openssl/x509v3.h>

struct AGHPKPInfo {
    /*
     * According to RFC, Public key pins may contains pins for public key hash of any certificate in chain.
     * Valid pin must contain public key pin for current chain and at least one pin not in current chain
     * (it must be backup key). Note that CRLs uses SPKI hash but HPKP uses public key hash.
     * The difference is that SPKI is DER encoded and signed, and public key is raw data.
     */
    std::string hostName;
    std::set<std::string> pkPins;
    long expirationDate;
    bool includeSubDomains;

    AGHPKPInfo() : expirationDate(0) {}

    AGHPKPInfo(const std::string &headerValue);

    void parseHeader(const std::string &headerValue);

    void parseDirective(const std::string &directive);

    bool hasPinsInChain(STACK_OF(X509) *certChain) const;

    bool hasPinsNotInChain(STACK_OF(X509) *certChain) const;

    bool expired() const;

    bool isValid() const;
};

#endif //CERTIFICATE_VERIFIER_AGHPKPINFO_H
