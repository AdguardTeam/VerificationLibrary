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

#include <ctime>
#include <openssl/x509v3.h>
#include <jsmn.h>
#include "AGHPKPInfo.h"
#include "AGStringUtils.h"

typedef std::vector<std::string> StrList;

AGHPKPInfo::AGHPKPInfo(const std::string &hostName, const std::string &headerValue)
        : hostName(hostName)
{
    parseHeader(headerValue);
}

void AGHPKPInfo::parseHeader(const std::string &headerValue) {
    StrList directives = AGStringUtils::split(headerValue, ";");
    for (StrList::const_iterator i = directives.begin(); i != directives.end(); i++) {
        const std::string &directive = AGStringUtils::trim(*i);
        parseDirective(directive);
    }
}

void AGHPKPInfo::parseDirective(const std::string &directive) {
    size_t pos = directive.find_first_of("=");
    std::string name = AGStringUtils::toLower(directive.substr(0, pos));
    std::string value = pos != std::string::npos ? directive.substr(pos + 1) : "";
    value = AGStringUtils::trim(value);
    if (value.size() >= 2 && value[0] == '"') {
        if (value[value.size() - 1] == '"') {
            value = value.substr(1, value.size() - 2);
        } else {
            return; // invalid token, ignoring
        }
    }
    if (name.size() > 4 && name.substr(0, 4) == "pin-") {
        pkPins.insert(value);
    } else if (name == "max-age") {
        expirationDate = std::time(NULL);
        long seconds;
        std::istringstream in(value);
        in >> seconds;
        if (!in.fail()) {
            expirationDate += seconds;
        }
    } else if (name == "includesubdomains") {
        includeSubDomains = true;
    }
}

bool AGHPKPInfo::hasPinsInChain(STACK_OF(X509) *certChain) const {
    int num = sk_X509_num(certChain);
    for (int i = 0; i < num; i++) {
        X509 *cert = sk_X509_value(certChain, i);
        uint8_t hash[32];
        uint32_t hash_len;
        ASN1_item_digest(ASN1_ITEM_rptr(X509_PUBKEY), EVP_sha256(), X509_get_X509_PUBKEY(cert), hash, &hash_len);
        std::string spkiHash = AGStringUtils::encodeToBase64(hash, hash_len);
        if (pkPins.count(spkiHash)) {
            return true;
        }
    }
    return false;
}

bool AGHPKPInfo::hasPinsNotInChain(STACK_OF(X509) *certChain) const {
    std::set<std::string> list(pkPins);
    int num = sk_X509_num(certChain);
    for (int i = 0; i < num; i++) {
        X509 *cert = sk_X509_value(certChain, i);
        uint8_t hash[32];
        uint32_t hash_len;
        ASN1_item_digest(ASN1_ITEM_rptr(X509_PUBKEY), EVP_sha256(), X509_get_X509_PUBKEY(cert), hash, &hash_len);
        list.erase(AGStringUtils::encodeToBase64(hash, hash_len));
    }
    return list.size() > 0;
}

bool AGHPKPInfo::expired() const {
    return std::time(0) > expirationDate;
}

bool AGHPKPInfo::isValid() const {
    return !expired() && pkPins.size() >= 2;
}
