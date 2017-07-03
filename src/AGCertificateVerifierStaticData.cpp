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

#include "AGCertificateVerifier.h"

#include <stdint.h>
#include <stddef.h>
#include <iostream>

namespace mozilla {

    typedef uint64_t PRTime; // for #include <StaticHPKPins.h>

#include "mozilla/StaticHPKPins.h"
#include "mozilla/CACertificates.h"
#include "mozilla/CACertificatesUntrusted.h"

}

/**
 * Load static HPKP info from header
 */
void AGCertificateVerifier::loadStaticHPKPInfo() {
    int listLen = sizeof(mozilla::kPublicKeyPinningPreloadList) / sizeof(mozilla::kPublicKeyPinningPreloadList[0]);
    for (int i = 0; i < listLen; i++) {
        const mozilla::TransportSecurityPreload *mInfo = &mozilla::kPublicKeyPinningPreloadList[i];
        AGHPKPInfo &info = staticHPKPInfo[mInfo->mHost];
        info.hostName = mInfo->mHost;
        for (int j = 0; j < mInfo->pinset->size; j++) {
            info.pkPins.insert(mInfo->pinset->data[j]);
        }
        info.includeSubDomains = mInfo->mIncludeSubdomains;
        info.expirationDate = mozilla::kPreloadPKPinsExpirationTime / 1000;
    }
    /*
    for (std::map<std::string, AGHPKPInfo>::const_iterator it = staticHPKPInfo.begin(); it != staticHPKPInfo.end(); it++) {
        std::clog << it->second.serialize() << std::endl;
    }*/
}

/**
 * Load Mozilla CA store from header
 */
void AGCertificateVerifier::loadMozillaCAStore() {
    if (mozillaCaStore) {
        X509_STORE_free(mozillaCaStore);
    }

    mozillaCaStore = X509_STORE_new();
    for (int i = 0; i < mozilla::ca_certificates_trusted_delegator_len; i++) {
        const unsigned char *ca_data_pos = mozilla::ca_certificates_trusted_delegator[i].ca_data;
        X509 *cert = d2i_X509(NULL,
                              &ca_data_pos,
                              mozilla::ca_certificates_trusted_delegator[i].ca_data_len);
        if (cert) {
            X509_STORE_add_cert(mozillaCaStore, cert);
            X509_free(cert);
        }
    }
    mozillaUntrustedCaStore = X509_STORE_new();
    for (int i = 0; i < mozilla::ca_certificates_not_trusted_len; i++) {
        const unsigned char *ca_data_pos = mozilla::ca_certificates_not_trusted[i].ca_data;
        X509 *cert = d2i_X509(NULL,
                              &ca_data_pos,
                              mozilla::ca_certificates_not_trusted[i].ca_data_len);
        if (cert) {
            X509_STORE_add_cert(mozillaUntrustedCaStore, cert);
            X509_free(cert);
        }
    }
}
