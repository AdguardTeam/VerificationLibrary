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
}

template<class T> void loadCAStoreStaticData(X509_STORE *caStore, T ca_certificates, const int ca_certificates_len) {
    for (int i = 0; i < ca_certificates_len; i++) {
        const unsigned char *ca_data_pos = ca_certificates[i].ca_data;
        X509 *cert = d2i_X509(NULL,
                              &ca_data_pos,
                              ca_certificates[i].ca_data_len);
        if (cert) {
            X509_STORE_add_cert(caStore, cert);
            X509_free(cert);
        }
    }
}

/**
 * Load Mozilla CA store from precompiler header data
 */
void AGCertificateVerifier::loadMozillaCAStore() {
    mozillaCaStore = X509_STORE_new();
    loadCAStoreStaticData(mozillaCaStore,
                          mozilla::ca_certificates_trusted_delegator,
                          mozilla::ca_certificates_trusted_delegator_len);
    mozillaUntrustedCaStore = X509_STORE_new();
    loadCAStoreStaticData(mozillaUntrustedCaStore,
                          mozilla::ca_certificates_not_trusted,
                          mozilla::ca_certificates_not_trusted_len);
}
