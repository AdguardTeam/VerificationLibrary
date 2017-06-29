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

#ifndef CERTIFICATE_VERIFIER_AGX509STOREUTILS_H
#define CERTIFICATE_VERIFIER_AGX509STOREUTILS_H

#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>

namespace AGX509StoreUtils {
    /**
     * Lookup specified X.509 certificate in X509 store context
     * @param ctx X.509 store context
     * @param cert X.509 certificate
     * @return True if certificate is found
     */
    static inline bool lookupInCtx(X509_STORE_CTX *ctx, X509 *cert) {
        X509_NAME *name = X509_get_subject_name(cert);
        if (name == NULL) {
            return false;
        }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        X509_OBJECT obj = {0};
        X509_STORE_get_by_subject(ctx, X509_LU_X509, name, &obj);
        X509 *storeCert = obj.data.x509;
        if (storeCert) {
            if (X509_cmp(storeCert, cert) == 0
                || (M_ASN1_BIT_STRING_cmp(X509_get0_pubkey_bitstr(storeCert), X509_get0_pubkey_bitstr(cert)) == 0
                    && storeCert->ex_flags & EXFLAG_SS))
            {
                X509_OBJECT_free_contents(&obj);
                return true;
            }
        }
        X509_OBJECT_free_contents(&obj);
#else
        X509_OBJECT *obj = X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_X509, name);
        X509 *storeCert = X509_OBJECT_get0_X509(obj);
        if (storeCert) {
            if (X509_cmp(storeCert, cert) == 0
                || (ASN1_STRING_cmp(X509_get0_pubkey_bitstr(storeCert), X509_get0_pubkey_bitstr(cert)) == 0
                    && X509_get_extension_flags(storeCert) & EXFLAG_SS))
            {
                X509_OBJECT_free(obj);
                return true;
            }
        }
        X509_OBJECT_free(obj);
#endif
        return false;
    }

    /**
     * Find at least one X.509 certificate in chain in X509 store context
     * @param ctx X.509 store
     * @param certChain X.509 certificate chain
     * @return True if at least one certificate is found
     */
    static inline bool lookupInCtx(X509_STORE_CTX *ctx, STACK_OF(X509) *certChain) {
        int num = sk_X509_num(certChain);
        for (int i = 0; i < num; i++) {
            X509 *cert = sk_X509_value(certChain, i);
            if (lookupInCtx(ctx, cert)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Lookup specified X.509 certificate in X509 store
     * @param store X.509 store
     * @param cert X.509 certificate
     * @return True if certificate is found
     */
    static inline bool lookupInStore(X509_STORE *store, X509 *cert) {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        if (!ctx) {
            return false;
        }
        if (!X509_STORE_CTX_init(ctx, store, NULL, NULL)) {
            return false;
        }
        if (!X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT)) {
            X509_STORE_CTX_free(ctx);
            return false;
        }
        bool ret = lookupInCtx(ctx, cert);
        X509_STORE_CTX_free(ctx);
        return ret;
    }

    /**
     * Lookup specified X.509 certificate in X509 store
     * @param store X.509 store
     * @param cert X.509 certificate
     * @return True if certificate is found
     */
    static inline bool lookupInStore(X509_STORE *store, STACK_OF(X509) *certChain) {
        X509_STORE_CTX *ctx = X509_STORE_CTX_new();
        if (!X509_STORE_CTX_init(ctx, store, NULL, NULL)) {
            return false;
        }
        if (!X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT)) {
            X509_STORE_CTX_free(ctx);
            return false;
        }
        bool ret = lookupInCtx(ctx, certChain);
        X509_STORE_CTX_free(ctx);
        return ret;
    }
}

#endif //CERTIFICATE_VERIFIER_AGX509STOREUTILS_H
