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

#include <bitset>
#include <iostream>
#include <fstream>

#include <jsmn.h>
#include <miniz.h>
#include <openssl/ocsp.h>
#include <openssl/ssl.h>

#include "AGCertificateVerifier.h"
#include "AGStringUtils.h"
#include "AGJsonUtils.h"
#include "AGX509StoreUtils.h"

static const int JSON_MAX_TOKENS = 32768;
static const std::string BLOCKED_SPKIS_KEY = "BlockedSPKIs";
static const std::string CRL_SET_CRX_FILE = "crl-set.bin";

static const time_t SHA1_DEPRECATION_DATE = 1475269200; // 2016-10-01

static const int OCSP_MAXAGE_SEC = 14*24*60*60;
static const int OCSP_JITTER_SEC = 60;
static const int OCSP_REQUEST_TIMEOUT_MS = 5000;

static const std::string HPKP_INFO_FILE = "hpkp-info.bin";

/**
 * Create Adguard certificate verifier
 * @param storagePath Path to verifier database (HPKP info)
 */
AGCertificateVerifier::AGCertificateVerifier(AGDataStorage *storage)
        : caStore(NULL),
          mozillaCaStore(NULL),
          storage(storage)
{
    load();
}

void AGCertificateVerifier::load() {
    caStore = X509_STORE_new();
    X509_STORE_set_default_paths(caStore);

    // Static info
    loadStaticHPKPInfo();
    loadMozillaCAStore();

    // Dynamic info
    loadDynamicHPKPInfo();
    loadCRLSets();
}

/**
 * Destroy certificate verifier
 */
AGCertificateVerifier::~AGCertificateVerifier() {
    if (caStore) {
        X509_STORE_free(caStore);
    }
    if (mozillaCaStore) {
        X509_STORE_free(mozillaCaStore);
    }
    if (mozillaUntrustedCaStore) {
        X509_STORE_free(mozillaUntrustedCaStore);
    }
}

/**
 * Verify specified certificate chain
 * @param dnsName Host name
 * @param certChain Certificate chain
 * @return Verify result
 */
AGVerifyResult AGCertificateVerifier::verify(const std::string &dnsName, STACK_OF(X509) *certChain) {
    if (caStore == NULL) {
        return AGVerifyResult(AGVerifyResult::VERIFIER_NOT_INITIALIZED, "Certificate verifier isn't initialized");
    }
    if (sk_X509_num(certChain) == 0) {
        return AGVerifyResult(AGVerifyResult::INVALID_CHAIN, "Certificate chain is empty");
    }

    AGVerifyResult res;
    // Check host name
    res = verifyDNSName(dnsName, certChain);
    if (!res.isOk()) {
        return res;
    }

    // Check chain (including SHA1 deprecation check)
     res = verifyChain(caStore, certChain);
    if (!res.isOk()) {
        return res;
    }

    // Checks without verify context
    // CRL set check
    res = verifyCrlSetsStatus(certChain);
    if (!res.isOk()) {
        return res;
    }
    // Distrusted CA check
    res = verifyUntrustedAuthority(certChain);
    if (!res.isOk()) {
        return res;
    }
    // HPKP check
    res = verifyPins(dnsName, certChain);
    if (!res.isOk()) {
        return res;
    }
    return res;
}

/**
 * Set CA store of verifier to the specified certificate list.
 * @param certList Certificate list
 */
void AGCertificateVerifier::setCAStore(STACK_OF(X509) *certList) {
    clearCAStore();
    int num = sk_X509_num(certList);
    for (int i = 0 ; i < num; i++) {
        X509 *cert = sk_X509_value(certList, i);
        if (cert) {
            X509_STORE_add_cert(caStore, cert);
        }
    }
}

/**
 * Set CA store of verifier to the specified certificate store (X509_STORE object).
 * @param store Initialized certificate store as X509_STORE object
 */
void AGCertificateVerifier::setCAStore(X509_STORE *store) {
    if (caStore) {
        X509_STORE_free(caStore);
    }
    caStore = store;
}

/**
 * Clears local CA store
 */
void AGCertificateVerifier::clearCAStore() {
    if (caStore) {
        X509_STORE_free(caStore);
    }
    caStore = X509_STORE_new();
}

/**
 * Verify if certificate matches hostname
 * @param dnsName Hostname
 * @param certChain Certificate chain
 * @return Verify result
 */
AGVerifyResult AGCertificateVerifier::verifyDNSName(const std::string &dnsName, STACK_OF(X509) *certChain) {
    X509 *cert = sk_X509_value(certChain, 0);
    if (cert == NULL) {
        return AGVerifyResult(AGVerifyResult::INVALID_CHAIN, "Can't check host name - can't get main certificate from chain");
    }
    /*
     * TODO: Is this flag needed?
     * Chrome does not check Subject Name when Subject Alternative Name extension is present.
     */
    uint32_t flags = X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
    if (X509_check_host(cert, dnsName.c_str(), dnsName.size(), flags, NULL) == 1) {
        return AGVerifyResult::OK;
    } else {
        return AGVerifyResult(AGVerifyResult::HOST_NAME_MISMATCH, "Host name does not match certificate subject names");
    }
}

/**
 * Verify that certificate chain is valid
 * @param store CA store
 * @param certChain Certificate chain
 * @return Verify result
 */
AGVerifyResult AGCertificateVerifier::verifyChain(X509_STORE *store, STACK_OF(X509) *certChain) {
    // Initialize cert store context
    X509_STORE_CTX *ctx = X509_STORE_CTX_new();
    if (!X509_STORE_CTX_init(ctx, store, NULL, NULL)) {
        return AGVerifyResult(AGVerifyResult::INVALID_CHAIN, "Can't verify certificate chain: can't initialize STORE_CTX");
    }
    if (!X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT)) {
        X509_STORE_CTX_free(ctx);
        return AGVerifyResult(AGVerifyResult::INVALID_CHAIN, "Can't verify certificate chain: can't set STORE_CTX purpose");
    }
    X509_STORE_CTX_set_cert(ctx, sk_X509_value(certChain, 0));
    X509_STORE_CTX_set_chain(ctx, certChain);
    int ret = X509_verify_cert(ctx);
    int error = X509_STORE_CTX_get_error(ctx);
    if (ret != 1) {
        std::string messageStart;
        int depth = X509_STORE_CTX_get_error_depth(ctx);
        if (depth < sk_X509_num(X509_STORE_CTX_get_chain(ctx))) {
            X509 *cert = sk_X509_value(X509_STORE_CTX_get_chain(ctx), depth);
            const char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            messageStart = std::string() + "Error verifying certificate \"" + subject + "\": ";
        }
        X509_STORE_CTX_free(ctx);
        switch (error) {
            case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
            case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
                return AGVerifyResult(AGVerifyResult::SELF_SIGNED, messageStart + X509_verify_cert_error_string(error));
            case X509_V_ERR_CERT_HAS_EXPIRED:
                return AGVerifyResult(AGVerifyResult::EXPIRED, messageStart + X509_verify_cert_error_string(error));
            case X509_V_ERR_CERT_NOT_YET_VALID:
                return AGVerifyResult(AGVerifyResult::NOT_YET_VALID, messageStart + X509_verify_cert_error_string(error));
            default:
                return AGVerifyResult(AGVerifyResult::INVALID_CHAIN, messageStart + X509_verify_cert_error_string(error));
        }
    }

    AGVerifyResult res = verifyDeprecatedSha1Signature(ctx);

    X509_STORE_CTX_free(ctx);
    return res;
}

/**
 * Verify that certificate matches HPKP pins to hostname
 * @param dnsName Hostname
 * @param certChain Certificate chain
 * @return Verify result
 */
AGVerifyResult AGCertificateVerifier::verifyPins(const std::string &dnsName, STACK_OF(X509) *certChain) {
    // Don't check pins for local root CA
    if (!verifyChain(mozillaCaStore, certChain).isOk()) {
        return AGVerifyResult(AGVerifyResult::OK, "Certificate passed basic checks but issued by non-standard CA, skipping pinning test");
    }

    std::vector<std::string> parts = AGStringUtils::split(dnsName, ".");
    std::string hostName;
    for (std::vector<std::string>::const_reverse_iterator i = parts.rbegin(); i != parts.rend(); i++) {
        hostName = *i + (!hostName.empty() ? "." + hostName : "");
        std::map<std::string, AGHPKPInfo>::const_iterator j = dynamicHPKPInfo.find(hostName);
        if (j != dynamicHPKPInfo.end()) {
            const AGHPKPInfo &info = j->second;
            if (hostName == info.hostName
                    && (info.includeSubDomains || hostName == dnsName)
                    && !info.expired()) {
                // We have pins for this host, so check'em
                if (info.hasPinsInChain(certChain)) {
                    return AGVerifyResult::OK;
                } else {
                    return AGVerifyResult(AGVerifyResult::PINNING_ERROR, "Certificate chain does not match dynamic public key pin for this host");
                }
            }
        }
        j = staticHPKPInfo.find(hostName);
        if (j != staticHPKPInfo.end()) {
            const AGHPKPInfo &info = j->second;
            if (hostName == info.hostName
                && (info.includeSubDomains || hostName == dnsName)
                && !info.expired()) {
                // We have pins for this host, so check'em
                if (info.hasPinsInChain(certChain)) {
                    return AGVerifyResult(AGVerifyResult::OK);
                } else {
                    return AGVerifyResult(AGVerifyResult::PINNING_ERROR, "Certificate chain does not match static public key pin for this host");
                }
            }
        }
    }
    return AGVerifyResult::OK;
}

/**
 * Save CRLSets CRX file to certificate verifier storage.
 *
 * CRLSets CRX file is CRX containing file named "crl-set".
 * CRX file format: https://developer.chrome.com/extensions/crx
 * CRLSets file format: https://chromium.googlesource.com/experimental/chromium/src/+/master/net/cert/crl_set_storage.cc
 *
 * You may get CRLSets signed by Google:
 * - CRLSets CRX extension id: hfnkpimlhhgieaddgfemjhofmfblmnib
 * - CRLSets CRX download URL: http://clients2.google.com/service/update2/crx?response=redirect&x=id%3Dhfnkpimlhhgieaddgfemjhofmfblmnib%26v=%26uc
 * or use your own set.
 */
void AGCertificateVerifier::updateCRLSets(const char *crlSetCrx, size_t crlSetCrxLen) {
    storage->saveData(CRL_SET_CRX_FILE, std::string(crlSetCrx, crlSetCrxLen));
    loadCRLSets();
}

static std::string certHashBase64(X509 *cert) {
    uint8_t hash[EVP_MD_size(EVP_sha256())];
    uint32_t hash_len;
    ASN1_item_digest(ASN1_ITEM_rptr(X509_PUBKEY), EVP_sha256(), X509_get_X509_PUBKEY(cert), hash, &hash_len);
    return AGStringUtils::encodeToBase64(hash, hash_len);
}

/**
 * Verify that certificate is not revoked. Lookup is performed in CRLSets
 * @param certChain Certificate chain
 * @return Verify result
 */
AGVerifyResult AGCertificateVerifier::verifyCrlSetsStatus(STACK_OF(X509) *certChain) {
    int num = sk_X509_num(certChain);
    X509 *cert = sk_X509_value(certChain, 0);
    std::string hash = certHashBase64(cert);
    if (revokedSHADigests.count(hash)) {
        // blacklisted by public key hash
        return AGVerifyResult(AGVerifyResult::REVOKED_CRLSETS, "Certificate is found in CRL sets by hash");
    }

    ASN1_INTEGER *asn1_serial = X509_get_serialNumber(cert);
    // OpenSSL strongly not recommend to cast ASN1_INTEGER to ASN1_STRING, so use bignum to convert it to string
    BIGNUM *bn = ASN1_INTEGER_to_BN(asn1_serial, NULL);
    char *serialBytes = BN_bn2hex(bn);
    BN_free(bn);
    std::string serial(serialBytes);
    OPENSSL_free(serialBytes);

    for (int i = 1; i < num; i++) {
        X509 *parentCert = sk_X509_value(certChain, i);
        std::map<std::string, std::set<std::string> >::const_iterator it = issuerSHADigestToCRL.find(certHashBase64(parentCert));
        if (it != issuerSHADigestToCRL.end()) {
            if (it->second.count(serial)) {
                // blacklisted in CRL
                return AGVerifyResult(AGVerifyResult::REVOKED_CRLSETS, "Certificate is found in CRL sets by serial number");
            }
        }
    }
    return AGVerifyResult::OK;
}

static size_t appendToStringStream(void *pOpaque, mz_uint64 file_ofs, const void *pBuf, size_t n) {
    std::ostringstream &os = *(std::ostringstream *)pOpaque;
    os.seekp(file_ofs, std::ios_base::beg);
    os.write((const char *) pBuf, n);
    return n;
}

/**
 * Load CRL sets previously saved in verifier storage.
 */
void AGCertificateVerifier::loadCRLSets() {
    std::string crlSetCrx;
    if (!storage->loadData(CRL_SET_CRX_FILE, &crlSetCrx)) {
        return;
    }

    struct CrlSetHeader {
        int magic;
        int version;
        int keyLen;
        int sigLen;
    };
    CrlSetHeader *header = (CrlSetHeader *) crlSetCrx.c_str();
    size_t crlSetZipOffset = sizeof(CrlSetHeader) + header->keyLen + header->sigLen;
    if (crlSetZipOffset > crlSetCrx.size()) {
        // Offset is too large
        return;
    }
    const char *crlSetZip = crlSetCrx.c_str() + crlSetZipOffset;
    size_t crlSetZipLength = crlSetCrx.size() - crlSetZipOffset;

    std::ostringstream crlSetContentStr;
    {
        mz_bool status;
        mz_zip_archive zip_archive;

        memset(&zip_archive, 0, sizeof(zip_archive));
        status = mz_zip_reader_init_mem(&zip_archive, crlSetZip, crlSetZipLength, 0);
        if (!status){
            // Failed to open CRX zip segment
            return;
        }
        mz_zip_reader_extract_file_to_callback(&zip_archive, "crl-set", &appendToStringStream, &crlSetContentStr, 0);
        mz_zip_reader_end(&zip_archive);
    }

    std::string crlSetContent = crlSetContentStr.str();
    size_t len = crlSetContent.size();
    unsigned char *pos = (unsigned char *) crlSetContent.c_str();

    // Read CRLSet header (JSON)
    uint16_t json_len = *(uint16_t *)(pos);
    pos += 2; // header length
    jsmntok_t tokens[JSON_MAX_TOKENS];
    jsmn_parser parser = {0};
    jsmn_init(&parser);
    const char *json = (const char *) pos;
    // JSMN parser is very fast and does not build a document tree - just streamed offsets-only representation
    int tokens_num = jsmn_parse(&parser, json, json_len, tokens, JSON_MAX_TOKENS);
    if (tokens_num >= 0) {
        for (int i = 0; i < tokens_num; i++) {
            jsmntok_t *key_tok = &tokens[i];
            // If token is object property key
            if (key_tok->type == JSMN_STRING && key_tok->size == 1) {
                const std::string key = std::string(json + key_tok->start, (size_t) key_tok->end - key_tok->start);
                if (key == BLOCKED_SPKIS_KEY) {
                    // Found BlockedSPKIs
                    // Value is in next token
                    jsmntok_t *value_tok = key_tok + 1;
                    if (value_tok->type == JSMN_ARRAY) {
                        // Next `value_tok->size' tokens are array elements
                        jsmntok_t *t = value_tok + 1;
                        jsmntok_t *endpos_tok = t + value_tok->size;
                        while (t != endpos_tok) {
                            if (t->type == JSMN_STRING) {
                                const std::string spki = std::string(json + t->start, (size_t) t->end - t->start);
                                revokedSHADigests.insert(spki);
                            } else {
                                break;
                            }
                            ++t;
                        }
                    }
                    break;
                }
            }
        }
    }
    pos += json_len;

    // Read CRLSet
    unsigned char *end = (unsigned char *) (crlSetContent.c_str() + len);
#define BCHECK(x) do { if (!(x)) break; } while (0)
    while (pos < end) {
        // Issuer SPKI SHA256 - 32 bytes
        BCHECK(pos + 32 > end);
        std::string issuerSHADigest = AGStringUtils::encodeToBase64(pos, 32);
        pos += 32;
        BCHECK(pos >= end);
        // Serial number count - 4 bytes
        uint32_t serialCount = *(uint32_t *)(pos);
        pos += 4;
        BCHECK(pos >= end);
        // Serial number list
        std::set<std::string> &serialList = issuerSHADigestToCRL[issuerSHADigest];
        for (int i = 0; i < serialCount; i++) {
            // Serial number size - 1 byte
            uint8_t serialSize = *pos++;
            BCHECK(pos >= end);
            BCHECK(pos + serialSize > end);
            // Serial number
            serialList.insert(AGStringUtils::encodeToHex(pos, serialSize));
            pos += serialSize;
            BCHECK(pos >= end);
        }
    }
#undef BCHECK
}

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
void AGCertificateVerifier::updateHPKPInfo(
        const std::string &dnsName, STACK_OF(X509) *certChain, const std::string &httpHeaderName, const std::string &httpHeaderValue)
{
    if (AGStringUtils::toLower(httpHeaderValue).find("report-only") != std::string::npos) {
        // TODO: Add support for report URI
        return;
    }
    AGHPKPInfo info = AGHPKPInfo(httpHeaderValue);
    if (!info.isValid()) {
        return;
    }
    // HPKP info must have at least one pin in current chain and at least one pin not in current chain
    if (!info.hasPinsNotInChain(certChain)) {
        return;
    }
    if (!info.hasPinsInChain(certChain)) {
        return;
    }
    dynamicHPKPInfo[dnsName] = info;
    saveDynamicHPKPInfo();
}

/**
 * Verify that certificate chain has no authorities that are no longer trusted by major web browsers
 * due to various reasons.
 *
 * @param certChain Certificate chain
 * @return Verify result
 */
AGVerifyResult AGCertificateVerifier::verifyUntrustedAuthority(STACK_OF(X509) *certChain) {
    // No intersection with untrusted store is allowed
    if (AGX509StoreUtils::lookupInStore(mozillaUntrustedCaStore, certChain)) {
        return AGVerifyResult(AGVerifyResult::BLACKLISTED_ROOT, "Certificate chain contains one of explicitly untrusted authorities");
    } else {
        return AGVerifyResult(AGVerifyResult::OK);
    }
}

/**
 * Verify that certificate does not use SHA1 signature hash algorithm.
 *
 * Verifies only certificates issued after October, 2016.
 * Another weak hash algorithms (MD2/4/5) are already untrusted by OpenSSL.
 *
 * @param certChain Certificate chain
 * @return Verify result
 */
AGVerifyResult AGCertificateVerifier::verifyDeprecatedSha1Signature(X509_STORE_CTX *ctx) {
    // Get current resolved chain from ctx
    STACK_OF(X509) *resolvedChain = X509_STORE_CTX_get_chain(ctx);
    if (resolvedChain == NULL || sk_X509_num(resolvedChain) == 0) {
        return AGVerifyResult(AGVerifyResult::INVALID_CHAIN, "Verify failed but tried to run weak hash check");
    }
    X509 *cert = sk_X509_value(resolvedChain, 0);

    time_t date = SHA1_DEPRECATION_DATE;
    if (X509_cmp_time(X509_get_notBefore(cert), &date) < 0) {
        // Issued before deprecation date, valid.
        return AGVerifyResult::OK;
    }

    // Building chain replacing certs to root CA store ones if possible
    STACK_OF(X509) *ctxChain = sk_X509_new_null();
    if (ctxChain == NULL) {
        return AGVerifyResult(AGVerifyResult::OUT_OF_MEMORY, "Can't allocate memory");
    }
    while (cert) {
        sk_X509_push(ctxChain, cert);
        X509 *issuer;
        int r = X509_STORE_CTX_get1_issuer(&issuer, ctx, cert);
        if (r == 1) {
            X509_free(issuer); // No need for up refcount
            if (!X509_cmp(issuer, cert)) {
                break;
            }
            cert = issuer;
        } else {
            cert = X509_find_by_subject(resolvedChain, X509_get_issuer_name(cert));
        }
    }

    // Check SHA1 deprecation
    for (int i = 0; i < sk_X509_num(ctxChain); i++) {
        cert = sk_X509_value(ctxChain, i);
        int mdnid = 0;
#if OPENSSL_VERSION_NUMBER < 0x10100000L
        if (OBJ_find_sigid_algs(OBJ_obj2nid(cert->sig_alg->algorithm), &mdnid, NULL))
#else
        if (OBJ_find_sigid_algs(X509_get_signature_nid(cert), &mdnid, NULL))
#endif
        {
            if (mdnid == NID_sha1) {
                // We trust root CA's with SHA1 hash signature
                if (AGX509StoreUtils::lookupInCtx(ctx, cert)) {
                    continue;
                } else {
                    sk_X509_free(ctxChain);
                    char *subject = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
                    return AGVerifyResult(AGVerifyResult::SIGNED_WITH_SHA1, "Detected SHA1 intermediate certificate: " + std::string(subject));
                }
            }
        }
    }
    sk_X509_free(ctxChain);
    return AGVerifyResult::OK;
}

/*
 * Imported from libtls
 * See third-party/libressl/LICENSE for licensing information
 */
static OCSP_CERTID *
tls_ocsp_get_certid(X509 *main_cert, STACK_OF(X509) *extra_certs, X509_STORE *store)
{
    X509_NAME *issuer_name;
    X509 *issuer;
    X509_STORE_CTX *storectx;
    OCSP_CERTID *cid = NULL;

    if ((issuer_name = X509_get_issuer_name(main_cert)) == NULL)
        return NULL;

    if (extra_certs != NULL) {
        issuer = X509_find_by_subject(extra_certs, issuer_name);
        if (issuer != NULL)
            return OCSP_cert_to_id(NULL, main_cert, issuer);
    }

    storectx = X509_STORE_CTX_new();
    if (!storectx) {
        return NULL;
    }
    if (X509_STORE_CTX_init(storectx, store, main_cert, extra_certs) != 1) {
        X509_STORE_CTX_free(storectx);
        return NULL;
    }
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    X509_OBJECT tmpobj;
    if (X509_STORE_get_by_subject(storectx, X509_LU_X509, issuer_name,
                                  &tmpobj) == 1) {
        cid = OCSP_cert_to_id(NULL, main_cert, tmpobj.data.x509);
        X509_OBJECT_free_contents(&tmpobj);
    }
#else
    X509_OBJECT *tmpobj;
    if ((tmpobj = X509_STORE_CTX_get_obj_by_subject(storectx, X509_LU_X509, issuer_name)) != NULL) {
        cid = OCSP_cert_to_id(NULL, main_cert, X509_OBJECT_get0_X509(tmpobj));
        X509_OBJECT_free(tmpobj);
    }
#endif
    X509_STORE_CTX_free(storectx);
    return cid;
}

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
AGVerifyResult AGCertificateVerifier::verifyOCSPResponse(const std::string &dnsName, STACK_OF(X509) *certChain,
                                                         OCSP_RESPONSE *resp) {
    AGVerifyResult res;
    OCSP_BASICRESP *br = NULL;
    ASN1_GENERALIZEDTIME *revtime = NULL, *thisupd = NULL, *nextupd = NULL;
    OCSP_CERTID *cid = NULL;
    STACK_OF(X509) *combined = NULL;
    int response_status=0, cert_status=0, crl_reason=0;
    unsigned long flags;

    if ((br = OCSP_response_get1_basic(resp)) == NULL) {
        return AGVerifyResult(AGVerifyResult::OCSP_INVALID_RESPONSE, "Can't get basic response from OCSP response");
    }

    /*
     * Skip validation of 'extra_certs' as this should be done
     * already as part of main handshake.
     */
    flags = OCSP_TRUSTOTHER;

    /* now verify */
    if (OCSP_basic_verify(br, certChain,
                          caStore, flags) != 1) {
        res = AGVerifyResult(AGVerifyResult::OCSP_INVALID_RESPONSE, "OCSP response signature verify failed");
        goto finish;
    }

    /* signature OK, look inside */
    response_status = OCSP_response_status(resp);
    if (response_status != OCSP_RESPONSE_STATUS_SUCCESSFUL) {
        res = AGVerifyResult(AGVerifyResult::OCSP_INVALID_RESPONSE, std::string("OCSP verify failed: response status is not successful: ") + OCSP_response_status_str(response_status));
        goto finish;
    }

    cid = tls_ocsp_get_certid(sk_X509_value(certChain, 0),
                              certChain, caStore);
    if (cid == NULL) {
        res = AGVerifyResult(AGVerifyResult::OCSP_INVALID_RESPONSE, "OCSP verify failed: no issuer cert");
        goto finish;
    }

    if (OCSP_resp_find_status(br, cid, &cert_status, &crl_reason,
                              &revtime, &thisupd, &nextupd) != 1) {
        res = AGVerifyResult(AGVerifyResult::OCSP_INVALID_RESPONSE, "OCSP verify failed: no result for cert");
        goto finish;
    }

    if (OCSP_check_validity(thisupd, nextupd, OCSP_JITTER_SEC,
                            OCSP_MAXAGE_SEC) != 1) {
        res = AGVerifyResult(AGVerifyResult::OCSP_INVALID_RESPONSE, "OCSP response is not current");
        goto finish;
    }

#if 0
    if (tls_ocsp_fill_info(ctx, response_status, cert_status,
                           crl_reason, revtime, thisupd, nextupd) != 0)
        goto error;
#endif

    /* finally can look at status */
    if (cert_status == V_OCSP_CERTSTATUS_REVOKED) {
        res = AGVerifyResult(AGVerifyResult::REVOKED_OCSP, "Certificate was revoked by issuer");
        goto finish;
    }

    res = AGVerifyResult::OK;

finish:
    sk_X509_free(combined);
    OCSP_CERTID_free(cid);
    OCSP_BASICRESP_free(br);
    return res;
}

/**
 * Load HTTP public key pinning information for verifier storage.
 */
void AGCertificateVerifier::loadDynamicHPKPInfo() {
    std::string json;
    if (!storage->loadData(HPKP_INFO_FILE, &json)) {
        return;
    }

    jsmntok_t tokens[JSON_MAX_TOKENS], *tok;
    jsmn_parser parser = {0};
    jsmn_init(&parser);
    // JSMN parser is very fast and does not build a document tree - just streamed offsets-only representation
    int tokens_num = jsmn_parse(&parser, json.c_str(), json.size(), tokens, JSON_MAX_TOKENS);
    if (tokens_num <= 0) {
        return;
    }
    int i = 0;
    if (tokens[i].type != JSMN_ARRAY || tokens[i].size == 0) {
        return;
    }
    int remaining_infos = tokens[i].size;
    i++;
    for (; remaining_infos > 0; remaining_infos--) {
        AGHPKPInfo info = AGHPKPInfo();
        if (tokens[i].type != JSMN_OBJECT) {
            return;
        }
        int remaining_keys = tokens[i].size;
        i++;
        for (; remaining_keys > 0; remaining_keys--) {
            if (tokens[i].type != JSMN_STRING || tokens[i].size != 1) {
                return;
            }
            std::string name = json.substr(tokens[i].start, tokens[i].end - tokens[i].start);
            i++;
            if (name == "hostName") {
                if (tokens[i].type != JSMN_STRING || tokens[i].size != 0) {
                    return;
                }
                info.hostName = AGJsonUtils::jsonUnquoteStringLatin1(json.substr(tokens[i].start, tokens[i].end - tokens[i].start));
                i++;
            } else if (name == "expirationDate") {
                if (tokens[i].type != JSMN_PRIMITIVE) {
                    return;
                }
                info.expirationDate = strtoll(json.substr(tokens[i].start, tokens[i].end - tokens[i].start).c_str(), NULL, 16);
                i++;
            } else if (name == "includeSubDomains") {
                if (tokens[i].type != JSMN_PRIMITIVE) {
                    return;
                }
                info.includeSubDomains = json.substr(tokens[i].start, tokens[i].end - tokens[i].start) == "true" ? true : false;
                i++;
            } else if (name == "pkPins") {
                if (tokens[i].type != JSMN_ARRAY) {
                    return;
                }
                int remaining_pkPins = tokens[i].size;
                i++;
                for (; remaining_pkPins > 0; remaining_pkPins--) {
                    if (tokens[i].type != JSMN_STRING || tokens[i].size != 0) {
                        return;
                    }
                    info.pkPins.insert(AGJsonUtils::jsonUnquoteStringLatin1(json.substr(tokens[i].start, tokens[i].end - tokens[i].start)));
                    i++;
                }
            }
        }
        if (info.isValid()) {
            dynamicHPKPInfo[info.hostName] = info;
        }
    }
}

/**
 * Save HTTP public key pinning information into verifier storage
 */
void AGCertificateVerifier::saveDynamicHPKPInfo() {
    std::ostringstream dynamicHPKPInfoData;
    dynamicHPKPInfoData << "[ ";
    for (std::map<std::string, AGHPKPInfo>::iterator i = dynamicHPKPInfo.begin(); i != dynamicHPKPInfo.end(); ) {
        if (i != dynamicHPKPInfo.begin()) {
            dynamicHPKPInfoData << ", ";
        }
        if (i->second.isValid()) {
            const AGHPKPInfo &info = i->second;
            {
                std::ostringstream os;
                os << "{ ";
                os << "\"hostName\" : ";
                os << "\"" << AGJsonUtils::jsonQuoteStringLatin1(info.hostName) << "\", ";
                os << "\"pkPins\" : [ ";
                for (std::set<std::string>::const_iterator it = info.pkPins.begin(); it != info.pkPins.end(); it++) {
                    if (it != info.pkPins.begin()) {
                        os << ", ";
                    }
                    os << "\"" << AGJsonUtils::jsonQuoteStringLatin1(*it) << "\"";
                }
                os << " ], ";
                os << "\"expirationDate\" : ";
                os << info.expirationDate << ", ";
                os << "\"includeSubDomains\" : ";
                {
                    std::stringstream includeSubDomainsStr;
                    includeSubDomainsStr << std::boolalpha << info.includeSubDomains;
                    os << includeSubDomainsStr.str();
                }
                os << " }";
                dynamicHPKPInfoData << os.str();
            }
            i++;
        } else {
            dynamicHPKPInfo.erase(i++);
        }
    }
    dynamicHPKPInfoData << " ]";
    storage->saveData(HPKP_INFO_FILE, dynamicHPKPInfoData.str());
}

/**
 * Perform an OCSP request for leaf certificate and verify its result.
 *
 * Full certificate chain is needed to check OCSP response signature.
 */
AGVerifyResult AGCertificateVerifier::verifyOCSP(const std::string &dnsName, STACK_OF(X509) *certChain) {
    AGVerifyResult result = AGVerifyResult::OK;
    X509 *cert = sk_X509_value(certChain, 0);
    struct stack_st_OPENSSL_STRING *ocsp = X509_get1_ocsp(cert);
    for (int i = 0; i < sk_OPENSSL_STRING_num(ocsp); i++) {
        char *ocsp_url = sk_OPENSSL_STRING_value(ocsp, i);
        result = doOCSPRequest(ocsp_url, dnsName, certChain);
        break;
    }
    sk_OPENSSL_STRING_pop_free(ocsp, (void(*)(OPENSSL_STRING))CRYPTO_free);
    return result;
}

/*
 * This function is imported from OpenSSL
 * See third-party/openssl/LICENSE for licensing information
 */
static OCSP_RESPONSE *query_responder(BIO *err, BIO *cbio, const char *path,
                                      const STACK_OF(CONF_VALUE) *headers,
                                      OCSP_REQUEST *req, int req_timeout)
{
    int fd;
    long rv;
    int i;
    OCSP_REQ_CTX *ctx = NULL;
    OCSP_RESPONSE *rsp = NULL;
    fd_set confds;
    struct timeval tv;

    if (req_timeout != -1)
        BIO_set_nbio(cbio, 1);

    rv = BIO_do_connect(cbio);

    if ((rv <= 0) && ((req_timeout == -1) || !BIO_should_retry(cbio))) {
        BIO_puts(err, "Error connecting BIO\n");
        return NULL;
    }

    if (BIO_get_fd(cbio, &fd) < 0) {
        BIO_puts(err, "Can't get connection fd\n");
        goto err;
    }

    if (req_timeout != -1 && rv <= 0) {
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        rv = select(fd + 1, NULL, &confds, NULL, &tv);
        if (rv == 0) {
            BIO_puts(err, "Timeout on connect\n");
            return NULL;
        }
    }

    ctx = OCSP_sendreq_new(cbio, (char *)path, NULL, -1);
    if (!ctx)
        return NULL;

    for (i = 0; i < sk_CONF_VALUE_num(headers); i++) {
        CONF_VALUE *hdr = sk_CONF_VALUE_value(headers, i);
        if (!OCSP_REQ_CTX_add1_header(ctx, hdr->name, hdr->value))
            goto err;
    }

    if (!OCSP_REQ_CTX_set1_req(ctx, req))
        goto err;

    for (;;) {
        rv = OCSP_sendreq_nbio(&rsp, ctx);
        if (rv != -1)
            break;
        if (req_timeout == -1)
            continue;
        FD_ZERO(&confds);
        FD_SET(fd, &confds);
        tv.tv_usec = 0;
        tv.tv_sec = req_timeout;
        if (BIO_should_read(cbio)) {
            rv = select(fd + 1, &confds, NULL, NULL, &tv);
        } else if (BIO_should_write(cbio)) {
            rv = select(fd + 1, NULL, &confds, NULL, &tv);
        } else {
            BIO_puts(err, "OCSP check failed: Unexpected retry condition\n");
            goto err;
        }
        if (rv == 0) {
            BIO_puts(err, "OCSP check failed: Timeout on request\n");
            break;
        }
        if (rv == -1) {
            BIO_puts(err, "OCSP check failed: select() error\n");
            break;
        }

    }
    err:
    if (ctx)
        OCSP_REQ_CTX_free(ctx);

    return rsp;
}

AGVerifyResult AGCertificateVerifier::doOCSPRequest(char *url, const std::string &dnsName, STACK_OF(X509) *certChain) {
    AGVerifyResult res;
    char *host = NULL, *port = NULL, *path = NULL;
    int use_ssl = 0;
    OCSP_CERTID *certid = NULL;
    STACK_OF(CONF_VALUE) *headers = NULL;
    OCSP_REQUEST *req = NULL;
    OCSP_RESPONSE *response = NULL;
    BIO *bio = NULL;
    X509 *cert = NULL;

    // Get cert
    cert = sk_X509_value(certChain, 0);
    if (cert == NULL) {
        res = AGVerifyResult(AGVerifyResult::OCSP_REQUEST_FAILED, "Certificate chain is empty");
        goto finish;
    }

    // Get OCSP url
    if (!OCSP_parse_url(url, &host, &port, &path, &use_ssl)) {
        res = AGVerifyResult(AGVerifyResult::OCSP_REQUEST_FAILED, "Invalid OCSP url");
        goto finish;
    }

    bio = BIO_new_connect(host);
    if (port) {
        BIO_set_conn_port(bio, port);
    }
    if (use_ssl == 1) {
        BIO *sbio;
        SSL_CTX *ctx = SSL_CTX_new(SSLv23_client_method());
        if (ctx == NULL) {
            res = AGVerifyResult(AGVerifyResult::OCSP_REQUEST_FAILED, "Error connecting to the remote server: error creating SSL context");
            goto finish;
        }
        SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
        sbio = BIO_new_ssl(ctx, 1);
        bio = BIO_push(sbio, bio);
    }

    // Construct request
    certid = tls_ocsp_get_certid(cert, certChain, caStore);
    if (certid == NULL) {
        res = AGVerifyResult(AGVerifyResult::OCSP_REQUEST_FAILED, "Not enough info for OCSP request creation");
        goto finish;
    }
    req = OCSP_REQUEST_new();
    if (req == NULL) {
        res = AGVerifyResult(AGVerifyResult::OUT_OF_MEMORY, "Can't allocate memory");
        OCSP_CERTID_free(certid);
        goto finish;
    }
    OCSP_request_add0_id(req, certid);

    // Send request
    headers = sk_CONF_VALUE_new_null();
    if (headers == NULL) {
        res = AGVerifyResult(AGVerifyResult::OUT_OF_MEMORY, "Can't allocate memory");
        goto finish;
    }
    response = query_responder(NULL, bio, "/", headers, req, OCSP_REQUEST_TIMEOUT_MS);
    if (response == NULL) {
        res = AGVerifyResult(AGVerifyResult::OCSP_REQUEST_FAILED, "Error querying the remote server");
        goto finish;
    }
    res = verifyOCSPResponse(dnsName, certChain, response);

finish:
    OCSP_RESPONSE_free(response);
    OCSP_REQUEST_free(req);
    BIO_free_all(bio);
    OPENSSL_free(host);
    OPENSSL_free(port);
    OPENSSL_free(path);
    sk_CONF_VALUE_pop_free(headers, (void(*)(CONF_VALUE *))CRYPTO_free);
    return res;
}
