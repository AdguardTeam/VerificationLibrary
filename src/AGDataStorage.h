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

#ifndef CERTIFICATE_VERIFIER_AGDATASTORAGE_H
#define CERTIFICATE_VERIFIER_AGDATASTORAGE_H

#include <string>

/**
 * Storage interface for AGCertificateVerifier
 */
class AGDataStorage {
public:
    virtual ~AGDataStorage(){}

    /**
     * Saves given data to storage
     * @param[in] name Key name in ASCII encoding
     * @param[in] value Data
     */
    virtual bool saveData(const std::string &name, const std::string &value) = 0;

    /**
     * Load data from storage by key name
     * @param[in] name Key name in ASCII encoding
     * @param[in,out] pOutValue Pointer to variable where loaded data will be stored
     * @return True if data was successfully loaded
     */
    virtual bool loadData(const std::string &name, std::string *pOutValue) = 0;

};

#ifdef __cpp_attributes
[[deprecated("For testing only. Implement your own secure storage for a certain platform")]]
#endif
class AGSimpleDirectoryStorage : public AGDataStorage {
public:
    AGSimpleDirectoryStorage(const std::string storagePath);

    virtual ~AGSimpleDirectoryStorage(){}

    virtual bool saveData(const std::string &name, const std::string &value);

    virtual bool loadData(const std::string &name, std::string *pOutValue);
private:
    std::string storagePath;
};

#endif //CERTIFICATE_VERIFIER_AGDATASTORAGE_H
