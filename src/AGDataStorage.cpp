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

#include <fstream>
#include <sstream>
#include "AGDataStorage.h"

AGSimpleDirectoryStorage::AGSimpleDirectoryStorage(const std::string storagePath)
        : storagePath(storagePath)
{
}

bool AGSimpleDirectoryStorage::saveData(const std::string &name, const std::string &value) {
    std::ofstream file((storagePath + "/" + name).c_str());
    if (file.fail()) {
        // Failed to open file for writing
        return false;
    }
    file.write(value.c_str(), value.size());
    if (file.fail()) {
        // Failed to write file contents
        return false;
    }
    return true;
}

bool AGSimpleDirectoryStorage::loadData(const std::string &name, std::string *pOutValue) {
    std::ifstream file((storagePath + "/" + name).c_str());
    if (file.fail()) {
        return false;
    }
    std::ostringstream buffer;
    buffer << file.rdbuf();
    if (file.fail()) {
        return false;
    }
    *pOutValue = buffer.str();
    return true;
}
