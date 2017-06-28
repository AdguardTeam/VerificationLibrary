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

#ifndef AGSTRINGUTILS_H
#define AGSTRINGUTILS_H

#include <string>
#include <list>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cctype>
#include <iomanip>

#include <stdint.h>
#include <vector>

/**
 * Functions and helper classes for dealing with strings
 */
namespace AGStringUtils {

    /**
     * Return lowercase version of string
     * @param str String
     * @return Lowercase string
     */
    static inline std::string toLower(const std::string &str) {
        std::string lowerStr;
        lowerStr.reserve(str.size());
        // cast is hint to compiler to use std::tolower from <cctype>, not from <locale>
        std::transform(str.begin(), str.end(), std::back_inserter(lowerStr), (int(*)(int)) &std::tolower);
        return lowerStr;
    }

    /**
     * Return uppercase version of string
     * @param str String
     * @return Uppercase string
     */
    static inline std::string toUpper(const std::string &str) {
        std::string upperStr;
        upperStr.reserve(str.size());
        // cast is hint to compiler to use std::toupper from <cctype>, not from <locale>
        std::transform(str.begin(), str.end(), std::back_inserter(upperStr), (int(*)(int)) &std::toupper);
        return upperStr;
    }

    /**
     * Trim spaces at the beginning and ending of string
     * @param str String
     * @return Trimmed string
     */
    static inline std::string trim(std::string str) {
        size_t endPos = str.find_last_not_of(" \t");
        if (endPos != std::string::npos) {
            str = str.substr(0, endPos + 1);
        }
        size_t startPos = str.find_first_not_of(" \t");
        if (endPos != std::string::npos) {
            str = str.substr(startPos);
        }
        return str;
    }

    /**
     * Splits string into pieces by any of delimiter chars
     * @param str String
     * @param chars Delimiters
     * @return List of strings
     */
    static inline std::vector<std::string> split(std::string str, const std::string &chars) {
        std::vector<std::string> strings;
        while (!str.empty()) {
            size_t next = str.find_first_of(chars);
            std::string encoding = str.substr(0, next);
            if (!encoding.empty()) {
                strings.push_back(encoding);
            }
            str.erase(0, next == std::string::npos ? (size_t) str.size() : next + 1);
        }
        return strings;
    }

    /**
     * Joins list of string to string
     */
    template <typename StrList>
    static std::string join(const StrList &strings, const std::string &delimiter) {
        std::ostringstream os;
        for (typename StrList::const_iterator i = strings.begin(); i != strings.end(); i++) {
            if (i != strings.begin()) {
                os << delimiter;
            }
            os << *i;
        }
        return os.str();
    }

    static inline bool caseEquals(const std::string &a, const std::string &b) {
        return !strcasecmp(a.c_str(), b.c_str());
    }
}

namespace AGStringUtils {
    /**
     * Case insensitive string comparator functor for using with STL structures
     */
    class CaseInsensitiveLess {
    public:
        static inline bool charCaseLess(char x, char y) {
            return std::tolower(x) < std::tolower(y);
        }
        inline bool operator()(const std::string &a, const std::string &b) const {
            return std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end(), charCaseLess);
        }
    };
}

namespace AGStringUtils {
    /**
     * Encode data to base64 string
     * @param data Input buffer
     * @param len Input buffer length
     * @return Base64-encoded data
     */
    static inline std::string encodeToBase64(const uint8_t *data, size_t len) {
        const static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const uint8_t *end = data + len;
        // Every 6 bits is encoded using given table, every 1-3 input bytes produces 4 output symbols
        size_t out_len = (len + 2) / 3 * 4;
        char out[out_len];
        const uint8_t *in_pos = data;
        char *out_pos = out;
        while (in_pos < end - 2) {
            *out_pos++ = table[in_pos[0] >> 2];
            *out_pos++ = table[((in_pos[0] & 0x03) << 4) | (in_pos[1] >> 4)];
            *out_pos++ = table[((in_pos[1] & 0x0f) << 2) | (in_pos[2] >> 6)];
            *out_pos++ = table[in_pos[2] & 0x3f];
            in_pos += 3;
        }
        if (in_pos < end) {
            *out_pos++ = table[in_pos[0] >> 2];
            if (end - in_pos == 1) {
                *out_pos++ = table[(in_pos[0] & 0x03) << 4];
                *out_pos++ = '=';
            } else {
                *out_pos++ = table[((in_pos[0] & 0x03) << 4) | (in_pos[1] >> 4)];
                *out_pos++ = table[(in_pos[1] & 0x0f) << 2];
            }
            *out_pos++ = '=';
        }
        return std::string(out, out_len);
    }

    /**
     * Encode input data to hex string
     * @param data Input buffer
     * @param len Input buffer length
     * @return Hex representation of input data
     */
    static inline std::string encodeToHex(const uint8_t *data, size_t len) {
        const static char table[] = "0123456789abcdef";
        const uint8_t *end = data + len;
        size_t out_len = len * 2;
        char out[out_len];
        const uint8_t *in_pos = data;
        char *out_pos = out;
        while (in_pos < end) {
            *out_pos++ = table[(*in_pos >> 4) & 0xf];
            *out_pos++ = table[*in_pos & 0xf];
            in_pos++;
        }
        return std::string(out, out_len);
    }
}

#endif /* AGSTRINGUTILS_H */
