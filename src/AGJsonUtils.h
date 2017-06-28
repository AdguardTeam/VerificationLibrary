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

#ifndef CERTIFICATE_VERIFIER_AGJSONUTILS_H
#define CERTIFICATE_VERIFIER_AGJSONUTILS_H

#include <stdlib.h>
#include <sstream>
#include <iomanip>

namespace AGJsonUtils {
    static inline std::string jsonQuoteStringLatin1(const std::string &string) {
        std::ostringstream str;
        for (std::string::const_iterator ch = string.begin(); ch != string.end(); ch++) {
            switch (*ch) {
                case '\\':
                case '"':
                case '/':
                    str << '\\' << *ch;
                    break;
                case '\b':
                    str << "\\b";
                    break;
                case '\t':
                    str << "\\t";
                    break;
                case '\n':
                    str << "\\n";
                    break;
                case '\f':
                    str << "\\f";
                    break;
                case '\r':
                    str << "\\r";
                    break;
                default:
                    if (*ch < ' ') {
                        std::ostringstream specialChar;
                        specialChar << "\\u" << std::setfill('0') << std::setw(4) << static_cast<int>(*ch);
                        str << specialChar.str();
                    } else {
                        str << *ch;
                    }
            }
        }
        return str.str();
    }

    static inline std::string jsonUnquoteStringLatin1(const std::string &json) {
        std::ostringstream str;
        enum {
            NORMAL,
            BACKSLASH,
            UNICODE_1,
            UNICODE_2,
            UNICODE_3,
            UNICODE_4
        } state = NORMAL;
        int charCode = 0;
        for (std::string::const_iterator ch = json.begin(); ch != json.end(); ch++) {
#ifdef __GNUC__
#define SWITCH_EXPECT(x, y) __builtin_expect((x), (y))
#else
#define SWITCH_EXPECT(x, y) (x)
#endif
            switch (SWITCH_EXPECT(state, NORMAL)) {
                case NORMAL:
                    if (*ch == '\\') {
                        state = BACKSLASH;
                    } else {
                        str << *ch;
                    }
                    break;
                case BACKSLASH:
                    switch (*ch) {
                        case 'b':
                            str << '\b';
                            state = NORMAL;
                            break;
                        case 't':
                            str << '\t';
                            state = NORMAL;
                            break;
                        case 'n':
                            str << '\n';
                            state = NORMAL;
                            break;
                        case 'f':
                            str << '\f';
                            state = NORMAL;
                            break;
                        case 'r':
                            str << '\r';
                            state = NORMAL;
                            break;
                        case 'u':
                            state = UNICODE_1;
                            charCode = 0;
                            break;
                        default:
                            str << *ch;
                            state = NORMAL;
                            break;
                    }
                    break;
                case UNICODE_1:
                {
                    const char str1[] = {*ch, 0};
                    charCode = (int) strtol(str1, NULL, 16);
                    state = UNICODE_2;
                }
                    break;
                case UNICODE_2:
                {
                    const char str2[] = {*ch, 0};
                    charCode = (charCode << 4) + (int) strtol(str2, NULL, 16);
                    state = UNICODE_3;
                }
                    break;
                case UNICODE_3:
                {
                    const char str3[] = {*ch, 0};
                    charCode = (charCode << 4) + (int) strtol(str3, NULL, 16);
                    state = UNICODE_4;
                }
                    break;
                case UNICODE_4:
                {
                    const char str4[] = {*ch, 0};
                    charCode = (charCode << 4) + (int) strtol(str4, NULL, 16);
                    if (charCode < 255) {
                        str << (char)charCode;
                    } else {
                        str << '?';
                    }
                    state = NORMAL;
                }
                    break;
            }
        }
        return str.str();
    }
}

#endif //CERTIFICATE_VERIFIER_AGJSONUTILS_H
