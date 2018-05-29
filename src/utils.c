/* Copyright (c) 2018 Aalto University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include "utils.h"

// Utilities
int hex2bytes(const char* hex, int len, char* res) {
    int i;
    for(i = 0; i < len/2; i++) {
        sscanf(&(hex[i*2]), "%2hhx", &(res[i]));
    }

    // Each 2 hex characters is one byte
    return len/2;
}

int bytes2hex(const unsigned char* bytes, int len, char* hex) {
    int i;
    for(i = 0; i < len; i++) {
        sprintf(&(hex[i*2]), "%02x", bytes[i]);
    }

    // Each 2 hex characters is one byte
    return len*2;
}
