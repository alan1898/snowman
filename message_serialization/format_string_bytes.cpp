//
// Created by alan on 19-4-26.
//

#include "format_string_bytes.h"

format_string_bytes::format_string_bytes() {
    replacement = new vector<int>();
}

format_string_bytes::format_string_bytes(string str) {
    int str_byte_num = str.size();
    int empty_num = (AES_BLOCK_SIZE - (str_byte_num % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    n = str_byte_num + empty_num;

    bytes = (unsigned char*)malloc(n + 1);
    for (int i = 0; i < n; ++i) {
        if (i < str_byte_num) {
            bytes[i] = str.at(i);
        } else {
            bytes[i] = '\0';
        }
    }
    bytes[n] = '\0';

    replacement = new vector<int>();
}

format_string_bytes::format_string_bytes(unsigned char *str_bytes, int str_byte_num) {
    int empty_num = (AES_BLOCK_SIZE - (str_byte_num % AES_BLOCK_SIZE)) % AES_BLOCK_SIZE;
    n = str_byte_num + empty_num;

    bytes = (unsigned char*)malloc(n + 1);
    for (int i = 0; i < n; ++i) {
        if (i < str_byte_num) {
            bytes[i] = str_bytes[i];
        } else {
            bytes[i] = '\0';
        }
    }
    bytes[n] = '\0';

    replacement = new vector<int>();
}

void format_string_bytes::replace() {
    for (int i = 0; i < n; ++i) {
        if (bytes[i] == '\0') {
            bytes[i] = 'x';
            replacement->push_back(i);
        }
    }
}

void format_string_bytes::recover() {
    for (int i = 0; i < replacement->size(); ++i) {
        bytes[replacement->at(i)] = '\0';
    }
}

int format_string_bytes::getN() {
    return n;
}
void format_string_bytes::setN(int n) {
    this->n = n;
}

unsigned char* format_string_bytes::getBytes() {
    return bytes;
}
void format_string_bytes::setBytes(unsigned char *bytes) {
    this->bytes = bytes;
}

vector<int>* format_string_bytes::getReplacement() {
    return replacement;
}
void format_string_bytes::setReplacement(vector<int> *replacement) {
    this->replacement = replacement;
}