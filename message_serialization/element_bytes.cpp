//
// Created by alan on 19-4-26.
//

#include "element_bytes.h"

element_bytes::element_bytes() {
    replacement = new vector<int>();
}

element_bytes::element_bytes(element_s *elem) {
    n = element_length_in_bytes(elem);
    bytes = (unsigned char*)malloc(n + 1);
    element_to_bytes(bytes, elem);
    bytes[n] = '\0';

    replacement = new vector<int>();

//    for (int i = 0; i < n; ++i) {
//        if (bytes[i] == '\0') {
//            bytes[i] = 'x';
//            replacement->push_back(i);
//        }
//    }
}

void element_bytes::replace() {
    for (int i = 0; i < n; ++i) {
        if (bytes[i] == '\0') {
            bytes[i] = 'x';
            replacement->push_back(i);
        }
    }
}

void element_bytes::recover() {
    for (int i = 0; i < replacement->size(); ++i) {
        bytes[replacement->at(i)] = '\0';
    }
}

int element_bytes::getN() {
    return n;
}
void element_bytes::setN(int n) {
    this->n = n;
}

unsigned char* element_bytes::getBytes() {
    return bytes;
}
void element_bytes::setBytes(unsigned char *bytes) {
    this->bytes = bytes;
}

vector<int>* element_bytes::getReplacement() {
    return replacement;
}
void element_bytes::setReplacement(vector<int> *replacement) {
    this->replacement = replacement;
}