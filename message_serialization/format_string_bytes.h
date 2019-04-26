//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_FORMAT_STRING_BYTES_H
#define ABELIB_FORMAT_STRING_BYTES_H

#include "../basis.h"

class format_string_bytes {
private:
    int n;
    unsigned char *bytes;
    vector<int> *replacement;
public:
    format_string_bytes();
    format_string_bytes(string str);
    format_string_bytes(unsigned char *str_bytes, int str_byte_num);

    int getN();
    void setN(int n);
    unsigned char* getBytes();
    void setBytes(unsigned char *bytes);
    vector<int>* getReplacement();
    void setReplacement(vector<int> *replacement);

    void replace();
    void recover();
};


#endif //ABELIB_FORMAT_STRING_BYTES_H
