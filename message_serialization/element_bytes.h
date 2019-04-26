//
// Created by alan on 19-4-26.
//

#ifndef ABELIB_ELEMENT_BYTES_H
#define ABELIB_ELEMENT_BYTES_H

#include "../basis.h"

class element_bytes {
private:
    int n;
    unsigned char *bytes;
    vector<int> *replacement;
public:
    element_bytes();
    element_bytes(element_s *elem);

    int getN();
    void setN(int n);
    unsigned char* getBytes();
    void setBytes(unsigned char *bytes);
    vector<int>* getReplacement();
    void setReplacement(vector<int> *replacement);

    void replace();
    void recover();
};


#endif //ABELIB_ELEMENT_BYTES_H
