//
// Created by alan on 19-9-3.
//

#ifndef ABELIB_SECRETKEY_H
#define ABELIB_SECRETKEY_H

#include "Key.h"

class SecretKey : public Key {
private:
    vector<string> *attributes;
    string *kgc_name;
public:
    SecretKey();
    SecretKey(vector<string> *attributes, string *kgc_name);

    vector<string>* getAttributes();
    string* getKgcName();
};


#endif //ABELIB_SECRETKEY_H
